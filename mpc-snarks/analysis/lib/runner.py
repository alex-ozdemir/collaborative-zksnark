#!/usr/bin/env python
from typing import NamedTuple, List, Tuple, Optional

import os
import sys
import shutil as sh
import subprocess as sub
import argparse
import tempfile
import threading
import queue
import time
import traceback


class Binary(object):
    path: str

    def __init__(self, name: str):
        if os.access(name, os.EX_OK):
            self.path = os.path.abspath(name)
        elif sh.which(name) is not None:
            self.path = sh.which(name)
        else:
            assert False, f"Could not find executable {name}"


ssh = Binary("ssh")
scp = Binary("scp")


def check_ssh(ip: str):
    print("check ssh to " + ip)
    out = sub.run(
        [ssh.path, f"{username}@{ip}", "ls && (pkill proof || echo no proof)"], stderr=sub.PIPE, stdout=sub.PIPE, input=""
    )
    assert (
        out.returncode == 0
    ), f"Could not run 'ls' on '{ip}'. Got STDOUT\n{out.stdout.decode()}\nSTDERR\n{out.stderr.decode()}"


class Machine(object):
    ip: str
    priv_ip: str

    def __init__(self, ip: str, priv_ip: str):
        check_ssh(ip)
        self.ip = ip
        self.priv_ip = priv_ip
        #self.disable_threading()

    def str(self):
        return f"{username}@{self.ip}"

    def disable_threading(self):
        print(f"Disabling hyperthreading: {self.ip}")
        sub.run(["ssh", self.str(), "sudo", "./hyperthreading.sh", "-d"], check=True)


class Hosts(NamedTuple):
    hosts: List[Machine]

    def mk_and_copy_host_file(self, hosts: "Hosts", host_path: str):
        with tempfile.NamedTemporaryFile("w+") as fp:
            fp.writelines(f"{host.priv_ip}:8000\n" for host in hosts.hosts)
            fp.flush()
            for host in hosts.hosts:
                sub.run([scp.path, '-q', fp.name, f"{host.str()}:{host_path}"])


class Cmd(NamedTuple):
    cmd: List[str]


LOCAL = "local"
GSZ = "gsz"
SPDZ = "spdz"

GROTH = "groth16"
PLONK = "plonk"
MARLIN = "marlin"

NET_COHOST = "cohost"
NET_LAN = "lan"

TIME_1024_SPDZ_SEC = {GROTH: 0.98, PLONK: 5.9, MARLIN: 3.1}

ALG_RATIO = {
    LOCAL: 0.5,
    GSZ: 0.6,
    SPDZ: 1.0,
}


class BenchmarkInput(NamedTuple):
    proof_system: str
    alg: str
    parties: int
    net: str
    size: int
    trial: int

    def cmds(self, bin_path, host_path):
        if self.net == NET_COHOST:
            return [
                [
                    "env",
                    f"BIN={bin_path}",
                    BENCH_PATH,
                    self.proof_system,
                    "local",
                    str(self.size),
                    "1",
                ]
            ]
        elif self.net == NET_LAN:
            return [
                [
                    "env",
                    f"BIN={bin_path}",
                    REMOTE_BENCH_PATH,
                    self.proof_system,
                    self.alg,
                    str(self.size),
                    host_path,
                    str(i),
                ]
                for i in range(self.parties)
            ]
        else:
            raise Exception("Bad ent: " + self.net)

    def estimated_time(self):
        t_1024 = TIME_1024_SPDZ_SEC[self.proof_system]
        return t_1024 / 1024 * self.size * ALG_RATIO[self.alg]

    def timeout(self):
        return max(20, self.estimated_time() * 1.5)

    def host_need(self):
        return 1 if self.net == NET_COHOST else self.parties

    def run(self, host_path: str, bin_path: str, hosts: Hosts) -> Optional[float]:
        count = len(hosts.hosts)
        cmds = [
            [ssh.path, host.str()] + cmd
            # [ssh.path, host.str()] + ["echo", "1"]
            for host, cmd in zip(hosts.hosts, self.cmds(bin_path, host_path))
        ]
        print('start', self, 'estimate:', self.estimated_time(), 'timeout:', self.timeout())
        outputs = None
        while outputs is None:
            outputs = async_run(cmds, self.timeout())
            if outputs is None:
                print("TIMEOUT", self, 'after', self.timeout())
        print('done', self, self.estimated_time(), outputs)
        if '' in outputs:
            return None
        return sum(time_str_to_secs(o) for o in outputs) / count

    def csv_line(self) -> str:
        return f"{self.proof_system},{self.alg},{self.parties},{self.net},{self.size},{self.trial}"

    def csv_header(self) -> str:
        return f"proof_system,alg,parties,net,size,trial"


def hosts_from_file(path: str) -> List[Machine]:
    out = []
    with open(path) as f:
        for line in f.read().strip().splitlines(keepends=False):
            ip, priv_ip = line.strip().split()
            out.append(Machine(ip, priv_ip))
    return out


def benchmarks_from_file(path: str) -> List[BenchmarkInput]:
    out = []
    with open(path) as f:
        for line in f.read().strip().splitlines(keepends=False):
            ps, a, p, n, s, t = line.strip().split(",")
            assert ps in [PLONK, MARLIN, GROTH]
            assert a in [LOCAL, GSZ, SPDZ]
            assert n in [NET_COHOST, NET_LAN]
            parties = int(p)
            if a == LOCAL:
                assert parties == 1
                assert n == NET_COHOST
            if a == MARLIN:
                assert parties >= 2
            if a == GSZ:
                pass
                #assert parties >= 3
            out.append(BenchmarkInput(ps, a, parties, n, int(s), int(t)))
    return out


def time_str_to_secs(s: str) -> float:
    s = s.strip()
    if s[-2:] == "ns":
        return float(s[:-2]) * 10 ** -9
    elif s[-2:] == "us":
        return float(s[:-2]) * 10 ** -6
    elif s[-2:] == "ms":
        return float(s[:-2]) * 10 ** -3
    elif s[-2:] == "ks":
        return float(s[:-2]) * 10 ** 3
    elif s[-1:] == "s":
        return float(s[:-1])
    else:
        raise Exception("bad time: " + s)


def async_run(cmds: List[List[str]], timeout: float) -> List[str]:
    n = len(cmds)
    ts = []
    rs = queue.LifoQueue()
    start_time = time.time()
    for cmd in cmds:
        t = threading.Thread(target=async_run_one, args=(cmd, rs))
        t.setDaemon(True)
        t.start()
        ts.append(t)
    for t in ts:
        elapsed = max(time.time() - start_time, 0)
        to = timeout-elapsed
        if to < 0:
            # Timeout!!!
            return None
        t.join(to)
        if t.is_alive():
            # Timeout!!!
            return None
    rlist = []
    while not rs.empty():
        rlist.append(rs.get())
    return rlist


def async_run_one(cmd: List[str], q: "Queue[str]"):
    o = sub.check_output(cmd)
    q.put(o.decode().strip())


class Benchmark(NamedTuple):
    input: BenchmarkInput
    time: float

    def csv_line(self) -> str:
        return f"{self.input.csv_line()},{self.time}"

    def csv_header(self) -> str:
        return f"{self.input.csv_header()},time"


class Result(NamedTuple):
    benchmark: Benchmark
    hosts: Hosts


def tiny_baselines():
    li = []
    for pf in [PLONK, MARLIN, GROTH]:
        for trial in range(1):
            alg = LOCAL
            n_parties = 1
            for log2size in range(2, 5, 2):
                size = 2 ** log2size
                li.append(BenchmarkInput(pf, alg, n_parties, size, trial))
    return li


def baselines():
    li = []
    for pf in [PLONK, MARLIN, GROTH]:
        for trial in range(3):
            alg = LOCAL
            n_parties = 1
            for log2size in range(1, 21, 1):
                size = 2 ** log2size
                li.append(BenchmarkInput(pf, alg, n_parties, size, trial))
    return li


parser = argparse.ArgumentParser()
parser.add_argument(
    "hosts", metavar="HOSTS", type=str, help="Hosts to use for testing. One IP per line"
)
parser.add_argument(
    "benchmarks",
    metavar="BENCHMARKS",
    type=str,
    help="Benchmarks to run. One PROOF,ALG,PARTIES,NET,SIZE,TRIAL per trial",
)
parser.add_argument(
    "--output",
    metavar="PATH",
    type=str,
    help="Where to write the output CSV to",
    default="out.csv",
)
parser.add_argument("--user", metavar="USERNAME", default=os.getenv("USER"))

args = parser.parse_args()
username = args.user

machines = hosts_from_file(args.hosts)
to_run = benchmarks_from_file(args.benchmarks)
print(f"{len(machines)} machines")

tasks = len(to_run)

results = queue.LifoQueue()
benchmarks = []

to_run.sort(key=lambda b: b.estimated_time())

print("Benchmarks:")
for t in to_run:
    print("  ", t)

HOST_PATH = "./hosts"
BIN_PATH = "./proof"
BENCH_PATH = "./multiprover-snark/mpc-snarks/scripts/bench.zsh"
REMOTE_BENCH_PATH = "./multiprover-snark/mpc-snarks/scripts/remote_bench.zsh"


def run_thread(inputs: BenchmarkInput, hosts: Hosts):
    try:
        hosts.mk_and_copy_host_file(hosts, HOST_PATH)
        time = inputs.run(HOST_PATH, BIN_PATH, hosts)
        results.put(Result(Benchmark(inputs, time), hosts))
    except Exception as e:
        traceback.print_exc()
        os._exit(1)



threads = []

update_ctr = 0

n_workers = len(machines)
incomplete = set(to_run)

while len(benchmarks) < tasks:
    # while len(to_run) > 0 and len(benchmarks) < tasks and not results.empty():
    # Check for results
    if not results.empty():
        try:
            while True:
                res = results.get_nowait()
                machines.extend(res.hosts.hosts)
                benchmarks.append(res.benchmark)
                incomplete.remove(res.benchmark.input)
        except queue.Empty as e:
            pass
    # Check for runnable tasks
    if len(to_run) > 0:
        needed = to_run[-1].host_need()
        if len(machines) >= needed:
            inputs = to_run[-1]
            to_run.pop()
            hosts = Hosts(machines[-needed:])
            for _ in range(needed):
                machines.pop()
            t = threading.Thread(target=run_thread, args=(inputs, hosts))
            t.start()
            threads.append(t)
    time.sleep(0.01)
    update_ctr += 1
    update_ctr %= 1000
    if update_ctr == 0:
        print(f"{n_workers-len(machines)}/{n_workers} hosts busy, {len(benchmarks)}/{tasks} tasks done")
        if len(incomplete) < 10:
            print(f"{incomplete}")

for t in threads:
    t.join()

print("Results:")
for r in benchmarks:
    print(r)

with open(args.output, 'w') as f:
    f.write(benchmarks[0].csv_header())
    f.write('\n')
    for r in benchmarks:
        if r.time is not None:
            f.write(r.csv_line())
            f.write('\n')

print("done")
