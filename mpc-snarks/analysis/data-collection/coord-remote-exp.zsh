#!/usr/bin/env zsh
set -e

self_host=$1
other_host=$2
infra=$3
bin=$4

function error {
    if [[ $# -ge 1 ]]
    then
        echo Error: $1
    fi
    echo "Usage: $0 HOST_1 HOST_2 INFRA_NAME PROOF_BIN"
    exit 2
}

if [[ $# -ne 4 ]]
then
    error "Wrong number of args"
fi

if [[ ! ( -x $bin ) ]]
then
    error "Cannot execute $bin"
fi

bin_file=${bin:t}


echo "Copying proof binary..."
scp $bin $self_host:$bin_file
scp $bin $other_host:$bin_file
scp analysis/data-collection/remote-exp-out.zsh ${self_host}:run.zsh
scp analysis/data-collection/remote-exp-out.zsh ${other_host}:run.zsh

echo "Checking for units on each host..."
ssh $self_host "units -t 1s us"
ssh $other_host "units -t 1s us"

echo "Checking for zsh on each host..."
ssh $self_host "zsh --version"
ssh $other_host "zsh --version"

echo "Checking binary..."
ssh $self_host "./$bin_file -p groth16 -c squaring --computation-size 10 local"
ssh $other_host "./$bin_file -p groth16 -c squaring --computation-size 10 local"

echo "Running experiments..."
ssh $self_host "./run.zsh $self_host $other_host 0 $infra $bin_file" > out0 & ; pid0=$!
ssh $other_host "./run.zsh $other_host $other_host 1 $infra $bin_file" | tee out1 & ; pid1=$!
wait $pid0 $pid1

echo Done
