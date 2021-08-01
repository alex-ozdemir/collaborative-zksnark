
#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

set -xe
if [ ! -f hosts ]; then
  ./analysis/collect/create_vms.zsh 32 1
fi
#log2sizes=(1 2 3 4 5)
#log2sizes=(1 2 3 4 5 6 7 8 9 10 11 12 13)
log2sizes=(10)
proofs=(groth16 plonk marlin)
trials=3

(
# 6pc
net=lan
for parties in 2 4 8 16 32
do
  for ps in ${proofs[@]}
  do
    for t in $(seq 0 $(($trials - 1)))
    do
      for log2size in ${log2sizes[@]}
      do
        for alg in spdz gsz
        do
          s=$((2 ** $log2size))
          echo $ps,$alg,$parties,$net,$s,$t
        done
      done
    done
  done
done
) > benches

cat benches

./analysis/lib/runner.py hosts benches --output ./analysis/data/Npc.csv

./analysis/collect/delete_vms.zsh
trap - INT TERM EXIT
