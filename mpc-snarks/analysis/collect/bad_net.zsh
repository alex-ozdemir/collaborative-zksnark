#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

set -e

proofs=(groth16 plonk marlin)
#kb_s_log2_s=(9 10 11 12 13 14 15)
kb_s_log2_s=(10 11 12 13 14 15 16)
trials=1


echo proof_system,alg,kb_s,size,trial,time
# 2pc
parties=2
net=lan
log2size=10
trials=3
for ps in ${proofs[@]}
do
  for t in $(seq 0 $(($trials - 1)))
  do
    for kb_s_log2 in ${kb_s_log2_s[@]}
    do
      for alg in spdz
      do
        kb_s=$((2 ** $kb_s_log2))
        s=$((2 ** $log2size))
        dur=$(./scripts/bandwidth_bench.zsh $ps $alg $s $kb_s)
        dur=$(units -t $dur s)
        echo $ps,$alg,$kb_s,$s,$t,$dur
      done
    done
  done
done

trap - INT TERM EXIT
