#!/usr/bin/env zsh
set -e

self_host=$1
other_host=$2
party_n=$3
infra=$4

echo constraints,proof,infra,trial,time
for trial in $(seq 1 3)
do
    for lsteps in $(seq 3 20)
    #for lsteps in $(seq 3 10)
    do
        for proof in groth16 marlin plonk
        do
            steps=$((2 ** $lsteps))
            trial_time=$(./scripts/remote_bench.zsh $self_host $other_host $party_n $proof $steps)
            trial_time=$(units -t $trial_time s)
            echo ${steps},${proof},$infra,$trial,${trial_time}
        done
    done
done
