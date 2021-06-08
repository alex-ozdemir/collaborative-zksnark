#!/usr/bin/env zsh
set -e

cargo build --release --bin proof

echo constraints,proof,infra,trial,time
for trial in $(seq 1 1)
#for trial in $(seq 1 3)
do
    #for lsteps in $(seq 3 20)
    for lsteps in $(seq 3 11)
    do
        steps=$((2 ** $lsteps))
        for proof in groth16 marlin plonk
        do
            for infra in local mpc spdz
            do
                local_trial_time=$(./scripts/bench.zsh $proof $infra $steps)
                local_trial_time=$(units -t $local_trial_time s)
                echo ${steps},${proof},$infra,$trial,${local_trial_time}
            done
        done
    done
done
