#!/usr/bin/env zsh
set -e

cargo build --release --bin proof

echo constraints,proof,infra,trial,time
for trial in $(seq 1 3)
do
    for lsteps in $(seq 3 20)
    #for lsteps in $(seq 3 12)
    do
        for proof in groth16 marlin plonk
        do
            steps=$((2 ** $lsteps))
            local_trial_time=$(./scripts/bench.zsh $proof local $steps)
            local_trial_time=$(units -t $local_trial_time s)
            echo ${steps},${proof},local,$trial,${local_trial_time}

            steps=$((2 ** $lsteps))
            local_trial_time=$(./scripts/bench.zsh $proof mpc $steps)
            local_trial_time=$(units -t $local_trial_time s)
            echo ${steps},${proof},mpc,$trial,${local_trial_time}
        done
    done
done
