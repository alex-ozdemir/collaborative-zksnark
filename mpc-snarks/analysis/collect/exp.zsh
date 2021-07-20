#!/usr/bin/env zsh
set -e

cargo build --release --bin proof

echo constraints,proof,infra,trial,parties,time
for trial in $(seq 1 1)
#for trial in $(seq 1 3)
do
    #for lsteps in $(seq 3 20)
    for lsteps in $(seq 3 10)
    do
        steps=$((2 ** $lsteps))
        for nparties in 2 3
        do
            for proof in groth16 marlin plonk
            do
                for infra in local hbc spdz gsz
                do
                    local_trial_time=$(./scripts/bench.zsh $proof $infra $steps $nparties)
                    local_trial_time=$(units -t $local_trial_time s)
                    echo ${steps},${proof},$infra,$trial,$nparties,${local_trial_time}
                done
            done
        done
    done
done
