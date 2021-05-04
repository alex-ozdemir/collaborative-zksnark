#!/usr/bin/env zsh
set -e


echo constraints,proof,infra,time
for proof in groth16 marlin
do
    for lsteps in $(seq 3 20)
    #for lsteps in $(seq 3 12)
    do
        steps=$((2 ** $lsteps))
        trials=3
        local_net_time=0
        for trial in $(seq 1 $trials)
        do
            local_trial_time=$(./scripts/bench.zsh $proof local $steps)
            local_trial_time=$(units -t $local_trial_time s)
            local_net_time=$(($local_net_time + $local_trial_time))
        done
        local_time=$(($local_net_time / $trials))
        echo ${steps},${proof},local,${local_time}

        mpc_net_time=0
        for trial in $(seq 1 $trials)
        do
            mpc_trial_time=$(./scripts/bench.zsh $proof mpc $steps)
            mpc_trial_time=$(units -t $mpc_trial_time s)
            mpc_net_time=$(($mpc_net_time + $mpc_trial_time))
        done
        mpc_time=$(($mpc_net_time / $trials))
        echo ${steps},${proof},mpc,${mpc_time}
    done
done
