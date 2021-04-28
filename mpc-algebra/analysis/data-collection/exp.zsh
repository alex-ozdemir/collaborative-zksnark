#!/usr/bin/env zsh
set -e


echo constraints,local_time,ark_local_time,mpc_time
for steps in 1 3 10 30 100 300 1000 3000 10000 30000 100000
#for steps in 1 3 10 30 100 300 1000 3000
do
    local_time=$(./scripts/bench.zsh local $steps)
    local_time=$(units -t $local_time s)
    ark_local_time=$(./scripts/bench.zsh ark-local $steps)
    ark_local_time=$(units -t $ark_local_time s)
    trials=5
    mpc_net_time=0
    for trial in $(seq 1 $trials)
    do
        mpc_trial_time=$(./scripts/bench.zsh mpc $steps)
        mpc_trial_time=$(units -t $mpc_trial_time s)
        mpc_net_time=$(($mpc_net_time + $mpc_trial_time))
    done
    mpc_time=$(($mpc_net_time / $trials))
    echo ${steps},${local_time},${ark_local_time},${mpc_time}
done
