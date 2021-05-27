#!/usr/bin/env zsh
set -e

self_host=$1
other_host=$2
party_n=$3
infra=$4
BIN=$5
LABEL="timed section"

(
echo constraints,proof,infra,trial,time
for trial in $(seq 1 1)
#for trial in $(seq 1 3)
do
    #for lsteps in $(seq 3 20)
    for lsteps in 3 5 7 9 10
    do
        for proof in groth16 marlin plonk
        do
            steps=$((2 ** $lsteps))
            trial_time=$(./$BIN -p $proof -c squaring --computation-size $steps mpc --host $self_host --peer-host $other_host --party $party_n | grep -E "End: *$LABEL" | grep -E -o '[0-9][0-9.]*.s')
            trial_time=$(units -t $trial_time s)
            echo ${steps},${proof},$infra,$trial,${trial_time}
        done
    done
done
) | tee out
