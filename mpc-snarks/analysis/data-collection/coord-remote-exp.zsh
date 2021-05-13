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
