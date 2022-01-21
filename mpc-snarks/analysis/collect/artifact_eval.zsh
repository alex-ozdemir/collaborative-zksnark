#!/usr/bin/env zsh

set -ex
time ./analysis/collect/bad_net.zsh | tee ./analysis/data/bad_net.csv
time ./analysis/collect/weak_machines.zsh
time ./analysis/collect/Npc.zsh
