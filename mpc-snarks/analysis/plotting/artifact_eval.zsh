#!/usr/bin/env zsh

set -xe

Rscript ./analysis/plotting/plot.R
Rscript ./analysis/plotting/Npc.R
Rscript ./analysis/plotting/bad_net.R
