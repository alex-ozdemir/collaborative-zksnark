#!/usr/bin/env zsh
# Reads the file `vms` and deletes all VMs listed there.
# Also deletes the `hosts` file.
trap "exit" INT TERM
trap "kill 0" EXIT

set -xe

n=$1

VM_FILE=vms
HOSTS_FILE=hosts


names=$(cat $VM_FILE | tr '\r' ' ')

gcloud beta compute instances delete $=names \
    --quiet \
    --zone us-central1-a \
    --project soe-collaborative-proof
rm -f $VM_FILE
rm -f $HOSTS_FILE


trap - INT TERM EXIT
