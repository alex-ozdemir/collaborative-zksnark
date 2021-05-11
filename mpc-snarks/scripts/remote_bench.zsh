#!/usr/bin/env zsh
set -e

self=$1
other=$2
party=$3
proof=$4
size=$5
if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi
LABEL="timed section"


function usage {
  echo "Usage: $0 SELF_HOST OTHER_HOST PARTY_N {groth16,marlin,plonk} N_SQUARINGS" >&2
  exit 1
}

if [ "$#" -ne 5 ] ; then
    usage
fi

case $proof in
    groth16|marlin|plonk)
        ;;
    *)
        usage
esac

$BIN -p $proof -c squaring --computation-size $size mpc --host $self --peer-host $other --party $party | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
