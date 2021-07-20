#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

pkill proof || true

proof=$1
infra=$2
size=$3
hostsfile=$4
partyid=$5
if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi
LABEL="timed section"


function usage {
  echo "Usage: $0 {groth16,marlin,plonk} {hbc,spdz,gsz,local,ark-local} N_SQUARINGS HOSTSFILE PARTY_ID" >&2
  exit 1
}

if [ "$#" -ne 5 ] ; then
    usage
fi

sleep 1

case $proof in
    groth16|marlin|plonk)
        ;;
    *)
        usage
esac

case $infra in
    hbc|spdz|gsz|local|ark-local)
        ;;
    *)
        usage
esac

case $infra in
    hbc|spdz|gsz)
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts $hostsfile --party $partyid --alg $infra | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    *)
        usage
    ;;
esac

trap - INT TERM EXIT
