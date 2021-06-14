#!/usr/bin/env zsh
set -e

proof=$1
infra=$2
size=$3
if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi
LABEL="timed section"


function usage {
  echo "Usage: $0 {groth16,marlin,plonk} {hbc,spdz,local,ark-local} N_SQUARINGS" >&2
  exit 1
}

if [ "$#" -ne 3 ] ; then
    usage
fi

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
    hbc|spdz)
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/2 --party 0 --alg $infra > /dev/null &
        pid0=$!
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/2 --party 1 --alg $infra | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s' &
        pid1=$!
        wait $pid0 $pid1
    ;;
    gsz)
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/4 --party 0 --alg $infra > /dev/null &
        pid0=$!
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/4 --party 1 --alg $infra > /dev/null &
        pid1=$!
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/4 --party 2 --alg $infra > /dev/null &
        pid2=$!
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/4 --party 3 --alg $infra | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s' &
        pid3=$!
        wait $pid0 $pid1 $pid2 $pid3
    ;;
    local)
        $BIN -p $proof -c squaring --computation-size $size local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    ark-local)
        $BIN -p $proof -c squaring --computation-size $size ark-local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    *)
        usage
    ;;
esac
