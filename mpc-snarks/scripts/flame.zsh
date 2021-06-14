#!/usr/bin/env zsh
set -e

proof=$1
infra=$2
size=$3
LABEL="timed section"


function usage {
  echo "Usage: $0 {groth16,marlin,plonk} {mpc,local,ark-local} N_SQUARINGS" >&2
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
    mpc)
        cargo run --release --bin proof -- -p $proof -c squaring --computation-size $size mpc --hosts data/2 --party 0 > /dev/null &
        #$BIN -c squaring --computation-size $size mpc --hosts data/2 --party 0 &
        pid0=$!
        cargo flamegraph --bin proof -o mpc.svg -- -p $proof -c squaring --computation-size $size mpc --hosts data/2 --party 1 &
        #$BIN -c squaring --computation-size $size mpc --hosts data/2 --party 1 &
        pid1=$!
        wait $pid0 $pid1
    ;;
    local)
        cargo flamegraph --bin proof -o local.svg -- -p $proof -c squaring --computation-size $size local
    ;;
    ark-local)
        $BIN -p $proof -c squaring --computation-size $size ark-local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    *)
        usage
    ;;
esac
