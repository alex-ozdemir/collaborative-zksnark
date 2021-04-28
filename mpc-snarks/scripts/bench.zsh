#!/usr/bin/env zsh

infra=$1
size=$2
BIN=./target/release/proof
LABEL="timed section"


function usage {
  echo "Usage: $0 {mpc,local,ark-local} N_SQUARINGS" >&2
  exit 1
}

if [ "$#" -ne 2 ] ; then
    usage
fi

case $infra in
    mpc)
        $BIN -c squaring --computation-size $size mpc --port 8001 --peer-port 8000 --party 0 > /dev/null &
        #$BIN -c squaring --computation-size $size mpc --port 8001 --peer-port 8000 --party 0 &
        pid0=$!
        $BIN -c squaring --computation-size $size mpc --port 8000 --peer-port 8001 --party 1 | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s' &
        #$BIN -c squaring --computation-size $size mpc --port 8000 --peer-port 8001 --party 1 &
        pid1=$!
        wait $pid0 $pid1
    ;;
    local)
        $BIN -c squaring --computation-size $size local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    ark-local)
        $BIN -c squaring --computation-size $size ark-local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    *)
        usage
    ;;
esac
