#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

proof=$1
infra=$2
size=$3
n_parties=$4
if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi
LABEL="timed section"


function usage {
  echo "Usage: $0 {groth16,marlin,plonk} {hbc,spdz,gsz,local,ark-local} N_SQUARINGS N_PARTIES" >&2
  exit 1
}

if [ "$#" -ne 4 ] ; then
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
    hbc|spdz|gsz)
        PROCS=()
        for i in $(seq 0 $(($n_parties - 1)))
        do
          #$BIN $i ./data/4 &
          if [ $i -eq 0 ]
          then
            RUST_BACKTRACE=1 $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/$n_parties --party $i --alg $infra &
            pid=$!
          else
            $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/$n_parties --party $i --alg $infra > /dev/null &
            pid=$!
          fi
          PROCS+=($pid)
        done

        for pid in ${PROCS}
        do
          wait $pid
        done
    ;;
    local)
        $BIN -p $proof -c squaring --computation-size $size local
    ;;
    ark-local)
        $BIN -p $proof -c squaring --computation-size $size ark-local
    ;;
    *)
        usage
    ;;
esac

trap - INT TERM EXIT
