#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

pkill proof || true

proof=$1
alg=$2
size=$3
kb_s=$4
n_parties=2
if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi
LABEL="timed section"


function usage {
  echo "Usage: $0 {groth16,marlin,plonk} {hbc,spdz,gsz,local,ark-local} N_SQUARINGS KB_PER_SEC" >&2
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

case $alg in
    hbc|spdz|gsz|local|ark-local)
        ;;
    *)
        usage
esac

mb_s=$(($kb_s*1.0/1000))

case $alg in
    hbc|spdz|gsz)
        PROCS=()
        yes $mb_s | mm-rate-to-events | head -n 10000 > mm_trace
        $BIN -p $proof -c squaring --computation-size $size mpc --hosts data/mahimahi_out --party 0 --alg $alg | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s' &
        pid=$!
        PROCS+=($pid)
        mm-link mm_trace mm_trace -- bash -c "$BIN -p $proof -c squaring --computation-size $size mpc --hosts data/mahimahi_in --party 1 --alg $alg > /dev/null && sleep $((0.05/ $mb_s))" &
        pid=$!
        PROCS+=($pid)

        for pid in ${PROCS}
        do
          wait $pid
        done
        rm mm_trace
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

trap - INT TERM EXIT
