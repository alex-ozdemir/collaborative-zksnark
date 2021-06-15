set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

cargo build --example gsz20
BIN=./target/debug/examples/gsz20

PROCS=()
for i in 0 1 2 3
do
  #$BIN $i ./data/4 &
  if [ $i == 0 ]
  then
    RUST_BACKTRACE=1 RUST_LOG=gsz20 $BIN $i ./data/4 &
    pid=$!
    PROCS[$i]=$pid
  else
    RUST_LOG=gsz20 $BIN $i ./data/4 > /dev/null &
    pid=$!
    PROCS[$i]=$pid
  fi
done

for pid in ${PROCS[@]}
do
  wait $pid
done

echo done

