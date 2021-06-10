set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

cargo build --example broadcast
BIN=./target/debug/examples/broadcast

PROCS=()
for i in 0 1 2 3
do
  $BIN $i ./data/4 &
  #RUST_LOG=debug $BIN $i ./data/4 &
  pid=$!
  PROCS+=("$pid")
done
jobs -pr

for pid in $PROCS
do
  jobs -pr
  wait $pid
  jobs -pr
done

echo done

