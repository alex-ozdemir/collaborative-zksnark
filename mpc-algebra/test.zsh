set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

cargo build --example gsz20
BIN=./target/debug/examples/gsz20

for n_parties in 3 4
do
  PROCS=()
  for i in $(seq 0 $(($n_parties - 1)))
  do
    #$BIN $i ./data/4 &
    if [ $i == 0 ]
    then
      RUST_BACKTRACE=1 RUST_LOG=gsz20 $BIN $i ./data/$n_parties &
      pid=$!
      PROCS[$i]=$pid
    else
      RUST_LOG=gsz20 $BIN $i ./data/$n_parties > /dev/null &
      pid=$!
      PROCS[$i]=$pid
    fi
  done
  
  for pid in ${PROCS[@]}
  do
    wait $pid
  done
done

echo done

