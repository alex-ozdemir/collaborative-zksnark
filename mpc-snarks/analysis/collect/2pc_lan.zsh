parties=2
net=lan
for ps in groth16 plonk marlin
do
  for t in 0
  do
    for log2size in 1 5 10
    do
      for alg in spdz
      do
        s=$((2 ** $log2size))
        echo $ps,$alg,$parties,$net,$s,$t
      done
    done
  done
done
