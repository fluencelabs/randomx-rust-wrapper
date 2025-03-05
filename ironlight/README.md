## RandomX IronLight RandomX mode

This library is a RandomX light mode written in Rust together with execution proving based on Plonky3 and SP1.


## Usage example
```
SP1_DEV=1 RAYON_NUM_THREADS=2 FRI_QUERIES=1 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo test --release prove_light_works  --package ccp-ironlight
cp -rp ~/.sp1/circuits/dev/* ~/.sp1/circuits/groth16/v3.0.0/
RAYON_NUM_THREADS=2 FRI_QUERIES=1 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo test --release prove_light_works  --package ccp-ironlight
```
The `prove_light_works` test demonstrates a full pipeline that runs, proves, verifies and prints out Groth16 proof. 