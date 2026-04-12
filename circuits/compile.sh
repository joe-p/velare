cd $(dirname "$0")
CIRCUITS_DIR=$(pwd)

bash ./setup/setup.sh

circom --r1cs --wasm --c --sym --inspect $CIRCUITS_DIR/claim.circom --prime bls12381 -o out
pnpm snarkjs plonk setup $CIRCUITS_DIR/out/claim.r1cs $CIRCUITS_DIR/setup/pot16_final.ptau $CIRCUITS_DIR/claim.zkey

