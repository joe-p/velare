#!/usr/bin/env tsx

import { execSync } from "child_process";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CIRCUITS_DIR = join(__dirname, "..");
const CIRCUITS = ["spend_2_2", "deposit_1"] as const;

execSync("bash ./setup/setup.sh", {
  cwd: CIRCUITS_DIR,
  stdio: "inherit",
});

for (const circuit of CIRCUITS) {
  console.log(`\n=== Compiling ${circuit} circuit ===`);

  execSync(
    `circom --r1cs --wasm --c --sym --inspect ${CIRCUITS_DIR}/circom/${circuit}.circom --prime bls12381 -o out`,
    { cwd: CIRCUITS_DIR, stdio: "inherit" },
  );

  console.log(`\n=== Setting up ${circuit} zkey ===`);

  execSync(
    `pnpm snarkjs plonk setup ${CIRCUITS_DIR}/out/${circuit}.r1cs ${CIRCUITS_DIR}/setup/pot16_final.ptau ${CIRCUITS_DIR}/zkeys/${circuit}.zkey`,
    { cwd: CIRCUITS_DIR, stdio: "inherit" },
  );
}

console.log("\n=== All circuits compiled successfully ===");
