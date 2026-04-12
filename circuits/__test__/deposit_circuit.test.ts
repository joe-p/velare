import circom_tester from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { join } from "path";
import { calculateCommitment } from "../src";

const DEPOSIT_PATH = join(__dirname, "..", "deposit.circom");

describe("deposit", () => {
  let claimCircuit: any;
  const claimer = 1n;
  const asset = 0n;
  const secret = 1337n;
  const amount = 5n;

  beforeAll(async () => {
    claimCircuit = await circom_tester.wasm(DEPOSIT_PATH, {
      prime: "bls12381",
      recompile: true,
    });
  });

  it("should work", async () => {
    const inputs = {
      addr: claimer,
      asset,
      amount,
      secret,
    };

    const witness = await claimCircuit.calculateWitness(inputs);
    await claimCircuit.checkConstraints(witness);

    await claimCircuit.assertOut(witness, {
      commitment: calculateCommitment({ secret, asset, claimer, amount }),
    });
  });
});
