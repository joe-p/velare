import circom_tester from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { join } from "path";
import { calculateCommitment, mimcSum } from "../src";

const CLAIM_PATH = join(__dirname, "..", "claim.circom");

describe("claim", () => {
  let claimCircuit: any;
  const claimer = 1n;
  const asset = 0n;
  const secret = 1337n;

  beforeAll(async () => {
    claimCircuit = await circom_tester.wasm(CLAIM_PATH, {
      prime: "bls12381",
      recompile: true,
    });
  });

  it("should work", async () => {
    const inputs = {
      claimer_addr: claimer,
      asset,
      xfer_amt: [5n],
      xfer_secret: [secret],
      old_balance: 5n,
      new_balance: 10n,
      balance_secret: secret,
    };

    const witness = await claimCircuit.calculateWitness(inputs);
    await claimCircuit.checkConstraints(witness);

    const commitCommon = { secret, asset, claimer };
    await claimCircuit.assertOut(witness, {
      old_balance_commitment: calculateCommitment({
        amount: 5n,
        ...commitCommon,
      }),
      new_balance_commitment: calculateCommitment({
        amount: 10n,
        ...commitCommon,
      }),
      xfer_commitment: mimcSum([
        calculateCommitment({ amount: 5n, ...commitCommon }),
      ]),
    });
  });
});
