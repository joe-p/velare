import circom_tester from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { join } from "path";
import { calculateCommitment } from "../src";

const DEPOSIT_PATH = join(__dirname, "..", "circom", "deposit_1.circom");

describe("deposit", () => {
  let depositCircuit: any;
  const receiver = 2n;
  const asset = 0n;
  const secret = 1337n;
  const amount = 100n;

  beforeAll(async () => {
    depositCircuit = await circom_tester.wasm(DEPOSIT_PATH, {
      prime: "bls12381",
      recompile: true,
    });
  });

  it("should work", async () => {
    const inputs = {
      asset,
      receivers: [receiver],
      out_amounts: [amount],
      out_secrets: [secret],
    };

    const witness = await depositCircuit.calculateWitness(inputs);
    await depositCircuit.checkConstraints(witness);

    await depositCircuit.assertOut(witness, {
      in_amount: amount,
      outputs: [
        calculateCommitment({
          claimer: receiver,
          asset,
          amount,
          secret,
        }),
      ],
    });
  });
});
