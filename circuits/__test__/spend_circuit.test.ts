import circom_tester from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { join } from "path";
import { calculateCommitment } from "../src";

const SPEND_PATH = join(__dirname, "..", "circom", "spend_2_2.circom");

describe("spend", () => {
  let spendCircuit: any;
  const spender = 1n;
  const receiver = 2n;
  const asset = 0n;
  const secret = 1337n;

  beforeAll(async () => {
    spendCircuit = await circom_tester.wasm(SPEND_PATH, {
      prime: "bls12381",
      recompile: true,
    });
  });

  it("should work", async () => {
    const inputs = {
      spender,
      asset,
      receivers: [receiver, receiver],
      in_amounts: [5n, 5n],
      in_secrets: [secret, secret],
      out_amounts: [3n, 7n],
      out_secrets: [secret, secret],
    };

    const witness = await spendCircuit.calculateWitness(inputs);
    await spendCircuit.checkConstraints(witness);

    const inputCommitmentCommon = { secret, asset, claimer: spender };
    const outputCommitmentCommon = { secret, asset, claimer: receiver };

    await spendCircuit.assertOut(witness, {
      inputs: [
        calculateCommitment({
          amount: 5n,
          ...inputCommitmentCommon,
        }),
        calculateCommitment({
          amount: 5n,
          ...inputCommitmentCommon,
        }),
      ],
      outputs: [
        calculateCommitment({
          amount: 3n,
          ...outputCommitmentCommon,
        }),
        calculateCommitment({
          amount: 7n,
          ...outputCommitmentCommon,
        }),
      ],
    });
  });
});
