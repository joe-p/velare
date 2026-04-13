import circom_tester from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { join } from "path";
import { calculateCommitment, mimcSum } from "../src";

const TRANSFER_PATH = join(__dirname, "..", "transfer.circom");

describe("transfer", () => {
  let transferCircuit: any;
  const sender = 1n;
  const receiver = 2n;
  const asset = 0n;
  const secret = 1337n;

  beforeAll(async () => {
    transferCircuit = await circom_tester.wasm(TRANSFER_PATH, {
      prime: "bls12381",
      recompile: true,
    });
  });

  it("should work", async () => {
    const inputs = {
      sender_addr: sender,
      receiver_addr: [receiver],
      asset,
      xfer_amt: [5n],
      xfer_secret: [secret],
      old_balance: 10n,
      new_balance: 5n,
      balance_secret: secret,
    };

    const witness = await transferCircuit.calculateWitness(inputs);
    await transferCircuit.checkConstraints(witness);

    const senderCommitCommon = { secret, asset, claimer: sender };
    const receiverCommitCommon = { secret, asset, claimer: receiver };

    await transferCircuit.assertOut(witness, {
      old_balance_commitment: calculateCommitment({
        amount: 10n,
        ...senderCommitCommon,
      }),
      new_balance_commitment: calculateCommitment({
        amount: 5n,
        ...senderCommitCommon,
      }),
      xfer_commitments: [calculateCommitment({
        amount: 5n,
        ...receiverCommitCommon,
      })],
    });
  });
});
