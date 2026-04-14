import circom_tester from "circom_tester";
import { beforeAll, describe, it } from "vitest";
import { join } from "path";
import { calculateCommitment } from "../src";

const DEPOSIT_PATH = join(__dirname, "..", "circom", "deposit.circom");
const SPEND_PATH = join(__dirname, "..", "circom", "spend.circom");

describe("deposit and spend integration", () => {
  let depositCircuit: any;
  let spendCircuit: any;

  const spender = 1n;
  const receiver = 2n;
  const asset = 0n;
  const secret1 = 1337n;
  const secret2 = 7331n;
  const amount1 = 50n;
  const amount2 = 50n;

  beforeAll(async () => {
    depositCircuit = await circom_tester.wasm(DEPOSIT_PATH, {
      prime: "bls12381",
      recompile: true,
    });

    spendCircuit = await circom_tester.wasm(SPEND_PATH, {
      prime: "bls12381",
      recompile: true,
    });
  });

  it("should allow spending deposit outputs", async () => {
    // Create first deposit (50n to spender)
    const deposit1Inputs = {
      asset,
      receivers: [spender],
      out_amounts: [amount1],
      out_secrets: [secret1],
    };

    const deposit1Witness =
      await depositCircuit.calculateWitness(deposit1Inputs);
    await depositCircuit.checkConstraints(deposit1Witness);

    // Create second deposit (50n to spender)
    const deposit2Inputs = {
      asset,
      receivers: [spender],
      out_amounts: [amount2],
      out_secrets: [secret2],
    };

    const deposit2Witness =
      await depositCircuit.calculateWitness(deposit2Inputs);
    await depositCircuit.checkConstraints(deposit2Witness);

    // Get the output commitments from deposits - these are the inputs to spend
    const inputCommitment1 = calculateCommitment({
      claimer: spender,
      asset,
      amount: amount1,
      secret: secret1,
    });

    const inputCommitment2 = calculateCommitment({
      claimer: spender,
      asset,
      amount: amount2,
      secret: secret2,
    });

    // Spend the deposit outputs (50 + 50 = 100 total)
    // Split into two outputs: 30n and 70n
    const spendInputs = {
      spender,
      asset,
      receivers: [receiver, receiver],
      in_amounts: [amount1, amount2],
      in_secrets: [secret1, secret2],
      out_amounts: [30n, 70n],
      out_secrets: [secret1, secret2],
    };

    const spendWitness = await spendCircuit.calculateWitness(spendInputs);
    await spendCircuit.checkConstraints(spendWitness);

    // Verify spend circuit outputs match expected commitments
    const outputCommitment1 = calculateCommitment({
      claimer: receiver,
      asset,
      amount: 30n,
      secret: secret1,
    });

    const outputCommitment2 = calculateCommitment({
      claimer: receiver,
      asset,
      amount: 70n,
      secret: secret2,
    });

    await spendCircuit.assertOut(spendWitness, {
      inputs: [inputCommitment1, inputCommitment2],
      outputs: [outputCommitment1, outputCommitment2],
    });
  });
});
