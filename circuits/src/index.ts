import { mimcSum } from "./mimc";

export * from "./mimc";

export function calculateCommitment(inputs: {
  claimer: bigint;
  asset: bigint;
  amount: bigint;
  secret: bigint;
}) {
  return mimcSum([inputs.claimer, inputs.asset, inputs.amount, inputs.secret]);
}
