import { beforeAll, describe, it } from "vitest";
import { ConfidentialTransactionsClient } from "../src";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";

describe("ConfidentialTransactions", () => {
  let algorand: AlgorandClient;
  let sender: algosdk.Address;
  let client: ConfidentialTransactionsClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    sender = (await algorand.account.dispenserFromEnvironment()).addr;
    client = await ConfidentialTransactionsClient.deploy(algorand, sender);
  });

  it("should initialize", async () => {
    const { group } = await client.composeInitializeGroup(
      sender,
      0n,
      5n,
      1337n,
    );
    await group.send();
  });
});
