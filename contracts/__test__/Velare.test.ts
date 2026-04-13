import { beforeAll, describe, it } from "vitest";
import { VelareClient } from "../src";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";

describe("Velare", () => {
  let algorand: AlgorandClient;
  let sender: algosdk.Address;
  let client: VelareClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    sender = (await algorand.account.dispenserFromEnvironment()).addr;
    client = await VelareClient.deploy(algorand, sender);
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
