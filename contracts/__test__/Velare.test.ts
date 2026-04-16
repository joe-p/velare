import { describe, it, beforeEach } from "vitest";
import { VelareClient } from "../src";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import { x25519 } from "@noble/curves/ed25519.js";

describe("Velare", async () => {
  let algorand: AlgorandClient;
  let sender: algosdk.Address;
  let senderViewkey = x25519.keygen();
  let client: VelareClient;

  beforeEach(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    sender = (await algorand.account.dispenserFromEnvironment()).addr;
    client = await VelareClient.deploy(algorand, sender);
  });

  it("should handle deposit", async () => {
    const { group } = await client.composeDepositGroup(
      sender,
      0n,
      5n,
      senderViewkey.publicKey,
    );
    await group.send();

    // TODO: state assertions
  });
});
