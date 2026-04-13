import { beforeAll, describe, it, beforeEach } from "vitest";
import { VelareClient } from "../src";
import {
  AlgorandClient,
  algos,
  microAlgos,
} from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";

describe("Velare", async () => {
  let algorand: AlgorandClient;
  let sender: algosdk.Address;
  let client: VelareClient;

  beforeEach(async () => {
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

  it("should transfer", async () => {
    const receiver = algorand.account.random();
    await algorand.account.ensureFundedFromEnvironment(
      receiver,
      microAlgos(5_000_000),
    );

    const { group: senderInitGroup } = await client.composeInitializeGroup(
      sender,
      0n,
      5n,
      1337n,
    );
    await senderInitGroup.send();

    const { group: receiverInitGroup } = await client.composeInitializeGroup(
      receiver,
      0n,
      5n,
      1337n,
    );
    await receiverInitGroup.send();

    const mbrAmt = 831_690;

    await algorand.send.payment({
      sender,
      receiver: client.appClient.appAddress,
      amount: microAlgos(mbrAmt),
    });

    const { group: xferGroup } = await client.composeTransferGroup({
      sender,
      receiver,
      asset: 0n,
      amount: 5n,
      balance_secret: 1337n,
      xfer_secret: 1337n,
      old_balance: 5n,
    });
    await xferGroup.send();
  });
});
