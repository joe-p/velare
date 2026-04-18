import { describe, it, beforeEach, expect } from "vitest";
import {
  computeVelareAddress,
  DEFAULT_HPKE_SUITE,
  getHpkeSuiteId,
  VelareClient,
} from "../src";
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
    const { group, enc, ct } = await client.composeDepositGroup(
      sender,
      0n,
      5n,
      senderViewkey.publicKey,
    );
    await group.send();

    const utxos = await client.appClient.state.box.utxo.getMap();
    expect(utxos.size).toBe(1);

    const utxo = Array.from(utxos.values())[0];
    expect(utxo.encapsulatedKey).toEqual(enc);
    expect(utxo.ciphertext).toEqual(ct);

    const velareAddr = computeVelareAddress(
      sender,
      DEFAULT_HPKE_SUITE,
      senderViewkey.publicKey,
    );

    const addressInfo =
      await client.appClient.state.box.addressInfo.value(velareAddr);

    expect(addressInfo?.hpkeSuite).toEqual(getHpkeSuiteId(DEFAULT_HPKE_SUITE));
    expect(addressInfo?.spendAddress).toEqual(sender.toString());
    expect(addressInfo?.viewKey).toEqual(senderViewkey.publicKey);
  });
});
