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

  it("should handle spend", async () => {
    const velareAddr = computeVelareAddress(
      sender,
      DEFAULT_HPKE_SUITE,
      senderViewkey.publicKey,
    );

    // Create first deposit (50n to sender)
    const deposit1Result = await client.composeDepositGroup(
      sender,
      0n,
      50n,
      senderViewkey.publicKey,
    );
    await deposit1Result.group.send();

    // Create second deposit (50n to sender)
    const deposit2Result = await client.composeDepositGroup(
      sender,
      0n,
      50n,
      senderViewkey.publicKey,
    );
    await deposit2Result.group.send();

    // Verify we have 2 UTXOs
    let utxos = await client.appClient.state.box.utxo.getMap();
    expect(utxos.size).toBe(2);

    // Build input UTXOs for spending using the deposit results
    const inUtxos = [
      {
        amount: 50n,
        secret: deposit1Result.inputs.out_secrets[0],
        encapsulatedKey: deposit1Result.enc,
        ciphertext: deposit1Result.ct,
      },
      {
        amount: 50n,
        secret: deposit2Result.inputs.out_secrets[0],
        encapsulatedKey: deposit2Result.enc,
        ciphertext: deposit2Result.ct,
      },
    ];

    // Spend both UTXOs: split 100n into 30n and 70n
    const spendResult = await client.composeSpendGroup(
      sender,
      0n,
      inUtxos,
      [30n, 70n],
      [velareAddr, velareAddr],
      senderViewkey.publicKey,
    );
    debugger;
    await spendResult.group.send();

    // Verify old UTXOs are deleted and 2 new ones exist
    utxos = await client.appClient.state.box.utxo.getMap();
    expect(utxos.size).toBe(2);

    // Verify the new output commitments exist as UTXO keys
    const utxoKeys = Array.from(utxos.keys());
    const outputCommitment1 = spendResult.outputCommitments[0];
    const outputCommitment2 = spendResult.outputCommitments[1];

    const hasCommitment1 = utxoKeys.some(
      (key) => key.utxo === outputCommitment1,
    );
    const hasCommitment2 = utxoKeys.some(
      (key) => key.utxo === outputCommitment2,
    );

    expect(hasCommitment1).toBe(true);
    expect(hasCommitment2).toBe(true);
  }, 30_000);
});
