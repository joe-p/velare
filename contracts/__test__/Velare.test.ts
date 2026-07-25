import { describe, it, beforeEach, expect } from "vitest";
import {
  computeVelareAddress,
  getHpkeSuiteId,
  getKemCosts,
  VelareClient,
  X25519_HPKE_SUITE,
  XWING_HPKE_SUITE,
} from "../src";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk, { addressWithSignersFromRawFalcon1024Signer } from "algosdk";
import { CipherSuite, KemId } from "hpke-js";
import * as falcon from "falcon-1024";

function getKemName(suite: CipherSuite) {
  const id = suite.kem.id;
  if (id === KemId.DhkemX25519HkdfSha256) return "X25519";
  if (id === KemId.XWing) return "X-Wing";
}

describe("Velare", async () => {
  let algorand: AlgorandClient;
  let sender: algosdk.Address;

  let client: VelareClient;

  beforeEach(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    const keypair = falcon.generateKey();
    const { address, txnSigner } = addressWithSignersFromRawFalcon1024Signer({
      falcon1024PublicKey: keypair.publicKey,
      falcon1024Signer: async (bytes: Uint8Array) => {
        return falcon.signCompressed(keypair.privateKey, bytes);
      },
    });

    sender = address;
    await algorand.account.ensureFundedFromEnvironment(sender, (10).algo());

    algorand.account.setSignerFromAccount({
      addr: sender,
      signer: txnSigner,
    });

    client = await VelareClient.deploy(algorand, sender);
  });

  [X25519_HPKE_SUITE, XWING_HPKE_SUITE].forEach((suite) => {
    describe(`${getKemName(suite)}`, async () => {
      const senderViewkey = new Uint8Array(
        await suite.kem.serializePublicKey(
          (await suite.kem.generateKeyPair()).publicKey,
        ),
      );

      it("should handle deposit", async () => {
        const { group, enc, ct } = await client.composeDepositGroup(
          sender,
          0n,
          5n,
          senderViewkey,
          suite,
        );
        await group.send();

        const utxos = await client.appClient.state.box.utxo.getMap();
        expect(utxos.size).toBe(1);

        const utxo = Array.from(utxos.values())[0];
        expect(utxo.encapsulatedKey).toEqual(enc);
        expect(utxo.ciphertext).toEqual(ct);

        const velareAddr = computeVelareAddress(sender, suite, senderViewkey);

        const addressInfo =
          await client.appClient.state.box.addressInfo.value(velareAddr);

        expect(addressInfo?.hpkeSuite).toEqual(getHpkeSuiteId(suite));
        expect(addressInfo?.spendAddress).toEqual(sender.toString());
        expect(addressInfo?.viewKey).toEqual(senderViewkey);
      });

      it("should handle spend", async () => {
        const velareAddr = computeVelareAddress(sender, suite, senderViewkey);

        // Create first deposit (50n to sender)
        const deposit1Result = await client.composeDepositGroup(
          sender,
          0n,
          50n,
          senderViewkey,
          suite,
        );
        await deposit1Result.group.send();

        // Create second deposit (50n to sender)
        const deposit2Result = await client.composeDepositGroup(
          sender,
          0n,
          50n,
          senderViewkey,
          suite,
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
          senderViewkey,
          suite,
        );
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

      it("should handle withdraw", async () => {
        // Create two deposits (50n each) to sender
        const deposit1Result = await client.composeDepositGroup(
          sender,
          0n,
          50n,
          senderViewkey,
          suite,
        );
        await deposit1Result.group.send();

        const deposit2Result = await client.composeDepositGroup(
          sender,
          0n,
          50n,
          senderViewkey,
          suite,
        );
        await deposit2Result.group.send();

        let utxos = await client.appClient.state.box.utxo.getMap();
        expect(utxos.size).toBe(2);

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

        // Withdraw 70n of the 100n, re-shielding 30n as change
        const withdrawAmount = 70n;

        const appAddress = client.appClient.appAddress;
        const appBalanceBefore = (
          await algorand.account.getInformation(appAddress)
        ).balance.microAlgos;

        const withdrawResult = await client.composeWithdrawGroup(
          sender,
          0n,
          inUtxos,
          withdrawAmount,
          senderViewkey,
          suite,
        );
        await withdrawResult.group.send();

        // The two input UTXOs are deleted and a single change UTXO remains
        utxos = await client.appClient.state.box.utxo.getMap();
        expect(utxos.size).toBe(1);

        const utxoEntries = Array.from(utxos.entries());
        const [changeKey, changeUtxo] = utxoEntries[0];

        // The remaining box is the change output commitment
        expect(changeKey.utxo).toBe(withdrawResult.changeCommitment);

        // The change UTXO stores the HPKE data for out1
        expect(changeUtxo.encapsulatedKey).toEqual(
          withdrawResult.outHpkeData[1].encapsulatedKey,
        );
        expect(changeUtxo.ciphertext).toEqual(
          withdrawResult.outHpkeData[1].ciphertext,
        );

        // The app funds 1x UTXO_MBR (change box), refunds 2x UTXO_MBR (deleted
        // inputs) and pays out the withdrawn amount. Inner-txn fees are drawn from
        // the group credit, so the app balance drops by exactly (MBR + amount).
        const appBalanceAfter = (
          await algorand.account.getInformation(appAddress)
        ).balance.microAlgos;
        expect(appBalanceAfter - appBalanceBefore).toBe(
          -(getKemCosts(suite).mbrPerUtxo + withdrawAmount),
        );
      }, 30_000);

      it("should handle withdrawAll without ZK", async () => {
        // Create two deposits (50n each) to sender
        const deposit1Result = await client.composeDepositGroup(
          sender,
          0n,
          50n,
          senderViewkey,
          suite,
        );
        await deposit1Result.group.send();

        const deposit2Result = await client.composeDepositGroup(
          sender,
          0n,
          50n,
          senderViewkey,
          suite,
        );
        await deposit2Result.group.send();

        let utxos = await client.appClient.state.box.utxo.getMap();
        expect(utxos.size).toBe(2);

        const inUtxos = [
          { amount: 50n, secret: deposit1Result.inputs.out_secrets[0] },
          { amount: 50n, secret: deposit2Result.inputs.out_secrets[0] },
        ];

        const appAddress = client.appClient.appAddress;
        const appBalanceBefore = (
          await algorand.account.getInformation(appAddress)
        ).balance.microAlgos;

        const withdrawResult = await client.composeWithdrawAllGroup(
          sender,
          0n,
          inUtxos,
          senderViewkey,
          suite,
        );
        await withdrawResult.group.send();

        // Both UTXOs are spent, none remain
        utxos = await client.appClient.state.box.utxo.getMap();
        expect(utxos.size).toBe(0);

        // The app refunds 2x UTXO_MBR (deleted inputs) and pays out the total
        // withdrawn value. Inner-txn fees are drawn from the group credit, so the
        // app balance drops by exactly (total + refunded MBR).
        const appBalanceAfter = (
          await algorand.account.getInformation(appAddress)
        ).balance.microAlgos;
        expect(appBalanceAfter - appBalanceBefore).toBe(
          -(2n * getKemCosts(suite).mbrPerUtxo + withdrawResult.total),
        );
      }, 30_000);
    });
  });
});
