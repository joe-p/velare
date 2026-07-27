import { describe, it, beforeEach, expect } from "vitest";
import {
  BLS12_381_SCALAR_MODULUS,
  computeVelareAddress,
  getHpkeSuiteId,
  getKemCosts,
  packHpkePayload,
  VelareClient,
  X25519_HPKE_SUITE,
  XWING_HPKE_SUITE,
} from "../src";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
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
          withdrawResult.changeHpkeData.encapsulatedKey,
        );
        expect(changeUtxo.ciphertext).toEqual(
          withdrawResult.changeHpkeData.ciphertext,
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

  // These behaviours are KEM-independent, so they run against X25519 only to
  // keep the suite fast.
  describe("zkFrozen", async () => {
    const suite = X25519_HPKE_SUITE;
    const viewKey = new Uint8Array(
      await suite.kem.serializePublicKey(
        (await suite.kem.generateKeyPair()).publicKey,
      ),
    );

    it("defaults to false on create", async () => {
      expect(await client.getZkFrozen()).toBe(false);
    });

    it("rejects a non-creator", async () => {
      const stranger = algorand.account.random();
      await algorand.account.ensureFundedFromEnvironment(
        stranger.addr,
        (1).algo(),
      );

      await expect(client.setZkFrozen(stranger.addr, true)).rejects.toThrow();
      expect(await client.getZkFrozen()).toBe(false);
    });

    it("blocks the ZK methods and allows withdrawAll, then unfreezes", async () => {
      // Fund two UTXOs while ZK is still available
      const deposit1 = await client.composeDepositGroup(
        sender,
        0n,
        50n,
        viewKey,
        suite,
      );
      await deposit1.group.send();
      const deposit2 = await client.composeDepositGroup(
        sender,
        0n,
        50n,
        viewKey,
        suite,
      );
      await deposit2.group.send();

      await client.setZkFrozen(sender, true);
      expect(await client.getZkFrozen()).toBe(true);

      // Every ZK-dependent entry point is now closed
      const frozenDeposit = await client.composeDepositGroup(
        sender,
        0n,
        5n,
        viewKey,
        suite,
      );
      await expect(frozenDeposit.group.send()).rejects.toThrow(/ZK is frozen/);

      const inUtxos = [
        {
          amount: 50n,
          secret: deposit1.inputs.out_secrets[0],
          encapsulatedKey: deposit1.enc,
          ciphertext: deposit1.ct,
        },
        {
          amount: 50n,
          secret: deposit2.inputs.out_secrets[0],
          encapsulatedKey: deposit2.enc,
          ciphertext: deposit2.ct,
        },
      ];

      const frozenSpend = await client.composeSpendGroup(
        sender,
        0n,
        inUtxos,
        [30n, 70n],
        [
          computeVelareAddress(sender, suite, viewKey),
          computeVelareAddress(sender, suite, viewKey),
        ],
        viewKey,
        suite,
      );
      await expect(frozenSpend.group.send()).rejects.toThrow(/ZK is frozen/);

      const frozenWithdraw = await client.composeWithdrawGroup(
        sender,
        0n,
        inUtxos,
        70n,
        viewKey,
        suite,
      );
      await expect(frozenWithdraw.group.send()).rejects.toThrow(/ZK is frozen/);

      // withdrawAll is the escape hatch and must still work
      const escape = await client.composeWithdrawAllGroup(
        sender,
        0n,
        [
          { amount: 50n, secret: deposit1.inputs.out_secrets[0] },
          { amount: 50n, secret: deposit2.inputs.out_secrets[0] },
        ],
        viewKey,
        suite,
      );
      await escape.group.send();
      expect((await client.appClient.state.box.utxo.getMap()).size).toBe(0);

      // Unfreezing restores the ZK paths
      await client.setZkFrozen(sender, false);
      expect(await client.getZkFrozen()).toBe(false);

      const afterUnfreeze = await client.composeDepositGroup(
        sender,
        0n,
        5n,
        viewKey,
        suite,
      );
      await afterUnfreeze.group.send();
      expect((await client.appClient.state.box.utxo.getMap()).size).toBe(1);
    }, 60_000);
  });

  describe("double-spend guards", async () => {
    const suite = X25519_HPKE_SUITE;
    const viewKey = new Uint8Array(
      await suite.kem.serializePublicKey(
        (await suite.kem.generateKeyPair()).publicKey,
      ),
    );

    it("rejects a deposit that mints more value than it funds", async () => {
      const costs = getKemCosts(suite);
      const receiver = computeVelareAddress(sender, suite, viewKey);

      // The attacker funds only the box MBR, contributing zero shielded value,
      // but proves a UTXO worth 1000 microAlgos. The contract must compare the
      // minted amount against (payment - boxMbr); comparing against
      // (payment + boxMbr) would let this through and mint 2*boxMbr for free.
      const mintAmount = 1_000n;
      const funded = costs.mbrPerUtxo + costs.mbrPerAddress;

      const rawSecret = crypto.getRandomValues(new Uint8Array(32));
      const secret =
        BigInt("0x" + Buffer.from(rawSecret).toString("hex")) %
        BLS12_381_SCALAR_MODULUS;

      const { enc, ct } = await suite.seal(
        {
          recipientPublicKey: await suite.kem.deserializePublicKey(viewKey),
        },
        packHpkePayload(0n, mintAmount, rawSecret),
      );

      const group = client.appClient.newGroup();

      await client.depositVerifier.verificationParams({
        composer: group,
        inputs: {
          asset: 0n,
          receivers: [receiver],
          out_amounts: [mintAmount],
          out_secrets: [secret],
        },
        paramsCallback: async ({ lsigParams, lsigsFee, args }) => {
          group.depositAlgo({
            sender,
            args: {
              verifierTxn: algorand.createTransaction.payment({
                ...lsigParams,
                receiver: lsigParams.sender,
                amount: microAlgos(0),
              }),
              signals: args.signals,
              _proof: args.proof,
              depositTxn: algorand.createTransaction.payment({
                sender,
                receiver: client.appClient.appAddress,
                amount: microAlgos(funded),
                extraFee: microAlgos(2_000n),
              }),
              hpkeData: {
                encapsulatedKey: new Uint8Array(enc),
                ciphertext: new Uint8Array(ct),
              },
              hpkeSuite: getHpkeSuiteId(suite),
              viewKey,
            },
            extraFee: microAlgos(
              lsigsFee.microAlgos + costs.extraFeePerUtxo + 2_000n,
            ),
          });
        },
      });

      await expect(group.send()).rejects.toThrow();
      expect((await client.appClient.state.box.utxo.getMap()).size).toBe(0);
    }, 60_000);

    it("rejects the same UTXO spent as both inputs", async () => {
      // The spend circuit only proves in0 + in1 == out0 + out1, so supplying the
      // same UTXO as both inputs is satisfiable and would double its value.
      const depositA = await client.composeDepositGroup(
        sender,
        0n,
        50n,
        viewKey,
        suite,
      );
      await depositA.group.send();
      // A second UTXO gives the app enough free balance for the doubled outputs
      // to be affordable, so the rejection is the guard and not an MBR shortfall
      const depositB = await client.composeDepositGroup(
        sender,
        0n,
        50n,
        viewKey,
        suite,
      );
      await depositB.group.send();

      const utxoA = {
        amount: 50n,
        secret: depositA.inputs.out_secrets[0],
        encapsulatedKey: depositA.enc,
        ciphertext: depositA.ct,
      };
      const velareAddr = computeVelareAddress(sender, suite, viewKey);

      const doubled = await client.composeSpendGroup(
        sender,
        0n,
        [utxoA, utxoA],
        [50n, 50n],
        [velareAddr, velareAddr],
        viewKey,
        suite,
      );
      await expect(doubled.group.send()).rejects.toThrow(
        /input UTXOs must be distinct/,
      );

      const doubledWithdraw = await client.composeWithdrawGroup(
        sender,
        0n,
        [utxoA, utxoA],
        70n,
        viewKey,
        suite,
      );
      await expect(doubledWithdraw.group.send()).rejects.toThrow(
        /input UTXOs must be distinct/,
      );

      // Nothing was spent
      expect((await client.appClient.state.box.utxo.getMap()).size).toBe(2);
    }, 60_000);

    it("rejects the same UTXO revealed twice in withdrawAll", async () => {
      // Two UTXOs are funded so that claiming one of them twice is genuinely
      // profitable: the doubled payout is covered by the *other* UTXO's value,
      // which is what makes this a fund-draining double-spend rather than a
      // transaction the app simply cannot afford.
      const depositA = await client.composeDepositGroup(
        sender,
        0n,
        50n,
        viewKey,
        suite,
      );
      await depositA.group.send();
      const depositB = await client.composeDepositGroup(
        sender,
        0n,
        50n,
        viewKey,
        suite,
      );
      await depositB.group.send();

      const utxoA = { amount: 50n, secret: depositA.inputs.out_secrets[0] };
      const utxoB = { amount: 50n, secret: depositB.inputs.out_secrets[0] };

      // The client catches it up front
      await expect(
        client.composeWithdrawAllGroup(
          sender,
          0n,
          [utxoA, utxoA],
          viewKey,
          suite,
        ),
      ).rejects.toThrow(/duplicate/i);

      // ...and so does the contract, when the client check is bypassed
      await expect(
        client.appClient.send.withdrawAllAlgo({
          sender,
          args: {
            withdrawals: [
              [utxoA.amount, utxoA.secret],
              [utxoA.amount, utxoA.secret],
            ],
            hpkeSuite: getHpkeSuiteId(suite),
            viewKey,
          },
          extraFee: (20_000).microAlgo(),
        }),
      ).rejects.toThrow(/must open an existing UTXO commitment/);

      // Both UTXOs are untouched
      expect((await client.appClient.state.box.utxo.getMap()).size).toBe(2);

      const appBalanceBefore = (
        await algorand.account.getInformation(client.appClient.appAddress)
      ).balance.microAlgos;

      // Withdrawing them honestly yields exactly their face value
      const honest = await client.composeWithdrawAllGroup(
        sender,
        0n,
        [utxoA, utxoB],
        viewKey,
        suite,
      );
      await honest.group.send();

      const appBalanceAfter = (
        await algorand.account.getInformation(client.appClient.appAddress)
      ).balance.microAlgos;
      expect(appBalanceAfter - appBalanceBefore).toBe(
        -(2n * getKemCosts(suite).mbrPerUtxo + 100n),
      );
    }, 60_000);
  });
});
