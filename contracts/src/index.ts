import {
  VelareClient as GeneratedClient,
  VelareFactory as GeneratedFactory,
} from "../contracts/clients/VelareClient";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import algosdk, { LogicSigAccount } from "algosdk";
import path, { join } from "node:path";
import { PlonkLsigVerifier } from "snarkjs-algorand";
import { CipherSuite, KemId, KdfId, AeadId } from "hpke-js";
import { XWing } from "@hpke/hybridkem-x-wing";
import { sha256 } from "@noble/hashes/sha2.js";
import { calculateCommitment } from "../../circuits/src";
import { readFileSync } from "node:fs";

type KemCosts = {
  /** Box MBR for a single UTXO box (key + HpkeData value) */
  mbrPerUtxo: bigint;
  /** Box MBR for a single addressInfo box (key + ExpandedVelareAddress value) */
  mbrPerAddress: bigint;
  extraFeePerUtxo: bigint;
};

const X25519_COSTS: KemCosts = {
  mbrPerUtxo: 63_300n,
  mbrPerAddress: 45_300n,
  extraFeePerUtxo: 0n,
};

const XWING_COSTS: KemCosts = {
  // X-Wing's encapsulated key is 1088 bytes larger than X25519's (ML-KEM-768
  // ciphertext 1088B + X25519 ephemeral 32B = 1120B vs 32B), which costs an
  // extra 1088 * 400 = 435_200 microAlgos of box MBR per UTXO.
  mbrPerUtxo: X25519_COSTS.mbrPerUtxo + 435_200n,
  // X-Wing's view key (public key) is 1184 bytes larger than X25519's
  // (ML-KEM-768 encapsulation key 1184B + X25519 32B = 1216B vs 32B), which
  // costs an extra 1184 * 400 = 473_600 microAlgos of box MBR per address.
  mbrPerAddress: X25519_COSTS.mbrPerAddress + 473_600n,
  extraFeePerUtxo: 155_000n,
};

const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

export const X25519_HPKE_SUITE = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
  kdf: KdfId.HkdfSha512,
  aead: AeadId.Chacha20Poly1305,
});

export const XWING_HPKE_SUITE = new CipherSuite({
  kem: new XWing(),
  kdf: KdfId.HkdfSha512,
  aead: AeadId.Chacha20Poly1305,
});

export function getKemCosts(suite: CipherSuite): KemCosts {
  if (suite.kem.id === KemId.XWing) return XWING_COSTS;
  if (suite.kem.id === KemId.DhkemX25519HkdfSha256) return X25519_COSTS;
  throw Error(`Unsupported KEM ${suite.kem}`);
}

export function getHpkeSuiteId(suite: CipherSuite): Uint8Array {
  const id = new Uint8Array(6);
  const view = new DataView(id.buffer);
  view.setUint16(0, suite.kem.id, false); // big-endian
  view.setUint16(2, suite.kdf.id, false); // big-endian
  view.setUint16(4, suite.aead.id, false); // big-endian
  return id;
}

export function addressInScalarField(addr: Uint8Array): bigint {
  const asBigint = BigInt("0x" + Buffer.from(addr).toString("hex"));
  return asBigint % BLS12_381_SCALAR_MODULUS;
}

export function computeVelareAddress(
  spendAddress: algosdk.Address,
  suite: CipherSuite,
  viewKey: Uint8Array,
): bigint {
  const hpkeSuiteId = getHpkeSuiteId(suite);
  const data = new Uint8Array([
    ...spendAddress.publicKey,
    ...hpkeSuiteId,
    ...viewKey,
  ]);
  const hash = sha256(data);
  const asBigint = BigInt("0x" + Buffer.from(hash).toString("hex"));
  return asBigint % BLS12_381_SCALAR_MODULUS;
}

export function depositVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);

  const zKey = path.join(
    thisFileDir.pathname,
    "../../circuits/zkeys/deposit_1.zkey",
  );
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../../circuits/out/deposit_1_js/deposit_1.wasm",
  );

  return new PlonkLsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: 9,
    appOffset: 2,
  });
}

export function spendVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);

  const zKey = path.join(
    thisFileDir.pathname,
    "../../circuits/zkeys/spend_hashed_2_2.zkey",
  );
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../../circuits/out/spend_hashed_2_2_js/spend_hashed_2_2.wasm",
  );

  return new PlonkLsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: 7,
    appOffset: 1,
  });
}

export class VelareClient {
  appClient: GeneratedClient;
  algorand: AlgorandClient;
  depositVerifier: PlonkLsigVerifier;
  spendVerifier: PlonkLsigVerifier;
  signalVerifier?: LogicSigAccount;

  constructor(algorand: AlgorandClient, appId: bigint) {
    this.appClient = algorand.client.getTypedAppClientById(GeneratedClient, {
      appId,
    });

    this.depositVerifier = depositVerifier(algorand);
    this.spendVerifier = spendVerifier(algorand);

    this.algorand = algorand;
  }

  static async deploy(algorand: AlgorandClient, creator: algosdk.Address) {
    const factory = algorand.client.getTypedAppFactory(GeneratedFactory, {});

    const result = await factory.send.create.createApplication({
      sender: creator,
      args: {
        depositVerifier: (
          await depositVerifier(algorand).lsigAccount()
        ).addr.toString(),
        spendVerifier: (
          await spendVerifier(algorand).lsigAccount()
        ).addr.toString(),
        signalVerifier: (await this.signalVerifierLsig(algorand))
          .address()
          .toString(),
      },
    });

    await algorand.send.payment({
      sender: creator,
      receiver: result.appClient.appAddress,
      amount: microAlgos(100_000),
    });

    return new VelareClient(algorand, result.appClient.appId);
  }

  static async signalVerifierLsig(algorand: AlgorandClient) {
    const signalVerifierTeal = readFileSync(
      join(__dirname, "../contracts/out/SignalVerifier.teal"),
    );
    const compiled = (
      await algorand.client.algod.compile(signalVerifierTeal).do()
    ).result;

    const signalVerifier = algorand.account.logicsig(
      Buffer.from(compiled, "base64"),
    ).account;

    return signalVerifier;
  }

  async composeDepositGroup(
    sender: algosdk.Address,
    asset: bigint,
    amount: bigint,
    viewPublic: Uint8Array,
    suite: CipherSuite,
  ) {
    const group = this.appClient.newGroup();

    const secret = crypto.getRandomValues(new Uint8Array(32));

    const hpkeSuite = getHpkeSuiteId(suite);

    const { enc, ct } = await suite.seal(
      {
        recipientPublicKey: await suite.kem.deserializePublicKey(viewPublic),
      },
      secret,
    );

    const secretBigint =
      BigInt("0x" + Buffer.from(secret).toString("hex")) %
      BLS12_381_SCALAR_MODULUS;

    const receiver = computeVelareAddress(sender, suite, viewPublic);

    const inputs = {
      asset,
      receivers: [receiver],
      out_amounts: [amount],
      out_secrets: [secretBigint],
    };

    // Calculate the output commitment
    const outputCommitment = calculateCommitment({
      claimer: receiver,
      asset,
      amount,
      secret: secretBigint,
    });

    await this.depositVerifier.verificationParams({
      composer: group,
      inputs,
      paramsCallback: async (params) => {
        const { lsigParams, lsigsFee, args } = params;

        const verifierTxn = this.algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        const costs = getKemCosts(suite);
        if (asset === 0n) {
          group.depositAlgo({
            sender,
            args: {
              verifierTxn,
              signals: args.signals,
              _proof: args.proof,
              depositTxn: this.algorand.createTransaction.payment({
                sender,
                receiver: this.appClient.appAddress,
                amount: microAlgos(
                  amount + costs.mbrPerUtxo + costs.mbrPerAddress,
                ),
              }),
              hpkeData: {
                encapsulatedKey: new Uint8Array(enc),
                ciphertext: new Uint8Array(ct),
              },
              hpkeSuite,
              viewKey: viewPublic,
            },
            extraFee: microAlgos(lsigsFee.microAlgos + costs.extraFeePerUtxo),
          });
        } else {
          throw Error("ASAs not yet supported");
        }
      },
    });

    return {
      group,
      inputs,
      outputCommitment,
      enc: new Uint8Array(enc),
      ct: new Uint8Array(ct),
    };
  }

  async composeSpendGroup(
    sender: algosdk.Address,
    asset: bigint,
    inUtxos: Array<{
      amount: bigint;
      secret: bigint;
      encapsulatedKey: Uint8Array;
      ciphertext: Uint8Array;
    }>,
    outAmounts: bigint[],
    outReceivers: bigint[],
    viewPublic: Uint8Array,
    suite: CipherSuite,
  ) {
    const group = this.appClient.newGroup();

    if (inUtxos.length !== 2) {
      throw new Error("Only 2 input UTXOs are supported");
    }
    if (outAmounts.length !== 2) {
      throw new Error("Only 2 output amounts are supported");
    }
    if (outReceivers.length !== 2) {
      throw new Error("Only 2 output receivers are supported");
    }

    const spender = computeVelareAddress(sender, suite, viewPublic);

    // Generate secrets and HPKE data for outputs
    const outSecrets: bigint[] = [];
    const outHpkeData: Array<{
      encapsulatedKey: Uint8Array;
      ciphertext: Uint8Array;
    }> = [];

    const costs = getKemCosts(suite);

    for (let i = 0; i < 2; i++) {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const secretBigint =
        BigInt("0x" + Buffer.from(secret).toString("hex")) %
        BLS12_381_SCALAR_MODULUS;
      outSecrets.push(secretBigint);

      const { enc, ct } = await suite.seal(
        {
          recipientPublicKey: await suite.kem.deserializePublicKey(viewPublic),
        },
        secret,
      );

      outHpkeData.push({
        encapsulatedKey: new Uint8Array(enc),
        ciphertext: new Uint8Array(ct),
      });
    }

    const inputs = {
      spender,
      asset,
      receivers: outReceivers,
      in_amounts: inUtxos.map((u) => u.amount),
      in_secrets: inUtxos.map((u) => u.secret),
      out_amounts: outAmounts,
      out_secrets: outSecrets,
    };

    // Calculate input commitments (what we're spending)
    const inputCommitments = inUtxos.map((u) =>
      calculateCommitment({
        claimer: spender,
        asset,
        amount: u.amount,
        secret: u.secret,
      }),
    );

    // Calculate output commitments (what we're creating)
    const outputCommitments = outAmounts.map((amount, i) =>
      calculateCommitment({
        claimer: outReceivers[i],
        asset,
        amount,
        secret: outSecrets[i],
      }),
    );

    await this.spendVerifier.verificationParams({
      composer: group,
      inputs,
      paramsCallback: async (params) => {
        const { lsigParams, lsigsFee, args } = params;

        const verifierTxn = await this.algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        const hpkeSuite = getHpkeSuiteId(suite);

        group.addTransaction(
          await this.algorand.createTransaction.payment({
            sender,
            receiver: this.appClient.appAddress,
            amount: microAlgos(costs.mbrPerUtxo * 2n),
          }),
        );

        this.signalVerifier =
          this.signalVerifier ??
          (await VelareClient.signalVerifierLsig(this.algorand));

        const signalVerifierTxn = await this.algorand.createTransaction.payment(
          {
            sender: this.signalVerifier.address(),
            receiver: this.appClient.appAddress,
            amount: microAlgos(0),
            staticFee: microAlgos(0),
          },
        );

        group.spend({
          sender,
          args: {
            verifierTxn,
            signalVerifierTxn,
            _signals: args.signals,
            _proof: args.proof,
            hpkeData: [
              [outHpkeData[0].ciphertext, outHpkeData[0].encapsulatedKey],
              [outHpkeData[1].ciphertext, outHpkeData[1].encapsulatedKey],
            ],
            hpkeSuite,
            viewKey: viewPublic,
            signalValues: [
              inputCommitments[0],
              inputCommitments[1],
              outputCommitments[0],
              outputCommitments[1],
              inputs.spender,
              inputs.asset,
              inputs.receivers[0],
              inputs.receivers[1],
            ],
          },
          extraFee: microAlgos(
            lsigsFee.microAlgos + 4_000n + 2n * costs.extraFeePerUtxo,
          ),
        });
      },
    });

    return {
      group,
      inputs,
      inputCommitments,
      outputCommitments,
      outHpkeData,
    };
  }

  /**
   * Un-shield ALGO by spending two UTXOs via the spend_hashed_2_2 circuit.
   * The first output (out0) is withdrawn to `sender` as ALGO; the remaining
   * value is re-shielded as a change UTXO (out1) back to the same address.
   */
  async composeWithdrawGroup(
    sender: algosdk.Address,
    asset: bigint,
    inUtxos: Array<{
      amount: bigint;
      secret: bigint;
      encapsulatedKey: Uint8Array;
      ciphertext: Uint8Array;
    }>,
    withdrawAmount: bigint,
    viewPublic: Uint8Array,
    suite: CipherSuite,
  ) {
    const group = this.appClient.newGroup();

    if (inUtxos.length !== 2) {
      throw new Error("Only 2 input UTXOs are supported");
    }

    const spender = computeVelareAddress(sender, suite, viewPublic);

    const totalIn = inUtxos[0].amount + inUtxos[1].amount;
    if (withdrawAmount > totalIn) {
      throw new Error("Withdraw amount exceeds input UTXO value");
    }
    const changeAmount = totalIn - withdrawAmount;

    // out0 = withdrawn to the sender, out1 = re-shielded change to the spender.
    // Both receivers are the caller's Velare address (the contract requires
    // receiver0 == velareAddress(sender) and receiver1 == spender).
    const outAmounts = [withdrawAmount, changeAmount];
    const outReceivers = [spender, spender];

    // Generate a blinding secret for each output. out0's secret is revealed to
    // the contract; out1 is stored as a UTXO box so it also needs HPKE data.
    const outSecrets: bigint[] = [];
    const outHpkeData: Array<{
      encapsulatedKey: Uint8Array;
      ciphertext: Uint8Array;
    }> = [];

    for (let i = 0; i < 2; i++) {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const secretBigint =
        BigInt("0x" + Buffer.from(secret).toString("hex")) %
        BLS12_381_SCALAR_MODULUS;
      outSecrets.push(secretBigint);

      const { enc, ct } = await suite.seal(
        {
          recipientPublicKey: await suite.kem.deserializePublicKey(viewPublic),
        },
        secret,
      );

      outHpkeData.push({
        encapsulatedKey: new Uint8Array(enc),
        ciphertext: new Uint8Array(ct),
      });
    }

    const inputs = {
      spender,
      asset,
      receivers: outReceivers,
      in_amounts: inUtxos.map((u) => u.amount),
      in_secrets: inUtxos.map((u) => u.secret),
      out_amounts: outAmounts,
      out_secrets: outSecrets,
    };

    // Input commitments (what we're spending)
    const inputCommitments = inUtxos.map((u) =>
      calculateCommitment({
        claimer: spender,
        asset,
        amount: u.amount,
        secret: u.secret,
      }),
    );

    // Output commitments (out0 withdrawn, out1 change)
    const outputCommitments = outAmounts.map((amount, i) =>
      calculateCommitment({
        claimer: outReceivers[i],
        asset,
        amount,
        secret: outSecrets[i],
      }),
    );

    await this.spendVerifier.verificationParams({
      composer: group,
      inputs,
      paramsCallback: async (params) => {
        const { lsigParams, lsigsFee, args } = params;

        const verifierTxn = await this.algorand.createTransaction.payment({
          ...lsigParams,
          receiver: lsigParams.sender,
          amount: microAlgos(0),
        });

        const hpkeSuite = getHpkeSuiteId(suite);
        const costs = getKemCosts(suite);

        // Fund the MBR for the single change UTXO box
        group.addTransaction(
          await this.algorand.createTransaction.payment({
            sender,
            receiver: this.appClient.appAddress,
            amount: microAlgos(costs.mbrPerUtxo),
          }),
        );

        this.signalVerifier =
          this.signalVerifier ??
          (await VelareClient.signalVerifierLsig(this.algorand));

        const signalVerifierTxn = await this.algorand.createTransaction.payment(
          {
            sender: this.signalVerifier.address(),
            receiver: this.appClient.appAddress,
            amount: microAlgos(0),
            staticFee: microAlgos(0),
          },
        );

        group.withdrawAlgo({
          sender,
          args: {
            verifierTxn,
            signalVerifierTxn,
            _signals: args.signals,
            _proof: args.proof,
            withdrawAmount,
            withdrawSecret: outSecrets[0],
            changeHpkeData: {
              encapsulatedKey: outHpkeData[1].encapsulatedKey,
              ciphertext: outHpkeData[1].ciphertext,
            },
            hpkeSuite,
            viewKey: viewPublic,
            signalValues: [
              inputCommitments[0],
              inputCommitments[1],
              outputCommitments[0],
              outputCommitments[1],
              inputs.spender,
              inputs.asset,
              inputs.receivers[0],
              inputs.receivers[1],
            ],
          },
          // Covers the zk/signal lsig fees plus the op-up and payment itxns
          // issued by withdrawAlgo (ensureBudget op-ups + MBR refund + payout)
          extraFee: microAlgos(lsigsFee.microAlgos + 12_000n),
        });
      },
    });

    return {
      group,
      inputs,
      inputCommitments,
      outputCommitments,
      outHpkeData,
      withdrawAmount,
      changeAmount,
      changeCommitment: outputCommitments[1],
    };
  }

  /**
   * Un-shield ALGO WITHOUT a ZK proof. The caller reveals the cleartext amount
   * and blinding secret of each owned UTXO; the contract recomputes each MiMC
   * commitment and requires the corresponding UTXO box to exist. All revealed
   * UTXOs are spent and their total value is paid out to `sender` as ALGO.
   */
  async composeWithdrawAllGroup(
    sender: algosdk.Address,
    asset: bigint,
    inUtxos: Array<{ amount: bigint; secret: bigint }>,
    viewPublic: Uint8Array,
    suite: CipherSuite,
  ) {
    const group = this.appClient.newGroup();

    if (asset !== 0n) {
      throw new Error("withdrawAllAlgo only supports ALGO (asset 0)");
    }

    const hpkeSuite = getHpkeSuiteId(suite);

    const spender = computeVelareAddress(sender, suite, viewPublic);

    // The commitments the contract will recompute and look up as UTXO boxes
    const inputCommitments = inUtxos.map((u) =>
      calculateCommitment({
        claimer: spender,
        asset,
        amount: u.amount,
        secret: u.secret,
      }),
    );

    const total = inUtxos.reduce((acc, u) => acc + u.amount, 0n);

    group.withdrawAllAlgo({
      sender,
      args: {
        withdrawals: inUtxos.map((u) => [u.amount, u.secret]),
        hpkeSuite,
        viewKey: viewPublic,
      },
      // Covers the inner txns issued by withdrawAllAlgo: ensureBudget op-ups for
      // the per-UTXO MiMC recomputation (~4000 budget each) plus the MBR refund
      // and the payout payment.
      extraFee: microAlgos(BigInt(inUtxos.length) * 8_000n + 4_000n),
    });

    return {
      group,
      spender,
      inputCommitments,
      total,
    };
  }
}
