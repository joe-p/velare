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
  /**
   * Padding for the size-proportional component of the group fee attributable
   * to one KEM-sized payload. See the derivation in `getKemCosts`.
   */
  extraFeePerUtxo: bigint;
};

/** Flat per-box MBR component */
const BOX_FLAT_MBR = 2_500n;
/** Per-byte (key + value) MBR component */
const BOX_BYTE_MBR = 400n;

const boxMbr = (keyBytes: number, valueBytes: number) =>
  BOX_FLAT_MBR + BOX_BYTE_MBR * BigInt(keyBytes + valueBytes);

/**
 * Box MBR and fee padding are pure functions of the KEM's serialized sizes, so
 * they are derived rather than tabulated. This keeps the client as crypto-agile
 * as the contract, which accepts any HPKE suite that fits the AVM size limits.
 */
export function getKemCosts(suite: CipherSuite): KemCosts {
  const encSize = suite.kem.encSize;
  const viewKeySize = suite.kem.publicKeySize;
  // The HPKE ciphertext seals HPKE_PAYLOAD_LENGTH bytes (asset + amount +
  // secret) and the AEAD appends its authentication tag
  const ctSize = HPKE_PAYLOAD_LENGTH + suite.aead.tagSize;

  return {
    // key:   "u" (1) + UtxoKey{ byte[31], uint256 } (63)
    // value: HpkeData{ byte[], byte[] } => 2 ARC-4 offsets (4) plus each
    //        dynamic field's 2-byte length prefix
    mbrPerUtxo: boxMbr(1 + 63, 4 + (2 + encSize) + (2 + ctSize)),
    // key:   "a" (1) + VelareAddress uint256 (32)
    // value: ExpandedVelareAddress{ address (32), byte[6], byte[] } => 38-byte
    //        head plus a 2-byte offset, then the view key's 2-byte length prefix
    mbrPerAddress: boxMbr(1 + 32, 38 + 2 + (2 + viewKeySize)),
    // Consensus charges a fee component proportional to transaction and box
    // bytes on top of the flat per-transaction min fee. Measured empirically: a
    // deposit group carrying X-Wing keys (2272 KEM-dependent bytes more than
    // X25519) needed ~156 microAlgos more than the flat minimum, i.e. roughly
    // 0.07 microAlgos per byte. Charging 1 microAlgo per KEM-dependent byte is
    // a deliberately conservative over-estimate (~14x headroom) that stays
    // negligible in absolute terms and scales to any KEM.
    extraFeePerUtxo: BigInt(encSize + viewKeySize),
  };
}

export const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

// Eventually AlgoKit will need to take care of this, but for now we just assume FALCON everywhere
const FALCON_FEE = 2_000n;

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

export function getHpkeSuiteId(suite: CipherSuite): Uint8Array {
  const id = new Uint8Array(6);
  const view = new DataView(id.buffer);
  view.setUint16(0, suite.kem.id, false); // big-endian
  view.setUint16(2, suite.kdf.id, false); // big-endian
  view.setUint16(4, suite.aead.id, false); // big-endian
  return id;
}

/**
 * Layout of the plaintext HPKE-sealed to the receiver's view key. The cleartext
 * asset id and amount are carried alongside the blinding secret so the receiver
 * can reconstruct the note commitment (MiMC(receiver, asset, amount, secret))
 * without brute-forcing the amount out of the one-way commitment.
 *
 * [ asset: u64 big-endian (8) ][ amount: u64 big-endian (8) ][ secret: 32 ] = 48 bytes
 *
 * Note that `secret` is carried as the raw 32 bytes, while the commitment is
 * computed over `secret mod BLS12_381_SCALAR_MODULUS`. A receiver reading this
 * payload must apply the same reduction before recomputing the commitment;
 * `openUtxoNote` does this for you.
 */
export const HPKE_PAYLOAD_LENGTH = 48;

export function packHpkePayload(
  asset: bigint,
  amount: bigint,
  secret: Uint8Array,
): Uint8Array {
  if (secret.length !== 32) {
    throw new Error(`secret must be 32 bytes, got ${secret.length}`);
  }
  const payload = new Uint8Array(HPKE_PAYLOAD_LENGTH);
  const view = new DataView(payload.buffer);
  view.setBigUint64(0, asset, false); // big-endian
  view.setBigUint64(8, amount, false); // big-endian
  payload.set(secret, 16);
  return payload;
}

export function unpackHpkePayload(payload: Uint8Array): {
  asset: bigint;
  amount: bigint;
  secret: Uint8Array;
} {
  if (payload.length !== HPKE_PAYLOAD_LENGTH) {
    throw new Error(
      `HPKE payload must be ${HPKE_PAYLOAD_LENGTH} bytes, got ${payload.length}`,
    );
  }
  const view = new DataView(
    payload.buffer,
    payload.byteOffset,
    payload.byteLength,
  );
  return {
    asset: view.getBigUint64(0, false),
    amount: view.getBigUint64(8, false),
    secret: payload.slice(16, 48),
  };
}

/**
 * Receiver side of the HPKE payload: decrypt a UTXO's HPKE data with the view
 * private key and validate the recovered note against the commitment the
 * contract actually stored.
 *
 * The validation matters because the sealed (asset, amount) are chosen by the
 * sender and are not authenticated against anything on-chain by HPKE alone. A
 * sender who seals values that disagree with the committed ones produces a note
 * the receiver can never spend, so a receiver must treat a commitment mismatch
 * as "this UTXO is not openable by me" rather than trusting the plaintext.
 *
 * Returns the note on success, or `undefined` if the payload does not open the
 * given commitment.
 */
export async function openUtxoNote(opts: {
  suite: CipherSuite;
  /** The view key pair's private key */
  viewPrivateKey: CryptoKey;
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
  /** The Velare address the UTXO is held under */
  receiver: bigint;
  /** The committed UTXO value, i.e. the `utxo` component of the box key */
  commitment: bigint;
}): Promise<
  | { asset: bigint; amount: bigint; secret: bigint; rawSecret: Uint8Array }
  | undefined
> {
  let note: { asset: bigint; amount: bigint; secret: Uint8Array };
  try {
    const plaintext = new Uint8Array(
      await opts.suite.open(
        {
          recipientKey: opts.viewPrivateKey,
          enc: opts.encapsulatedKey as unknown as ArrayBuffer,
        },
        opts.ciphertext as unknown as ArrayBuffer,
      ),
    );
    note = unpackHpkePayload(plaintext);
  } catch {
    // Not sealed to this view key, or malformed
    return undefined;
  }

  const secret =
    BigInt("0x" + Buffer.from(note.secret).toString("hex")) %
    BLS12_381_SCALAR_MODULUS;

  const expected = calculateCommitment({
    claimer: opts.receiver,
    asset: note.asset,
    amount: note.amount,
    secret,
  });

  if (expected !== opts.commitment) return undefined;

  return {
    asset: note.asset,
    amount: note.amount,
    secret,
    rawSecret: note.secret,
  };
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
      extraFee: microAlgos(FALCON_FEE),
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
      extraFee: microAlgos(FALCON_FEE),
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

  /**
   * Freeze or unfreeze the ZK-dependent methods (`depositAlgo`, `spend`,
   * `withdrawAlgo`). Creator only. While frozen, `withdrawAllAlgo` is the only
   * way to move funds, and it requires revealing balances.
   */
  async setZkFrozen(creator: algosdk.Address, frozen: boolean) {
    return this.appClient.send.setZkFrozen({
      sender: creator,
      args: { frozen },
      extraFee: microAlgos(FALCON_FEE),
    });
  }

  async getZkFrozen(): Promise<boolean> {
    // The generated accessor surfaces the AVM bool as a bigint
    return ((await this.appClient.state.global.zkFrozen()) ?? 0n) !== 0n;
  }

  /**
   * Whether the `addressInfo` box for a Velare address is already funded. The
   * box is written on every deposit but only locks up MBR the first time, so a
   * repeat deposit must not pay for it again — that overpayment has no refund
   * path and would be stranded in the app account.
   */
  private async addressInfoExists(velareAddr: bigint): Promise<boolean> {
    try {
      return (
        (await this.appClient.state.box.addressInfo.value(velareAddr)) !==
        undefined
      );
    } catch {
      return false;
    }
  }

  async composeDepositGroup({
    sender,
    asset,
    amount,
    viewPublic,
    suite = XWING_HPKE_SUITE,
  }: {
    sender: algosdk.Address;
    asset: bigint;
    amount: bigint;
    viewPublic: Uint8Array;
    suite?: CipherSuite;
  }) {
    const group = this.appClient.newGroup();

    const secret = crypto.getRandomValues(new Uint8Array(32));

    const hpkeSuite = getHpkeSuiteId(suite);

    const { enc, ct } = await suite.seal(
      {
        recipientPublicKey: await suite.kem.deserializePublicKey(viewPublic),
      },
      packHpkePayload(asset, amount, secret),
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
        // Only the first deposit to a given Velare address locks up the
        // addressInfo box MBR; later ones rewrite the existing box for free.
        const addressMbr = (await this.addressInfoExists(receiver))
          ? 0n
          : costs.mbrPerAddress;

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
                amount: microAlgos(amount + costs.mbrPerUtxo + addressMbr),
                extraFee: microAlgos(FALCON_FEE),
              }),
              hpkeData: {
                encapsulatedKey: new Uint8Array(enc),
                ciphertext: new Uint8Array(ct),
              },
              hpkeSuite,
              viewKey: viewPublic,
            },
            extraFee: microAlgos(
              lsigsFee.microAlgos + costs.extraFeePerUtxo + FALCON_FEE,
            ),
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

  async composeSpendGroup({
    sender,
    asset,
    inUtxos,
    outAmounts,
    outReceivers,
    viewPublic,
    suite = XWING_HPKE_SUITE,
  }: {
    sender: algosdk.Address;
    asset: bigint;
    inUtxos: Array<{
      amount: bigint;
      secret: bigint;
      encapsulatedKey: Uint8Array;
      ciphertext: Uint8Array;
    }>;
    outAmounts: bigint[];
    outReceivers: bigint[];
    viewPublic: Uint8Array;
    suite?: CipherSuite;
  }) {
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
        packHpkePayload(asset, outAmounts[i], secret),
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
            extraFee: microAlgos(FALCON_FEE),
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
            lsigsFee.microAlgos +
              4_000n +
              2n * costs.extraFeePerUtxo +
              FALCON_FEE,
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
  async composeWithdrawGroup({
    sender,
    asset,
    inUtxos,
    withdrawAmount,
    viewPublic,
    suite = XWING_HPKE_SUITE,
  }: {
    sender: algosdk.Address;
    asset: bigint;
    inUtxos: Array<{
      amount: bigint;
      secret: bigint;
      encapsulatedKey: Uint8Array;
      ciphertext: Uint8Array;
    }>;
    withdrawAmount: bigint;
    viewPublic: Uint8Array;
    suite?: CipherSuite;
  }) {
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

    // Generate a blinding secret for each output. Both are needed by the
    // circuit, but only out1 becomes a UTXO box, so only out1 needs HPKE data —
    // out0's amount and secret are revealed to the contract in the clear.
    const rawSecrets = [0, 1].map(() =>
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const outSecrets = rawSecrets.map(
      (s) =>
        BigInt("0x" + Buffer.from(s).toString("hex")) %
        BLS12_381_SCALAR_MODULUS,
    );

    const { enc, ct } = await suite.seal(
      {
        recipientPublicKey: await suite.kem.deserializePublicKey(viewPublic),
      },
      packHpkePayload(asset, outAmounts[1], rawSecrets[1]),
    );
    const changeHpkeData = {
      encapsulatedKey: new Uint8Array(enc),
      ciphertext: new Uint8Array(ct),
    };

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
            extraFee: microAlgos(FALCON_FEE),
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
            changeHpkeData,
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
          // issued by withdrawAlgo (ensureBudget op-ups + MBR refund + payout),
          // and the KEM-size-proportional component for the change UTXO
          extraFee: microAlgos(
            lsigsFee.microAlgos + 12_000n + costs.extraFeePerUtxo + FALCON_FEE,
          ),
        });
      },
    });

    return {
      group,
      inputs,
      inputCommitments,
      outputCommitments,
      changeHpkeData,
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
  async composeWithdrawAllGroup({
    sender,
    asset,
    inUtxos,
    viewPublic,
    suite = XWING_HPKE_SUITE,
  }: {
    sender: algosdk.Address;
    asset: bigint;
    inUtxos: Array<{ amount: bigint; secret: bigint }>;
    viewPublic: Uint8Array;
    suite?: CipherSuite;
  }) {
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

    // The contract rejects duplicates, but catch it here too so the caller gets
    // a clear error instead of a failed transaction
    const seen = new Set(inputCommitments);
    if (seen.size !== inputCommitments.length) {
      throw new Error("duplicate UTXOs in withdrawAll");
    }

    const total = inUtxos.reduce((acc, u) => acc + u.amount, 0n);
    const costs = getKemCosts(suite);

    group.withdrawAllAlgo({
      sender,
      args: {
        withdrawals: inUtxos.map((u) => [u.amount, u.secret]),
        hpkeSuite,
        viewKey: viewPublic,
      },
      // Covers the inner txns issued by withdrawAllAlgo: ensureBudget op-ups for
      // the per-UTXO MiMC recomputation (~4000 budget each) plus the combined
      // MBR-refund/payout payment, the KEM-size-proportional component for the
      // view key carried in the args, and this call's FALCON signature.
      extraFee: microAlgos(
        BigInt(inUtxos.length) * 8_000n +
          4_000n +
          costs.extraFeePerUtxo +
          FALCON_FEE,
      ),
    });

    return {
      group,
      spender,
      inputCommitments,
      total,
    };
  }
}
