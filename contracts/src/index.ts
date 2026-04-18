import {
  VelareClient as GeneratedClient,
  VelareFactory as GeneratedFactory,
} from "../contracts/clients/VelareClient";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import path from "node:path";
import { PlonkLsigVerifier } from "snarkjs-algorand";
import { CipherSuite, KemId, KdfId, AeadId } from "hpke-js";
import { sha256 } from "@noble/hashes/sha2.js";

const UTXO_MBR = 63_300n;
const ADDR_MBR = 45_300n;

const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

export const DEFAULT_HPKE_SUITE = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
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
    "../../circuits/zkeys/spend_2_2.zkey",
  );
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../../circuits/out/spend_2_2_js/spend.wasm",
  );

  return new PlonkLsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: 13,
    appOffset: 1,
  });
}

export class VelareClient {
  appClient: GeneratedClient;
  algorand: AlgorandClient;
  depositVerifier: PlonkLsigVerifier;
  spendVerifier: PlonkLsigVerifier;

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
      },
    });

    await algorand.send.payment({
      sender: creator,
      receiver: result.appClient.appAddress,
      amount: microAlgos(100_000),
    });

    return new VelareClient(algorand, result.appClient.appId);
  }

  async composeDepositGroup(
    sender: algosdk.Address,
    asset: bigint,
    amount: bigint,
    viewPublic: Uint8Array,
  ) {
    const group = this.appClient.newGroup();

    const secret = crypto.getRandomValues(new Uint8Array(32));

    const hpkeSuite = getHpkeSuiteId(DEFAULT_HPKE_SUITE);

    const { enc, ct } = await DEFAULT_HPKE_SUITE.seal(
      {
        recipientPublicKey:
          await DEFAULT_HPKE_SUITE.kem.deserializePublicKey(viewPublic),
      },
      secret,
    );

    const inputs = {
      asset,
      receivers: [computeVelareAddress(sender, DEFAULT_HPKE_SUITE, viewPublic)],
      out_amounts: [amount],
      out_secrets: [
        BigInt("0x" + Buffer.from(secret).toString("hex")) %
          BLS12_381_SCALAR_MODULUS,
      ],
    };

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
                amount: microAlgos(amount + UTXO_MBR + ADDR_MBR),
              }),
              hpkeData: {
                encapsulatedKey: new Uint8Array(enc),
                ciphertext: new Uint8Array(ct),
              },
              hpkeSuite,
              viewKey: viewPublic,
            },
            extraFee: microAlgos(lsigsFee.microAlgos),
          });
        } else {
          throw Error("ASAs not yet supported");
        }
      },
    });

    return {
      group,
      inputs,
      enc: new Uint8Array(enc),
      ct: new Uint8Array(ct),
    };
  }
}
