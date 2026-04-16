import {
  VelareClient as GeneratedClient,
  VelareFactory as GeneratedFactory,
} from "../contracts/clients/VelareClient";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import path from "node:path";
import { PlonkLsigVerifier } from "snarkjs-algorand";
import { x25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";

const UTXO_MBR = 82_200n;

const BLS12_381_SCALAR_MODULUS = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);

export function addressInScalarField(addr: Uint8Array): bigint {
  const asBigint = BigInt("0x" + Buffer.from(addr).toString("hex"));
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

function ecdh(keys: { private: Uint8Array; public: Uint8Array }) {
  return bytesToNumberBE(x25519.getSharedSecret(keys.public, keys.private));
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

    const ephemeralKey = x25519.keygen();

    const inputs = {
      asset,
      receivers: [addressInScalarField(sender.publicKey)],
      out_amounts: [amount],
      out_secrets: [
        ecdh({ public: viewPublic, private: ephemeralKey.secretKey }),
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
                amount: microAlgos(amount + UTXO_MBR),
              }),
              ephemeralKey: ephemeralKey.publicKey,
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
    };
  }
}
