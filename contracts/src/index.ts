import {
  ConfidentialTransactionsClient as GeneratedClient,
  ConfidentialTransactionsFactory as GeneratedFactory,
} from "../contracts/clients/ConfidentialTransactionsClient";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import path from "node:path";
import { PlonkLsigVerifier } from "snarkjs-algorand";

const BALANCE_MBR = 31_700n;

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
    "../../circuits/zkeys/deposit.zkey",
  );
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../../circuits/out/deposit_js/deposit.wasm",
  );

  return new PlonkLsigVerifier({
    algorand,
    zKey,
    wasmProver,
    totalLsigs: 9,
    appOffset: 2,
  });
}

export class ConfidentialTransactionsClient {
  appClient: GeneratedClient;
  algorand: AlgorandClient;
  depositVerifier: PlonkLsigVerifier;

  constructor(algorand: AlgorandClient, appId: bigint) {
    this.appClient = algorand.client.getTypedAppClientById(GeneratedClient, {
      appId,
    });

    this.depositVerifier = depositVerifier(algorand);

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
      },
    });

    await algorand.send.payment({
      sender: creator,
      receiver: result.appClient.appAddress,
      amount: microAlgos(100_000),
    });

    return new ConfidentialTransactionsClient(algorand, result.appClient.appId);
  }

  async composeInitializeGroup(
    sender: algosdk.Address,
    asset: bigint,
    amount: bigint,
    secret: bigint,
  ) {
    const group = this.appClient.newGroup();

    const inputs = {
      addr: addressInScalarField(sender.publicKey),
      asset,
      amount: 0,
      secret,
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
          group.initializeAlgoBalance({
            sender,
            args: {
              verifierTxn,
              signals: args.signals,
              _proof: args.proof,
              depositTxn: this.algorand.createTransaction.payment({
                sender,
                receiver: this.appClient.appAddress,
                amount: microAlgos(amount + BALANCE_MBR),
              }),
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
