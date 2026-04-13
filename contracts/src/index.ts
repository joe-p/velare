import {
  VelareClient as GeneratedClient,
  VelareFactory as GeneratedFactory,
} from "../contracts/clients/VelareClient";
import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import path from "node:path";
import { PlonkLsigVerifier } from "snarkjs-algorand";
import { calculateCommitment } from "../../circuits/src/index";

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

export function transferVerifier(algorand: AlgorandClient): PlonkLsigVerifier {
  const thisFileDir = new URL(".", import.meta.url);

  const zKey = path.join(
    thisFileDir.pathname,
    "../../circuits/zkeys/transfer.zkey",
  );
  const wasmProver = path.join(
    thisFileDir.pathname,
    "../../circuits/out/transfer_js/transfer.wasm",
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
  transferVerifier: PlonkLsigVerifier;

  constructor(algorand: AlgorandClient, appId: bigint) {
    this.appClient = algorand.client.getTypedAppClientById(GeneratedClient, {
      appId,
    });

    this.depositVerifier = depositVerifier(algorand);
    this.transferVerifier = transferVerifier(algorand);

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
        transferVerifier: (
          await transferVerifier(algorand).lsigAccount()
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
      amount,
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

  async composeTransferGroup({
    sender,
    receiver,
    asset,
    amount,
    balance_secret,
    xfer_secret,
    old_balance,
  }: {
    sender: algosdk.Address;
    receiver: algosdk.Address;
    asset: bigint;
    amount: bigint;
    balance_secret: bigint;
    xfer_secret: bigint;
    old_balance: bigint;
  }) {
    const group = this.appClient.newGroup();

    const inputs = {
      sender_addr: addressInScalarField(sender.publicKey),
      receiver_addr: [addressInScalarField(receiver.publicKey)],
      asset,
      xfer_amt: [amount],
      xfer_secret: [xfer_secret],
      old_balance,
      new_balance: old_balance - 5n,
      balance_secret: balance_secret,
    };

    await this.transferVerifier.verificationParams({
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
          group.transfer({
            sender,
            args: {
              verifierTxn,
              signals: args.signals,
              _proof: args.proof,
              receiver: receiver.toString(),
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

  async verifyBalance(opts: {
    account: algosdk.Address;
    asset?: bigint;
    amount: bigint;
    secret: bigint;
  }) {
    const { account, asset, amount, secret } = opts;
    const balanceBox = await this.appClient.state.box.balances.value({
      addr: account.toString(),
      asset: asset ?? 0n,
    });

    return (
      balanceBox ===
      calculateCommitment({
        claimer: addressInScalarField(account.publicKey),
        asset: asset ?? 0n,
        amount,
        secret,
      })
    );
  }
}
