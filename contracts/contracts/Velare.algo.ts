import {
  Account,
  BigUint,
  BoxMap,
  Bytes,
  bytes,
  Contract,
  GlobalState,
  gtxn,
  Txn,
  assert,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";
import { sha256 } from "@algorandfoundation/algorand-typescript/op";

/** BLS12-381 scalar field modulus (Fr), 32-byte big-endian */
export const BLS12_381_SCALAR_MODULUS = BigUint(
  Bytes.fromHex(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  ),
);

/**
 * PLONK proof structure: G1 points (96B BE) and field evals (32B BE)
 */
export type PlonkProof = {
  // Uncompressed G1 points
  A: bytes<96>;
  B: bytes<96>;
  C: bytes<96>;
  Z: bytes<96>;
  T1: bytes<96>;
  T2: bytes<96>;
  T3: bytes<96>;
  Wxi: bytes<96>;
  Wxiw: bytes<96>;
  // Field evaluations are 32 bytes (SNARKJS internal representation, BE)
  eval_a: Uint256;
  eval_b: Uint256;
  eval_c: Uint256;
  eval_s1: Uint256;
  eval_s2: Uint256;
  eval_zw: Uint256;
};

/**
 * Key used for storing UTXOs. It should be noted that the ordering is important here.
 * The receiver and asset are first so they can be used as part of the prefix in a query to algod
 */
export type UtxoKey = {
  /** SHA256(receiver || asset) */
  receiverAssetHash: bytes<32>;
  /** Ephemeral key pair used for the key exchange to generate the UTXO blinding secret */
  ephemeralKeypair: bytes<32>;
};

export type UtxoCommitment = Uint256;

export class Velare extends Contract {
  depositVerifier = GlobalState<Account>({ key: "d" });

  transferVerifier = GlobalState<Account>({ key: "t" });

  utxos = BoxMap<UtxoKey, UtxoCommitment>({ keyPrefix: "" });

  createApplication(depositVerifier: Account, transferVerifier: Account) {
    this.depositVerifier.value = depositVerifier;
    this.transferVerifier.value = transferVerifier;
  }

  transfer(
    signals: Uint256[],
    _proof: PlonkProof,
    verifierTxn: gtxn.Transaction,
    receiver: Account,
  ) {
    assert(
      verifierTxn.sender === this.transferVerifier.value,
      "invalid verifier txn",
    );

    const [
      xferCommitment,
      oldBalanceCommitment,
      newBalanceCommitment,
      senderAddr,
      receiverAddr,
      asset,
    ] = signals;

    const transferKey: UtxoKey = {
      sender: Txn.sender,
      receiverAssetHash: sha256(receiver.bytes.concat(asset.bytes))
        .slice(16)
        .toFixed({ length: 16 }),
      nonce: Txn.txId.slice(15).toFixed({ length: 15 }),
    };
    const senderKey = { addr: Txn.sender, asset: asset.asUint64() };

    assert(
      BigUint(Txn.sender.bytes) % BLS12_381_SCALAR_MODULUS ===
        senderAddr.asBigUint(),
      "sender does not match circuit sender",
    );

    assert(
      BigUint(receiver.bytes) % BLS12_381_SCALAR_MODULUS ===
        receiverAddr.asBigUint(),
      "receiver does not match circuit sender",
    );

    assert(
      oldBalanceCommitment === this.balances(senderKey).value,
      "old balance does not match",
    );

    this.balances(senderKey).value = newBalanceCommitment;

    if (!this.pendingTransfers(transferKey).exists) {
      this.pendingTransfers(transferKey).create({ size: 2_000 });
    }
    this.pendingTransfers(transferKey).value.push(xferCommitment);
  }
}
