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
  uint64,
  biguint,
  op,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";
import { bzero, sha256 } from "@algorandfoundation/algorand-typescript/op";

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
  /** SHA256(receiver || asset).slice(0, 31) */
  receiverAssetHash: bytes<31>;
  /** Ephemeral key pair used for the key exchange to generate the UTXO blinding secret */
  ephemeralKey: bytes<32>;
};

export type UtxoCommitment = Uint256;

function u64IsSignal(u64: uint64, signal: Uint256): boolean {
  return signal.asBigUint() === BigUint(u64);
}

function addrIsSignal(addr: Account, signal: Uint256): boolean {
  return addrInField(addr) === signal.asBigUint();
}

function addrInField(addr: Account): biguint {
  return BigUint(addr.bytes) % BLS12_381_SCALAR_MODULUS;
}

export class Velare extends Contract {
  depositVerifier = GlobalState<Account>({ key: "d" });

  spendVerifier = GlobalState<Account>({ key: "s" });

  utxoMap = BoxMap<UtxoKey, UtxoCommitment>({ keyPrefix: "m" });

  createApplication(depositVerifier: Account, spendVerifier: Account) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
  }

  depositAlgo(
    signals: Uint256[],
    _proof: PlonkProof,
    verifierTxn: gtxn.Transaction,
    depositTxn: gtxn.PaymentTxn,
    ephemeralKey: bytes<32>,
  ) {
    assert(
      verifierTxn.sender === this.depositVerifier.value,
      "invalid verifier txn",
    );

    const [amount, output, asset, receiver] = signals;

    assert(
      amount.asBigUint() <= BigUint(depositTxn.amount),
      "UTXO amount should be less than or equal to deposit amount",
    );
    assert(u64IsSignal(0, asset), "UTXO asset should be 0 for ALGO deposit");
    assert(
      addrIsSignal(Txn.sender, receiver),
      "UTXO receiver should be the depositor",
    );

    const utxoKey: UtxoKey = {
      receiverAssetHash: sha256(receiver.bytes.concat(op.itob(0)))
        .slice(0, 31)
        .toFixed({ length: 31 }),
      ephemeralKey,
    };
    this.utxoMap(utxoKey).value = output;
  }
}
