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
  clone,
  itxn,
  ensureBudget,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";
import {
  exp,
  Global,
  sha256,
} from "@algorandfoundation/algorand-typescript/op";

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
  /** SHA256(VelareAddress || asset).slice(0, 31) */
  receiverAssetHash: bytes<31>;
  utxo: Uint256;
};

/** SHA256(spendAddress || hpkeSuite || viewKey) % BLS12_381_SCALAR_MODULUS */
export type VelareAddress = Uint256;

export type ExpandedVelareAddress = {
  /** The Algorand address that has spend authority over the UTXOs */
  spendAddress: Account;
  /**
   * Identifier for KEM, KDF, and AEAD algorithms used for HPKE.
   * See RFC 9180 Section 7: https://www.rfc-editor.org/rfc/rfc9180.html#section-7
   */
  hpkeSuite: bytes<6>;
  /** The key used for the HPKE KEM */
  viewKey: bytes;
};

export type HpkeData = {
  encapsulatedKey: bytes;
  ciphertext: bytes;
};

function u64IsSignal(u64: uint64, signal: Uint256): boolean {
  return signal.asBigUint() === BigUint(u64);
}

function utxoKey(addr: VelareAddress, asset: Uint256, utxo: Uint256): UtxoKey {
  return {
    receiverAssetHash: sha256(addr.bytes.concat(asset.bytes))
      .slice(0, 31)
      .toFixed({ length: 31 }),
    utxo,
  };
}

function velareAddress(expandedAddr: ExpandedVelareAddress) {
  const { spendAddress, hpkeSuite, viewKey } = expandedAddr;
  return new Uint256(
    BigUint(sha256(spendAddress.bytes.concat(hpkeSuite).concat(viewKey))) %
      BLS12_381_SCALAR_MODULUS,
  );
}

export class Velare extends Contract {
  depositVerifier = GlobalState<Account>({ key: "d" });

  spendVerifier = GlobalState<Account>({ key: "s" });

  /** Map of UTXO information to the HPKE data */
  utxo = BoxMap<UtxoKey, HpkeData>({ keyPrefix: "u" });

  addressInfo = BoxMap<VelareAddress, ExpandedVelareAddress>({
    keyPrefix: "a",
  });

  createApplication(depositVerifier: Account, spendVerifier: Account) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
  }

  depositAlgo(
    signals: Uint256[],
    _proof: PlonkProof,
    verifierTxn: gtxn.Transaction,
    depositTxn: gtxn.PaymentTxn,
    hpkeData: HpkeData,
    hpkeSuite: bytes<6>,
    viewKey: bytes,
  ) {
    assert(
      verifierTxn.sender === this.depositVerifier.value,
      "invalid verifier txn",
    );

    const [amount, output, asset, receiver] = signals;

    assert(u64IsSignal(0, asset), "UTXO asset should be 0 for ALGO deposit");
    const expandedVelareAddr = {
      spendAddress: Txn.sender,
      hpkeSuite,
      viewKey,
    };
    const velareAddr = velareAddress(expandedVelareAddr);
    assert(velareAddr === receiver, "UTXO receiver should be the depositor");

    const preMbr: uint64 = Global.currentApplicationAddress.minBalance;
    this.utxo(utxoKey(receiver, asset, output)).value = clone(hpkeData);
    this.addressInfo(receiver).value = clone(expandedVelareAddr);
    const boxMbr: uint64 = Global.currentApplicationAddress.minBalance - preMbr;

    assert(
      amount.asBigUint() <= BigUint(depositTxn.amount + boxMbr),
      "UTXO amount should be less than or equal to deposit amount + boxMbr",
    );
  }

  private _deleteUtxos(utxoKeys: UtxoKey[]) {
    const preMbr = Global.currentApplicationAddress.minBalance;
    for (const utxoKey of clone(utxoKeys)) {
      this.utxo(utxoKey).delete();
    }
    const postMbr: uint64 = Global.currentApplicationAddress.minBalance;

    itxn.payment({ receiver: Txn.sender, amount: preMbr - postMbr }).submit();
  }

  spend(
    _signals: Uint256[],
    _proof: PlonkProof,
    signalValues: Uint256[],
    verifierTxn: gtxn.Transaction,
    hpkeData: HpkeData[],
    hpkeSuite: bytes<6>,
    viewKey: bytes,
  ) {
    ensureBudget(1400);
    assert(
      verifierTxn.sender === this.spendVerifier.value,
      "invalid verifier txn",
    );

    const [in0, in1, out0, out1, spender, asset, receivers0, receivers1] =
      signalValues;

    // TODO: Ensure signalValues hash to signals[0] in an lsig

    assert(
      velareAddress({ spendAddress: Txn.sender, hpkeSuite, viewKey }) ===
        spender,
      "UTXO receiver should be the depositor",
    );

    const inKey0 = utxoKey(spender, asset, in0);
    const inKey1 = utxoKey(spender, asset, in1);
    const outKey0 = utxoKey(receivers0, asset, out0);
    const outKey1 = utxoKey(receivers1, asset, out1);

    assert(this.utxo(inKey0).exists);
    assert(this.utxo(inKey1).exists);

    this.utxo(outKey0).value = clone(hpkeData[0]);
    this.utxo(outKey1).value = clone(hpkeData[1]);

    this._deleteUtxos([inKey0, inKey1]);
  }
}
