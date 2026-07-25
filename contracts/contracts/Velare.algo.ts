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
  Global,
  mimc,
  MimcConfigurations,
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

/** A UTXO to withdraw, opened by revealing its cleartext amount and blinding secret */
export type AlgoWithdrawal = {
  /** Cleartext amount of the UTXO */
  amount: uint64;
  /** Blinding secret of the UTXO */
  secret: Uint256;
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

  signalVerifier = GlobalState<Account>({ key: "S" });

  /** Map of UTXO information to the HPKE data */
  utxo = BoxMap<UtxoKey, HpkeData>({ keyPrefix: "u" });

  addressInfo = BoxMap<VelareAddress, ExpandedVelareAddress>({
    keyPrefix: "a",
  });

  createApplication(
    depositVerifier: Account,
    spendVerifier: Account,
    signalVerifier: Account,
  ) {
    this.depositVerifier.value = depositVerifier;
    this.spendVerifier.value = spendVerifier;
    this.signalVerifier.value = signalVerifier;
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
    signalVerifierTxn: gtxn.Transaction,
    verifierTxn: gtxn.Transaction,
    hpkeData: HpkeData[],
    hpkeSuite: bytes<6>,
    viewKey: bytes,
  ) {
    ensureBudget(1400);
    assert(
      verifierTxn.sender === this.spendVerifier.value,
      "invalid zk verifier txn",
    );
    assert(
      signalVerifierTxn.sender === this.signalVerifier.value,
      "invalid signal verifier txn",
    );

    const [in0, in1, out0, out1, spender, asset, receivers0, receivers1] =
      signalValues;

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

  /**
   * Un-shield ALGO by spending two UTXOs. Re-uses the spend_hashed_2_2 circuit:
   * one output (out0) is withdrawn to the caller as ALGO, the other (out1) is
   * kept as a shielded change UTXO. The circuit guarantees in0 + in1 == out0 +
   * out1, so paying out out0's amount and re-shielding out1 conserves value.
   *
   * The withdrawn amount is private in the proof, so the caller must reveal
   * out0's amount and blinding secret; we recompute its commitment with the
   * same MiMC used by the circuit and require it to match the proven output.
   */
  withdrawAlgo(
    _signals: Uint256[],
    _proof: PlonkProof,
    signalValues: Uint256[],
    signalVerifierTxn: gtxn.Transaction,
    verifierTxn: gtxn.Transaction,
    /** Cleartext amount of the withdrawn output (out0) */
    withdrawAmount: uint64,
    /** Blinding secret of the withdrawn output (out0) */
    withdrawSecret: Uint256,
    /** HPKE data for the re-shielded change output (out1) */
    changeHpkeData: HpkeData,
    hpkeSuite: bytes<6>,
    viewKey: bytes,
  ) {
    // Extra budget covers the MiMC recomputation of the output commitment
    ensureBudget(4000);
    assert(
      verifierTxn.sender === this.spendVerifier.value,
      "invalid zk verifier txn",
    );
    assert(
      signalVerifierTxn.sender === this.signalVerifier.value,
      "invalid signal verifier txn",
    );

    const [in0, in1, out0, out1, spender, asset, receivers0, receivers1] =
      signalValues;

    assert(u64IsSignal(0, asset), "withdrawal only supports ALGO (asset 0)");

    const velareAddr = velareAddress({
      spendAddress: Txn.sender,
      hpkeSuite,
      viewKey,
    });

    // The caller must own the UTXOs being spent
    assert(velareAddr === spender, "spender should be the withdrawer");
    // The withdrawn output must be received by the caller
    assert(
      receivers0 === velareAddr,
      "withdrawal receiver should be the sender",
    );
    // The change output stays shielded under the caller's address
    assert(receivers1 === spender, "change receiver should be the spender");

    // Bind the revealed amount/secret to the proven output commitment:
    // commitment == MiMC(receiver, asset, amount, secret)
    const commitment = mimc(
      MimcConfigurations.BLS12_381Mp111,
      receivers0.bytes
        .concat(asset.bytes)
        .concat(new Uint256(BigUint(withdrawAmount)).bytes)
        .concat(withdrawSecret.bytes),
    );
    assert(
      BigUint(commitment) === out0.asBigUint(),
      "revealed amount and secret must open the withdrawal output commitment",
    );

    const inKey0 = utxoKey(spender, asset, in0);
    const inKey1 = utxoKey(spender, asset, in1);
    const changeKey = utxoKey(receivers1, asset, out1);

    assert(this.utxo(inKey0).exists);
    assert(this.utxo(inKey1).exists);

    // Re-shield the change output
    this.utxo(changeKey).value = clone(changeHpkeData);

    // Delete the spent inputs and refund their box MBR to the sender
    this._deleteUtxos([inKey0, inKey1]);

    // Pay out the un-shielded amount
    itxn.payment({ receiver: Txn.sender, amount: withdrawAmount }).submit();
  }

  /**
   * Un-shield ALGO WITHOUT a ZK proof. Instead of proving knowledge of the
   * UTXOs in zero-knowledge, the caller reveals the cleartext amount and
   * blinding secret of each UTXO they own. For each one we recompute the MiMC
   * commitment exactly as the deposit/spend circuits do and require the
   * corresponding UTXO box to exist in the contract. Because the commitment
   * binds (receiver, asset, amount, secret), a caller can only produce a
   * commitment that matches an existing box for UTXOs they actually own and
   * whose amount/secret they know.
   *
   * All revealed UTXOs are spent and their total amount is paid out to the
   * caller as ALGO; nothing is re-shielded. This path does not rely on ZK proofs.
   */
  withdrawAllAlgo(
    withdrawals: AlgoWithdrawal[],
    hpkeSuite: bytes<6>,
    viewKey: bytes,
  ) {
    const asset = new Uint256(0);

    const velareAddr = velareAddress({
      spendAddress: Txn.sender,
      hpkeSuite,
      viewKey,
    });

    const keysToDelete: UtxoKey[] = [];
    let total: uint64 = 0;

    for (const withdrawal of clone(withdrawals)) {
      // A MiMC recomputation per UTXO is expensive; top up the budget each time
      ensureBudget(4000);

      // Bind the revealed amount/secret to a UTXO commitment:
      // commitment == MiMC(receiver, asset, amount, secret)
      const commitment = mimc(
        MimcConfigurations.BLS12_381Mp111,
        velareAddr.bytes
          .concat(asset.bytes)
          .concat(new Uint256(BigUint(withdrawal.amount)).bytes)
          .concat(withdrawal.secret.bytes),
      );

      const key = utxoKey(velareAddr, asset, new Uint256(BigUint(commitment)));
      assert(
        this.utxo(key).exists,
        "revealed amount and secret must open an existing UTXO commitment",
      );

      keysToDelete.push(key);
      total += withdrawal.amount;
    }

    // Delete the spent UTXOs and refund their box MBR to the sender
    this._deleteUtxos(keysToDelete);

    // Pay out the total un-shielded amount
    itxn.payment({ receiver: Txn.sender, amount: total }).submit();
  }
}
