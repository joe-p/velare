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
  uint64,
  assert,
  Global,
  Uint64,
  log,
} from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";

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

export type BalanceKey = {
  asset: uint64;
  addr: Account;
};

export class Velare extends Contract {
  depositVerifier = GlobalState<Account>({ key: "d" });

  transferVerifier = GlobalState<Account>({ key: "t" });

  balances = BoxMap<BalanceKey, Uint256>({ keyPrefix: "b" });

  // TODO: Add a uint64 index to the key so we don't have a cap
  pendingTransfers = BoxMap<BalanceKey, Uint256[]>({ keyPrefix: "p" });

  createApplication(depositVerifier: Account, transferVerifier: Account) {
    this.depositVerifier.value = depositVerifier;
    this.transferVerifier.value = transferVerifier;
  }

  initializeAlgoBalance(
    signals: Uint256[],
    _proof: PlonkProof,
    verifierTxn: gtxn.Transaction,
    depositTxn: gtxn.PaymentTxn,
  ) {
    const balanceKey = { addr: Txn.sender, asset: Uint64(0) };

    assert(!this.balances(balanceKey).exists, "balance already exists");
    assert(
      verifierTxn.sender === this.depositVerifier.value,
      "invalid verification txn",
    );

    const [commitment, addr, asset, amount] = signals;

    assert(asset.asBigUint() === BigUint(0), "asset must be ALGO");

    const preMbr = Global.currentApplicationAddress.minBalance;
    this.balances(balanceKey).value = commitment;
    const balanceMbr: uint64 =
      Global.currentApplicationAddress.minBalance - preMbr;

    assert(
      BigUint(Txn.sender.bytes) % BLS12_381_SCALAR_MODULUS === addr.asBigUint(),
      "address does not match sender",
    );

    assert(
      amount.asBigUint() === BigUint(depositTxn.amount - balanceMbr),
      "commitment amount does not match deposit amount (minus min balance)",
    );

    assert(
      depositTxn.receiver === Global.currentApplicationAddress,
      "deposit must go to app address",
    );
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

    const receiverKey = { addr: receiver, asset: asset.asUint64() };
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

    if (!this.pendingTransfers(receiverKey).exists) {
      this.pendingTransfers(receiverKey).create({ size: 2_000 });
    }
    this.pendingTransfers(receiverKey).value.push(xferCommitment);
  }
}
