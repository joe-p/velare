# Velare

Velare is a confidential transaction protocol for Algorand that aims to be as crypto-agile as possible so it can support post-quantum cryptography.

## Primitives

### Transaction Signing

Since Velare is built using smart contracts on Algorand, all transactions that interact with the protocol need to be signed by an Algorand-support signature scheme.

#### Quantum Threat

Algorand has historically used ed25519 for signing transactions, but this scheme can be broken by a quantum attacker. If users of Velare use an ed25519 account, it would be possible for a quantum attacker to front-run their transactions and spend their UTXOs.

#### Post-Quantum Readiness

Algorand supports FALCON-1024, a post-quantum signature scheme that protects users from quantum attackers. Velare users can use this scheme to ensure their funds cannot be stolen.

### HPKE (Hybrid Public Key Encryption)

The Velare protocol uses HPKE to allow the sender to transmit the encrypted amount, asset, and UTXO secret to the intended receiver on-chain.

#### Quantum Threat

If an ECC-based KEM is used for HPKE, the amounts lose forward secrecy in a post-quantum world. A quantum attacker can use the two public keys used for the key exchange (which are public information) to get the shared secret. Using this, they can decrypt the HPKE ciphertext that contains the amount, asset, and UTXO secret.

#### Post-Quantum Readiness

HPKE itself is designed for crypto agility. The Velare protocol takes advantage of this and supports any HPKE suite (provided the KEM keys fit within the various Algorand size limits). The `VelareClient` implemented in this repo derives its box minimum-balance and fee requirements from the suite's own key and ciphertext sizes rather than hardcoding them per KEM, so any HPKE suite works. X25519 and X-Wing (X25519 and ML-KEM hybrid) are exported ready to use as `X25519_HPKE_SUITE` and `XWING_HPKE_SUITE`, and **X-Wing is the default** — the classical suite has to be opted into explicitly. This means users of the protocol can be sure their transactions and balances will remain confidential, even in a post-quantum world.

Because X-Wing's keys are much larger than X25519's, choosing it costs meaningfully more box MBR: ~0.50 ALGO per UTXO and ~0.52 ALGO per Velare address, versus ~0.07 and ~0.05 for X25519. The MBR for a UTXO is refunded when it is spent.

### Zero-Knowledge Proofs

The Velare protocol uses Zero-Knowledge Proofs to keep transaction amount confidential while ensuring all transactions are valid.

#### Quantum Threat

Velare uses BLS12-381 PLONK proofs, which are based on elliptic-curve cryptography. The soundness of the verifier is degraded in a post-quantum world which means a quantum attacker can create a "fake" proof that still verifies. This would allow an attacker to spend more funds from a UTXO than what is actually available. The most dangerous part of this attack is that it is impossible to detect when this happens. The exploit would only become evident when a potentially honest user tries to withdraw funds from the protocol that are no longer in the contract.

#### Post-Quantum Readiness

While there are STARKs and some lattice-based proof systems that are PQ-secure, the proof sizes are very large compared to ECC ZK proofs (~50 KB). This means that today's PQ ZK proof systems are not practical for usage with most of today's blockchains.

One option is to allow the contract to be updated so that the contract can be updated to use a PQ ZK proof system. The problem is that it is impossible to know how the contract must be updated since we don't yet have the primitives in the AVM. This means that if the Velare contract was mutable to allow upgrading the ZK proof system, the person sending the update could also act maliciously and update to a program that steal funds.

Rather than making the Velare contract mutable, there is a global state value `zkFrozen` which is a boolean controlled by the creator via the `setZkFrozen` method. When this value is set to true, none of the methods that require ZK proofs (`deposit`, `spend`, and `withdraw`) can be called. The only method that can be called when `zkFrozen` is true is the `withdrawAll` method. This method does not use ZK proofs and instead does all the verification in the contract. This does mean that a user must expose their balance when `zkFrozen` is true, but this seems better than the alternative of losing all of their funds.

Freezing is deliberately reversible. A one-way switch would mean that a premature or mistaken freeze permanently forces every user through the balance-revealing `withdrawAll` path, so the creator can unfreeze as well.

#### Trust Assumption

`zkFrozen` is a unilateral power held by the creator, and it is worth being explicit that this cuts both ways. It exists to protect users, but the creator can also flip it at any time for any reason, at which point every user who wants to move funds must reveal their balance through `withdrawAll`. The creator can therefore force the de-anonymisation of the entire protocol at will. The creator cannot steal funds this way — `withdrawAll` only ever pays a caller their own committed UTXOs — but they can destroy confidentiality. Deploying Velare under a key that is not trusted for this decision (or not putting it behind a governance mechanism) is a real risk, not a theoretical one.

## Status

This is a prototype and has not been audited. In particular it currently depends on `@joe-p/algosdk`, a fork of `algosdk` carrying the FALCON-1024 signing support this repo needs, pinned through a `pnpm` override. That dependency needs to move back to upstream `algosdk` before any real deployment. Fee handling likewise assumes FALCON signatures everywhere and pads for them manually, which is expected to become AlgoKit's job.
