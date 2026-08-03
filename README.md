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

##### Upgradable Contract

Because the AVM does not support PQ ZK proofs, the Velare contract is upgradable. Since an update could theoretically drain user funds, there is a delay function that allows users to withdraw funds before the update can actually take place. The idea is that once PQ ZK is available on the AVM, the contract can be updated to use the new primitives without users having to explicitly move funds.

##### Freezing ZK

Ideally PQ proof systems are available in the AVM before we believe a quantum attacker is feasible. This would allow an update to be initiated without the funds in the contract ever being at risk. It is, however, possible that q-day will come before the AVM is capable of supporting PQ proof systems. Rather than letting an attacker drain the contract in this scenario, there is a `zkFrozen` flag that can be controlled by the creator. When this flag is enabled, all the methods that rely on the soundness of PLONK SNARKs will be disabled. This means users cannot deposit or spend funds. The only action available to users will be withdrawing in the clear. This clear withdrawal method will reveal the amount that is in the UTXOs being withdrawn, but the circumvention of the SNARK means this method is no susceptible to a quantum attacker.

##### Trust Assumptions

The creator has the ability to initiate updates on a time delay. It is the user's responsibility to monitor pending updates and determine whether they want to keep funds in the contract or not before the update actually takes place. A malicious update could drain all funds in the contract.

The creator also has the ability to enable `zkFrozen`. This one-way operation means that amounts and balances must be revealed to withdraw. The only way to revert this is through a contract update.

## Status

This is a prototype and has not been audited. In particular it currently depends on `@joe-p/algosdk`, a fork of `algosdk` carrying the FALCON-1024 signing support this repo needs, pinned through a `pnpm` override. That dependency needs to move back to upstream `algosdk` before any real deployment. Fee handling likewise assumes FALCON signatures everywhere and pads for them manually, which is expected to become AlgoKit's job.
