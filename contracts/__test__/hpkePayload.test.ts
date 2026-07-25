import { describe, it, expect } from "vitest";
import {
  HPKE_PAYLOAD_LENGTH,
  packHpkePayload,
  unpackHpkePayload,
  X25519_HPKE_SUITE,
  XWING_HPKE_SUITE,
} from "../src";
import { CipherSuite, KemId } from "hpke-js";

function getKemName(suite: CipherSuite) {
  const id = suite.kem.id;
  if (id === KemId.DhkemX25519HkdfSha256) return "X25519";
  if (id === KemId.XWing) return "X-Wing";
  return "unknown";
}

describe("HPKE payload", () => {
  it("packs asset, amount and secret into a 48-byte payload", () => {
    const secret = new Uint8Array(32).fill(7);
    const payload = packHpkePayload(123n, 456n, secret);

    expect(payload.length).toBe(HPKE_PAYLOAD_LENGTH);

    const unpacked = unpackHpkePayload(payload);
    expect(unpacked.asset).toBe(123n);
    expect(unpacked.amount).toBe(456n);
    expect(unpacked.secret).toEqual(secret);
  });

  it("round-trips u64 boundary values", () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const max = (1n << 64n) - 1n;
    const unpacked = unpackHpkePayload(packHpkePayload(max, max, secret));
    expect(unpacked.asset).toBe(max);
    expect(unpacked.amount).toBe(max);
    expect(unpacked.secret).toEqual(secret);
  });

  it("rejects a non-32-byte secret", () => {
    expect(() => packHpkePayload(0n, 0n, new Uint8Array(16))).toThrow();
  });

  it("rejects a wrong-length payload", () => {
    expect(() => unpackHpkePayload(new Uint8Array(40))).toThrow();
  });

  [X25519_HPKE_SUITE, XWING_HPKE_SUITE].forEach((suite) => {
    it(`receiver recovers asset, amount and secret over HPKE (${getKemName(suite)})`, async () => {
      const { publicKey, privateKey } = await suite.kem.generateKeyPair();
      const viewPublic = new Uint8Array(
        await suite.kem.serializePublicKey(publicKey),
      );

      const asset = 0n;
      const amount = 5n;
      const secret = crypto.getRandomValues(new Uint8Array(32));

      // Sender side: exactly what composeDepositGroup does.
      const { enc, ct } = await suite.seal(
        {
          recipientPublicKey: await suite.kem.deserializePublicKey(viewPublic),
        },
        packHpkePayload(asset, amount, secret),
      );

      // Receiver side: decrypt with the view private key and read the note.
      const plaintext = new Uint8Array(
        await suite.open({ recipientKey: privateKey, enc }, ct),
      );
      const note = unpackHpkePayload(plaintext);

      expect(note.asset).toBe(asset);
      expect(note.amount).toBe(amount);
      expect(note.secret).toEqual(secret);
    });
  });
});
