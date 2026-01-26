import crypto from "crypto";
import { describe, expect, it } from "vitest";
import { signIntegrityToken, verifyIntegrityToken } from "../src/lib/crypto";

describe("integrity token signing", () => {
  it("signs and verifies payload", () => {
    const keyPair = crypto.generateKeyPairSync("ed25519");
    const signingKey = {
      kid: "k1",
      alg: "EdDSA" as const,
      privateKey: (keyPair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString(
        "base64"
      ),
      publicKey: (keyPair.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString(
        "base64"
      )
    };
    const payload = { iss: "backend", projectId: "com.example.app", requestHash: "abcd" };
    const token = signIntegrityToken(payload, signingKey);
    const verified = verifyIntegrityToken(token, [signingKey]);
    expect(verified.payload.iss).toBe("backend");
    expect(verified.payload.projectId).toBe("com.example.app");
    expect(verified.payload.requestHash).toBe("abcd");
  });
});
