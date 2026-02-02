import crypto from "crypto";
import { getPrisma } from "../lib/prisma";
import { SigningKey } from "../lib/config";

function generateUuidV7(): string {
  const bytes = crypto.randomBytes(16);
  const now = Date.now();
  bytes[0] = (now >> 40) & 0xff;
  bytes[1] = (now >> 32) & 0xff;
  bytes[2] = (now >> 24) & 0xff;
  bytes[3] = (now >> 16) & 0xff;
  bytes[4] = (now >> 8) & 0xff;
  bytes[5] = now & 0xff;
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20
  )}-${hex.slice(20)}`;
}

function generateEd25519Key(): { kid: string; publicKey: string; privateKey: string; alg: "EdDSA" } {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const publicKey = keyPair.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const privateKey = keyPair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  return {
    kid: `k${Date.now()}`,
    alg: "EdDSA",
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64")
  };
}

export async function ensureBackendSettings(): Promise<{
  backendId: string;
  signingKey: SigningKey;
}> {
  const prisma = getPrisma();
  const existing = await prisma.backendSettings.findFirst();
  if (existing) {
    return {
      backendId: existing.backendId,
      signingKey: {
        kid: existing.signingKid,
        alg: existing.signingAlg as "EdDSA" | "ES256",
        publicKey: existing.signingPublicKey,
        privateKey: existing.signingPrivateKey
      }
    };
  }
  const backendId = generateUuidV7();
  const key = generateEd25519Key();
  await prisma.backendSettings.create({
    data: {
      backendId,
      signingKid: key.kid,
      signingAlg: key.alg,
      signingPublicKey: key.publicKey,
      signingPrivateKey: key.privateKey
    }
  });
  return {
    backendId,
    signingKey: {
      kid: key.kid,
      alg: key.alg,
      publicKey: key.publicKey,
      privateKey: key.privateKey
    }
  };
}

export async function rotateBackendSigningKey(): Promise<SigningKey> {
  const prisma = getPrisma();
  const key = generateEd25519Key();
  const existing = await prisma.backendSettings.findFirst();
  if (!existing) {
    const backendId = generateUuidV7();
    await prisma.backendSettings.create({
      data: {
        backendId,
        signingKid: key.kid,
        signingAlg: key.alg,
        signingPublicKey: key.publicKey,
        signingPrivateKey: key.privateKey
      }
    });
  } else {
    await prisma.backendSettings.update({
      where: { id: existing.id },
      data: {
        signingKid: key.kid,
        signingAlg: key.alg,
        signingPublicKey: key.publicKey,
        signingPrivateKey: key.privateKey
      }
    });
  }
  return {
    kid: key.kid,
    alg: key.alg,
    publicKey: key.publicKey,
    privateKey: key.privateKey
  };
}
