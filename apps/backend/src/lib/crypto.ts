import crypto from "crypto";
import { importPKCS8, importSPKI, jwtVerify, SignJWT } from "jose";
import { SigningKey } from "./config";

function pemFromBase64(base64: string, label: "PRIVATE KEY" | "PUBLIC KEY"): string {
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export async function signIntegrityToken(payload: Record<string, unknown>, key: SigningKey): Promise<string> {
  const privateKey = pemFromBase64(key.privateKey || "", "PRIVATE KEY");
  const algorithm = resolveAlgorithm(key.alg, () =>
    deriveAlgorithmFromPrivateKey(privateKey)
  );
  const keyObject = await importPKCS8(privateKey, algorithm);
  const jwt = new SignJWT(payload);
  jwt.setProtectedHeader({
    typ: "ua.integrity+jwt",
    alg: algorithm,
    kid: key.kid
  });
  return jwt.sign(keyObject);
}

export async function verifyIntegrityToken(
  token: string,
  publicKeys: Array<{ kid: string; alg: string; publicKey: string }>
): Promise<{ payload: Record<string, unknown>; header: Record<string, unknown> }> {
  const headerSegment = token.split(".")[0];
  const header = JSON.parse(Buffer.from(headerSegment, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
  const kid = header.kid as string | undefined;
  if (!kid) {
    throw new Error("Missing kid");
  }
  const key = publicKeys.find((k) => k.kid === kid);
  if (!key) {
    throw new Error("Unknown kid");
  }
  const publicKey = pemFromBase64(key.publicKey, "PUBLIC KEY");
  const algorithm = resolveAlgorithm(key.alg, () => deriveAlgorithmFromPublicKey(publicKey));
  const keyObject = await importSPKI(publicKey, algorithm);
  const { payload } = await jwtVerify(token, keyObject, { algorithms: [algorithm] });
  return { payload: payload as Record<string, unknown>, header };
}

function normalizeAlgorithm(value?: string): "EdDSA" | "ES256" {
  const raw = (value || "").trim();
  const lower = raw.toLowerCase();
  const mapped = lower === "eddsa" || lower === "ed25519" ? "EdDSA" : lower === "es256" ? "ES256" : raw;
  if (mapped !== "EdDSA" && mapped !== "ES256") {
    throw new Error(`Unsupported signing algorithm: ${value}`);
  }
  return mapped as "EdDSA" | "ES256";
}

function resolveAlgorithm(value: string | undefined, fallback: () => "EdDSA" | "ES256"): "EdDSA" | "ES256" {
  try {
    if (value) {
      return normalizeAlgorithm(value);
    }
  } catch {
    // fall back to key inspection
  }
  return fallback();
}

function deriveAlgorithmFromPrivateKey(pem: string): "EdDSA" | "ES256" {
  const keyObject = crypto.createPrivateKey(pem);
  return deriveAlgorithmFromKeyType(keyObject.asymmetricKeyType);
}

function deriveAlgorithmFromPublicKey(pem: string): "EdDSA" | "ES256" {
  const keyObject = crypto.createPublicKey(pem);
  return deriveAlgorithmFromKeyType(keyObject.asymmetricKeyType);
}

function deriveAlgorithmFromKeyType(keyType: string | undefined): "EdDSA" | "ES256" {
  if (keyType === "ed25519" || keyType === "ed448") {
    return "EdDSA";
  }
  if (keyType === "ec") {
    return "ES256";
  }
  throw new Error(`Unsupported key type for signing: ${keyType || "unknown"}`);
}
