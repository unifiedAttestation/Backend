import { importSPKI, jwtVerify } from "jose";
import { AttestationCache, createAttestationCache } from "./cache";
import { fetchBackendInfo, fetchFederationBackends, normalizeBaseUrl } from "./registry";
import { AttestationVerificationError, type ParsedAttestation, type SigningKeyInfo, type Verdict } from "./types";

export type VerifyIntegrityTokenOfflineParams = {
  /** A UA-issued token, as returned by POST /device/process or forwarded by an app. */
  token: string;
  /** Backend root URL, e.g. "https://uattest.volla.tech" (no "/api/v1" suffix). */
  registryBaseUrl: string;
  projectId?: string;
  expectedRequestHash?: string;
  signerDigestSha256?: string;
  /** Pass a shared instance across calls for a hot request path; otherwise a fresh one is created from cacheTtlMs. */
  cache?: AttestationCache;
  /** Ignored if `cache` is passed. Default 5 minutes. */
  cacheTtlMs?: number;
};

export type TokenVerifyResult = {
  verdict: Verdict;
  requestHash: string;
  claims: {
    iss: string;
    projectId: string;
    requestHash: string;
    app: { packageName?: string; signerDigests: string[] };
    deviceIntegrity: ParsedAttestation["deviceIntegrity"];
  };
};

function pemFromBase64(base64: string): string {
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
}

function decodeJwtSegment(token: string, index: number): Record<string, unknown> {
  const segment = token.split(".")[index];
  if (!segment) {
    throw new AttestationVerificationError("INVALID_TOKEN", "Malformed token");
  }
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new AttestationVerificationError("INVALID_TOKEN", "Malformed token");
  }
}

/**
 * Verifies a UA-issued token (from POST /device/process) entirely offline --
 * the "classic-style" counterpart to calling POST /app/decodeToken live.
 * Fetches the issuing backend's public key (self or federated, both already
 * public endpoints) once per cache TTL, then checks the signature and claims
 * locally. See README.md for the trust model this implies.
 */
export async function verifyIntegrityTokenOffline(
  params: VerifyIntegrityTokenOfflineParams
): Promise<TokenVerifyResult> {
  const cache = params.cache ?? createAttestationCache(params.cacheTtlMs);
  const baseUrl = normalizeBaseUrl(params.registryBaseUrl);

  const header = decodeJwtSegment(params.token, 0);
  const unverifiedPayload = decodeJwtSegment(params.token, 1);
  const iss = unverifiedPayload.iss as string | undefined;
  const kid = header.kid as string | undefined;
  const alg = header.alg as string | undefined;
  if (!iss || !kid || !alg) {
    throw new AttestationVerificationError("INVALID_TOKEN", "Token is missing iss/kid/alg");
  }

  let signingKeys: SigningKeyInfo[];
  const info = await fetchBackendInfo(baseUrl, cache);
  if (info.backendId === iss) {
    signingKeys = info.publicKeys;
  } else {
    const federated = await fetchFederationBackends(baseUrl, cache);
    const match = federated.find((b) => b.backendId === iss && b.status === "active");
    if (!match) {
      throw new AttestationVerificationError("UNKNOWN_ISSUER", `Unknown or untrusted backend: ${iss}`);
    }
    signingKeys = match.publicKeys;
  }

  const keyEntry = signingKeys.find((k) => k.kid === kid);
  if (!keyEntry) {
    throw new AttestationVerificationError("UNKNOWN_ISSUER", `Unknown signing key kid: ${kid}`);
  }

  let payload: Record<string, unknown>;
  try {
    const keyObject = await importSPKI(pemFromBase64(keyEntry.publicKey), keyEntry.alg);
    const result = await jwtVerify(params.token, keyObject, { algorithms: [keyEntry.alg] });
    payload = result.payload as Record<string, unknown>;
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") {
      throw new AttestationVerificationError("TOKEN_EXPIRED", "Token expired");
    }
    throw new AttestationVerificationError("INVALID_SIGNATURE", "Token signature verification failed");
  }

  if (params.projectId && payload.projectId !== params.projectId) {
    throw new AttestationVerificationError("PROJECT_MISMATCH", "Token projectId mismatch");
  }
  if (params.expectedRequestHash && payload.requestHash !== params.expectedRequestHash) {
    throw new AttestationVerificationError("REQUEST_HASH_MISMATCH", "requestHash mismatch");
  }
  const app = payload.app as { packageName?: string; signerDigests: string[] };
  if (params.signerDigestSha256) {
    const signerDigests = (app.signerDigests || []).map((d) => d.toLowerCase());
    if (!signerDigests.includes(params.signerDigestSha256.toLowerCase())) {
      throw new AttestationVerificationError("APP_ID_MISMATCH", "Signer mismatch");
    }
  }

  return {
    verdict: payload.verdict as Verdict,
    requestHash: payload.requestHash as string,
    claims: {
      iss: payload.iss as string,
      projectId: payload.projectId as string,
      requestHash: payload.requestHash as string,
      app,
      deviceIntegrity: payload.deviceIntegrity as ParsedAttestation["deviceIntegrity"]
    }
  };
}
