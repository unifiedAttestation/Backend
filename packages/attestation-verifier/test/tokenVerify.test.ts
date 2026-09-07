import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, generateKeyPair, exportSPKI } from "jose";
import { createAttestationCache } from "../src/cache";
import { verifyIntegrityTokenOffline } from "../src/tokenVerify";

const BASE_URL = "https://ua.example.test";
const SELF_BACKEND_ID = "backend-self-0001";
const OTHER_BACKEND_ID = "backend-federated-0002";
const PROJECT_ID = "com.example.app";
const REQUEST_HASH = "aabbccdd";
const SIGNER_DIGEST = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";

async function toBase64Spki(publicKey: CryptoKey): Promise<string> {
  const pem = await exportSPKI(publicKey);
  return pem.replace(/-----BEGIN PUBLIC KEY-----/, "").replace(/-----END PUBLIC KEY-----/, "").replace(/\s+/g, "");
}

type BuildTokenOpts = {
  iss?: string;
  kid?: string;
  privateKey: CryptoKey;
  exp?: number;
  projectId?: string;
  requestHash?: string;
  signerDigests?: string[];
};

async function buildToken(opts: BuildTokenOpts): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: opts.iss ?? SELF_BACKEND_ID,
    iat: now,
    exp: opts.exp ?? now + 60,
    projectId: opts.projectId ?? PROJECT_ID,
    requestHash: opts.requestHash ?? REQUEST_HASH,
    app: { packageName: PROJECT_ID, signerDigests: opts.signerDigests ?? [SIGNER_DIGEST] },
    deviceIntegrity: { verifiedBootState: "VERIFIED", verifiedBootKey: "aa11", osPatchLevel: 202410 },
    verdict: { isTrusted: true, reasonCodes: [] }
  };
  return new SignJWT(payload)
    .setProtectedHeader({ typ: "ua.integrity+jwt", alg: "ES256", kid: opts.kid ?? "k1" })
    .sign(opts.privateKey);
}

function mockFetch(handlers: {
  info?: { backendId: string; publicKeys: Array<{ kid: string; alg: string; publicKey: string }> };
  federation?: Array<{ backendId: string; publicKeys: Array<{ kid: string; alg: string; publicKey: string }>; status: string }>;
}) {
  const fn = vi.fn(async (input: string | URL) => {
    const url = String(input);
    if (url === `${BASE_URL}/api/v1/info`) {
      return new Response(JSON.stringify(handlers.info ?? {}), { status: 200 });
    }
    if (url === `${BASE_URL}/api/v1/federation/backends`) {
      return new Response(JSON.stringify(handlers.federation ?? []), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fn);
  return { fn };
}

describe("verifyIntegrityTokenOffline", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies a self-issued token (happy path)", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] } });

    const token = await buildToken({ privateKey });
    const result = await verifyIntegrityTokenOffline({
      token,
      registryBaseUrl: BASE_URL,
      projectId: PROJECT_ID,
      expectedRequestHash: REQUEST_HASH,
      signerDigestSha256: SIGNER_DIGEST
    });

    expect(result.verdict.isTrusted).toBe(true);
    expect(result.claims.iss).toBe(SELF_BACKEND_ID);
    expect(result.requestHash).toBe(REQUEST_HASH);
  });

  it("verifies a federated-issued token (iss is not the backend it was fetched from)", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    mockFetch({
      info: { backendId: SELF_BACKEND_ID, publicKeys: [] },
      federation: [{ backendId: OTHER_BACKEND_ID, status: "active", publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] }]
    });

    const token = await buildToken({ iss: OTHER_BACKEND_ID, privateKey });
    const result = await verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL });

    expect(result.claims.iss).toBe(OTHER_BACKEND_ID);
    expect(result.verdict.isTrusted).toBe(true);
  });

  it("rejects an expired token", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] } });

    const token = await buildToken({ privateKey, exp: Math.floor(Date.now() / 1000) - 60 });
    await expect(verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL })).rejects.toMatchObject({
      code: "TOKEN_EXPIRED"
    });
  });

  it("rejects a token whose signature doesn't match the fetched key", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    const { publicKey: wrongPublicKey } = await generateKeyPair("ES256");
    const wrongPublicKeyBase64 = await toBase64Spki(wrongPublicKey);
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: wrongPublicKeyBase64 }] } });

    const token = await buildToken({ privateKey });
    await expect(verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL })).rejects.toMatchObject({
      code: "INVALID_SIGNATURE"
    });
  });

  it("rejects a projectId mismatch", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] } });

    const token = await buildToken({ privateKey });
    await expect(
      verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL, projectId: "com.other.app" })
    ).rejects.toMatchObject({ code: "PROJECT_MISMATCH" });
  });

  it("rejects a requestHash mismatch", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] } });

    const token = await buildToken({ privateKey });
    await expect(
      verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL, expectedRequestHash: "deadbeef" })
    ).rejects.toMatchObject({ code: "REQUEST_HASH_MISMATCH" });
  });

  it("rejects a signerDigestSha256 mismatch", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] } });

    const token = await buildToken({ privateKey });
    await expect(
      verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL, signerDigestSha256: "ff".repeat(32) })
    ).rejects.toMatchObject({ code: "APP_ID_MISMATCH" });
  });

  it("rejects an unknown/untrusted issuer", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [] }, federation: [] });

    const token = await buildToken({ iss: "some-random-backend", privateKey });
    await expect(verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL })).rejects.toMatchObject({
      code: "UNKNOWN_ISSUER"
    });
  });

  it("rejects a malformed token string", async () => {
    mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [] } });
    await expect(verifyIntegrityTokenOffline({ token: "not-a-jwt", registryBaseUrl: BASE_URL })).rejects.toMatchObject({
      code: "INVALID_TOKEN"
    });
  });

  it("reuses a shared cache instead of refetching /api/v1/info on a second call", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicKeyBase64 = await toBase64Spki(publicKey);
    const { fn } = mockFetch({ info: { backendId: SELF_BACKEND_ID, publicKeys: [{ kid: "k1", alg: "ES256", publicKey: publicKeyBase64 }] } });
    const cache = createAttestationCache();

    const token = await buildToken({ privateKey });
    await verifyIntegrityTokenOffline({ token, registryBaseUrl: BASE_URL, cache });
    const callCountAfterFirst = fn.mock.calls.length;

    const secondToken = await buildToken({ privateKey, requestHash: "eeff0011" });
    await verifyIntegrityTokenOffline({ token: secondToken, registryBaseUrl: BASE_URL, cache });

    expect(fn.mock.calls).toHaveLength(callCountAfterFirst);
  });
});
