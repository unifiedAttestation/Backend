# ua-attestation-verifier

Verify Android KeyMint hardware attestation chains **entirely on your own backend**, without calling a Unified Attestation (UA) backend's `POST /api/v1/device/process` or `POST /api/v1/app/decodeToken` at all.

UA is not a separate attestation mechanism -- it's built directly on top of Android's standard hardware-backed Key Attestation. This package does the same chain verification and build-policy matching a UA backend does, using only public, unauthenticated data:

- `GET /api/v1/devices/:slug` -- build policies, and (once a trust anchor is registered) the active certificate serials + a link to the root certs
- `GET /api/v1/info/root` -- root CA certificates
- `GET /api/v1/info/status` -- revoked certificate serials

## Install

```
npm install ua-attestation-verifier
```

## Usage

```ts
import { verifyDeviceAttestation } from "ua-attestation-verifier";

const result = await verifyDeviceAttestation({
  attestationChain,              // base64 DER chain, as returned by Android-SDK
  requestHash,                   // same value your app bound into the attestation challenge
  registryBaseUrl: "https://uattest.volla.tech", // a UA backend's root URL (no /api/v1 suffix)
  deviceSlug: "volla-ansuz",     // the device family's public registry slug
  projectId: "com.example.app",  // optional: also checks the attestation's app identity
});

if (result.verdict.isTrusted) {
  // proceed
} else {
  // result.verdict.reasonCodes explains why not
}
```

Errors are thrown as `AttestationVerificationError` with a `code` matching the same vocabulary the UA backend's `/device/process` uses (`INVALID_CHAIN`, `ANCHOR_MISSING`, `UNTRUSTED_ROOT`, `REVOKED_CERT`, `CHALLENGE_MISMATCH`, `APP_ID_MISMATCH`, `POLICY_FAIL`), so error handling written against that endpoint transfers directly.

### Offline token verification (`verifyIntegrityTokenOffline`)

`verifyDeviceAttestation` above skips `/device/process` (verify the raw attestation chain yourself). This function skips the *other* live call -- `/app/decodeToken` -- letting you verify a UA-**issued token** yourself instead of asking a UA backend to check it for you every time:

```ts
import { verifyIntegrityTokenOffline } from "ua-attestation-verifier";

const result = await verifyIntegrityTokenOffline({
  token,                          // the UA token, as returned by /device/process (or forwarded by an app)
  registryBaseUrl: "https://uattest.volla.tech",
  projectId: "com.example.app",   // optional
  expectedRequestHash,             // optional
  signerDigestSha256,               // optional -- checks the app's real signing cert, not just its package name
});
```

How it resolves trust: it reads the token's (unverified) `iss` and `kid`, fetches `GET /api/v1/info` (cached) for the issuing backend's own public keys, and -- if the token was minted by some *other* backend federated with that one -- also fetches `GET /api/v1/federation/backends` (cached) to find that backend's row. Both endpoints are already public today; no new UA backend changes were needed to support this. It then verifies the signature and `exp`/`projectId`/`requestHash`/`signerDigestSha256` locally, exactly mirroring what `/app/decodeToken` and its internal `tokenValidation.ts` already check, and returns the same `{verdict, requestHash, claims}` shape `/app/decodeToken` returns -- so this is a drop-in offline substitute for that call.

**Trust model, to be explicit:** this doesn't remove trust in UA -- you're still trusting whichever backend's signing key you fetched, same as calling `/app/decodeToken` live does. What changes is *when* that trust is exercised: once per cache TTL (fetching a public key) instead of once per token (a live call). The device's own one-time call to mint the token in the first place still needs some UA backend to be reachable -- this only removes the App Server's dependency on backend uptime at verification time, not the device's dependency at mint time.

### Lower-level primitives

For advanced use (custom caching, offline batch verification, etc.), the individual building blocks are also exported: `parseKeyAttestation`, `verifyCertificateChainStrict`, `matchBuildPolicy`, `evaluateIntegrity`, `fetchDeviceEntry`, `fetchRootCertificates`, `fetchRevocationStatus`, `fetchBackendInfo`, `fetchFederationBackends`, `createAttestationCache`.

## Caching and revocation freshness

`verifyDeviceAttestation` caches its registry/root/status HTTP fetches in memory, with a default TTL of 5 minutes. Pass a shared `cache` instance (from `createAttestationCache()`) across calls in a hot request path instead of relying on the default (which creates a fresh, cold cache per call unless you pass one). Pass `cacheTtlMs` to tune the default cache's TTL.

**Security consideration**: on a fetch failure, the cache serves its last-known value (with a `console.warn`) rather than hard-failing, so a transient registry hiccup doesn't turn into a verification outage. This means revocation freshness is bounded by your TTL, not by real-time state. If you're verifying a high-value transaction, use a shorter TTL (or your own `fetchRevocationStatus` call with `cache: undefined`-equivalent logic) than the default.

## What's intentionally different from the internal backend

- The public registry only lists *enabled* build policies, so this package can't distinguish "no builds registered for this device" from "all builds are disabled" -- both look like an empty build list.
- `verifyDeviceAttestation`'s result has no `iss` claim (no JWT is involved in that particular flow -- it verifies a raw attestation chain, not a UA-issued token).
- Cross-authority revocation (an upstream CA like Google separately revoking a serial) is not covered -- only revocations tracked by the backend you're pointed at (`/info/status`) are checked.
- `verifyIntegrityTokenOffline` has no equivalent of the backend's `DeviceReport` upsert -- it's a pure, stateless check with no side effects, by design.
