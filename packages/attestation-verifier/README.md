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

### Lower-level primitives

For advanced use (custom caching, offline batch verification, etc.), the individual building blocks are also exported: `parseKeyAttestation`, `verifyCertificateChainStrict`, `matchBuildPolicy`, `evaluateIntegrity`, `fetchDeviceEntry`, `fetchRootCertificates`, `fetchRevocationStatus`, `createAttestationCache`.

## Caching and revocation freshness

`verifyDeviceAttestation` caches its registry/root/status HTTP fetches in memory, with a default TTL of 5 minutes. Pass a shared `cache` instance (from `createAttestationCache()`) across calls in a hot request path instead of relying on the default (which creates a fresh, cold cache per call unless you pass one). Pass `cacheTtlMs` to tune the default cache's TTL.

**Security consideration**: on a fetch failure, the cache serves its last-known value (with a `console.warn`) rather than hard-failing, so a transient registry hiccup doesn't turn into a verification outage. This means revocation freshness is bounded by your TTL, not by real-time state. If you're verifying a high-value transaction, use a shorter TTL (or your own `fetchRevocationStatus` call with `cache: undefined`-equivalent logic) than the default.

## What's intentionally different from the internal backend

- The public registry only lists *enabled* build policies, so this package can't distinguish "no builds registered for this device" from "all builds are disabled" -- both look like an empty build list.
- `verifyDeviceAttestation`'s result has no `iss` claim (no JWT is involved in this local-verification flow).
- Cross-authority revocation (an upstream CA like Google separately revoking a serial) is not covered -- only revocations tracked by the backend you're pointed at (`/info/status`) are checked.
