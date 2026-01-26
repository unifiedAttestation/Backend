# Unified Attestation Protocol

## Request hash
- Canonical request string is defined by the app server.
- `requestHash = SHA-256(UTF8(canonicalRequestString))`.
- No nonce protocol and no requestId/deviceId in the flow.

## Device flow
1) App calls Android-SDK to get providerSet (backendIds).
2) App sends backendIds + canonical request string to its app server.
3) App server selects backendId.
4) App calls Android-SDK `requestIntegrityToken(backendId, projectId, requestHash)`.
5) Android-Service performs KeyMint attestation with `attestationChallenge = requestHash`.
6) Android-Service POSTs cert chain to backend `/api/v1/device/process`.
7) Backend verifies chain, evaluates integrity, returns short-lived signed token.

## App server decode
- App server POSTs token to backend `/api/v1/app/decodeToken` with apiSecret and expectedRequestHash.
- Backend verifies token signature (local or federated keys), checks exp + projectId + requestHash.

## Token claims
- `iss`, `iat`, `exp`, `projectId`, `requestHash`.
- `app: { packageName, signerDigests }`.
- `deviceIntegrity` (parsed key attestation data).
- `verdict: { isTrusted, reasonCodes }`.

## Scoped device ID
- `scopedDeviceId = SHA-256(backendId || projectId || spkiDER)`.
- Used only for backend reports and never sent to apps.
