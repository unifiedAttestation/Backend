export { getCertificateSerial, parseCertificateChain, verifyCertificateChain, verifyCertificateChainStrict } from "./chain";
export { hasAttestationExtension, parseKeyAttestation } from "./parsing";
export { evaluateIntegrity, matchBuildPolicy, normalizeMeta } from "./policy";
export { AttestationCache, createAttestationCache, DEFAULT_CACHE_TTL_MS } from "./cache";
export {
  fetchDeviceEntry,
  fetchRootCertificates,
  fetchRevocationStatus,
  fetchBackendInfo,
  fetchFederationBackends,
  normalizeBaseUrl
} from "./registry";
export { verifyDeviceAttestation } from "./verify";
export type { VerifyDeviceAttestationParams, VerifyDeviceAttestationResult } from "./verify";
export { verifyIntegrityTokenOffline } from "./tokenVerify";
export type { VerifyIntegrityTokenOfflineParams, TokenVerifyResult } from "./tokenVerify";
export type {
  AttestationErrorCode,
  BackendInfo,
  BuildPolicyInput,
  BuildPolicyMatch,
  DeviceMeta,
  DeviceRegistryCertificate,
  DeviceRegistryEntry,
  FederationBackendEntry,
  ParsedAttestation,
  ParsedAuthorizationList,
  RevocationStatus,
  SigningKeyInfo,
  Verdict
} from "./types";
export { AttestationVerificationError } from "./types";
