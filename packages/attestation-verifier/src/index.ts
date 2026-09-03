export { getCertificateSerial, parseCertificateChain, verifyCertificateChain, verifyCertificateChainStrict } from "./chain";
export { hasAttestationExtension, parseKeyAttestation } from "./parsing";
export { evaluateIntegrity, matchBuildPolicy, normalizeMeta } from "./policy";
export { AttestationCache, createAttestationCache, DEFAULT_CACHE_TTL_MS } from "./cache";
export { fetchDeviceEntry, fetchRootCertificates, fetchRevocationStatus, normalizeBaseUrl } from "./registry";
export { verifyDeviceAttestation } from "./verify";
export type { VerifyDeviceAttestationParams, VerifyDeviceAttestationResult } from "./verify";
export type {
  AttestationErrorCode,
  BuildPolicyInput,
  BuildPolicyMatch,
  DeviceMeta,
  DeviceRegistryCertificate,
  DeviceRegistryEntry,
  ParsedAttestation,
  ParsedAuthorizationList,
  RevocationStatus,
  Verdict
} from "./types";
export { AttestationVerificationError } from "./types";
