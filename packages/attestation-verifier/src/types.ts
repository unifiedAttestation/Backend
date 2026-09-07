export type ParsedAuthorizationList = {
  attestationApplicationId?: {
    packageName?: string;
    signerDigests: string[];
  };
  origin?: string;
  verifiedBootState?: string;
  deviceLocked?: boolean;
  verifiedBootKey?: string;
  verifiedBootHash?: string;
  osVersion?: number;
  osPatchLevel?: number;
  vendorPatchLevel?: number;
  bootPatchLevel?: number;
  teePatchLevel?: number;
};

export type ParsedAttestation = {
  attestationChallengeHex: string;
  attestationSecurityLevel: string;
  keymasterSecurityLevel: string;
  app: {
    packageName?: string;
    signerDigests: string[];
  };
  deviceIntegrity: ParsedAuthorizationList;
  publicKeySpkiDer: Buffer;
};

export type Verdict = {
  isTrusted: boolean;
  reasonCodes: string[];
};

export type DeviceMeta = {
  manufacturer?: string;
  brand?: string;
  model?: string;
  device?: string;
  buildFingerprint?: string;
};

export type BuildPolicyInput = {
  id?: string;
  deviceFamilyId?: string;
  buildFingerprint: string;
  verifiedBootKeyHex: string;
  verifiedBootHashHex: string | null;
  osVersionRaw: number | null;
  minOsPatchLevelRaw: number | null;
  enabled: boolean;
};

export type BuildPolicyMatch = {
  deviceFamilyId?: string;
  buildPolicyId?: string;
  buildFingerprint?: string;
};

export type DeviceRegistryCertificate = {
  rsaLeafSerialHex: string;
  rsaIntermediateSerialHex: string | null;
  ecdsaLeafSerialHex: string;
  ecdsaIntermediateSerialHex: string | null;
  authority: { name: string; rootCertificatesUrl: string };
};

export type DeviceRegistryEntry = {
  slug: string;
  manufacturer: string | null;
  brand: string | null;
  model: string | null;
  codename: string | null;
  name: string;
  enabled: boolean;
  createdAt: string;
  oemOrgName: string;
  certificate: DeviceRegistryCertificate | null;
  builds: BuildPolicyInput[];
};

export type RevocationStatus = Record<string, { status: "REVOKED"; reason: string }>;

/** A backend's own signing key, as returned by GET /api/v1/info's `publicKeys[]`
 * and by each row of GET /api/v1/federation/backends' `publicKeys`. */
export type SigningKeyInfo = {
  kid: string;
  alg: string;
  publicKey: string;
};

export type BackendInfo = {
  backendId: string;
  publicKeys: SigningKeyInfo[];
};

export type FederationBackendEntry = {
  backendId: string;
  publicKeys: SigningKeyInfo[];
  status: string;
};

/** Same string vocabulary as the backend's `errorResponse` codes in routes/device.ts
 * (plus tokenValidation.ts's codes for the token-verification path), so
 * error-handling code written against POST /device/process or POST
 * /app/decodeToken transfers directly. */
export type AttestationErrorCode =
  | "INVALID_CHAIN"
  | "INVALID_ATTESTATION"
  | "ANCHOR_MISSING"
  | "UNTRUSTED_ROOT"
  | "REVOKED_CERT"
  | "CHALLENGE_MISMATCH"
  | "APP_ID_MISMATCH"
  | "POLICY_FAIL"
  | "INVALID_TOKEN"
  | "UNKNOWN_ISSUER"
  | "TOKEN_EXPIRED"
  | "PROJECT_MISMATCH"
  | "REQUEST_HASH_MISMATCH"
  | "INVALID_SIGNATURE";

export class AttestationVerificationError extends Error {
  code: AttestationErrorCode;

  constructor(code: AttestationErrorCode, message: string) {
    super(message);
    this.name = "AttestationVerificationError";
    this.code = code;
  }
}
