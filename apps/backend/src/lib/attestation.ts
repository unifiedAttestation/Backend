import forge from "node-forge";

const ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

type ParsedAuthorizationList = {
  attestationApplicationId?: {
    packageName?: string;
    signerDigests: string[];
  };
  verifiedBootState?: string;
  deviceLocked?: boolean;
  verifiedBootKey?: string;
  verifiedBootHash?: string;
  osVersionRaw?: number;
  osPatchLevelRaw?: number;
  vendorPatchLevelRaw?: number;
  bootPatchLevelRaw?: number;
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

function bytesToHex(value: string): string {
  return Buffer.from(value, "binary").toString("hex");
}

function asn1Integer(node: forge.asn1.Asn1): number {
  const hex = bytesToHex(node.value as string);
  return parseInt(hex || "0", 16);
}

function asn1Enumerated(node: forge.asn1.Asn1): number {
  return asn1Integer(node);
}

function asn1OctetString(node: forge.asn1.Asn1): Buffer {
  return Buffer.from(node.value as string, "binary");
}

function asn1Boolean(node: forge.asn1.Asn1): boolean {
  const bytes = Buffer.from(node.value as string, "binary");
  return bytes.length > 0 && bytes[0] !== 0x00;
}

function parseAttestationApplicationId(value: Buffer): ParsedAuthorizationList["attestationApplicationId"] {
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(value.toString("binary"), "binary"));
  const sequence = asn1.value as forge.asn1.Asn1[];
  const packageInfos = sequence[0]?.value as forge.asn1.Asn1[] | undefined;
  const signatureDigests = sequence[1]?.value as forge.asn1.Asn1[] | undefined;
  let packageName: string | undefined;
  if (packageInfos && packageInfos.length > 0) {
    const packageInfo = packageInfos[0]?.value as forge.asn1.Asn1[] | undefined;
    if (packageInfo && packageInfo.length > 0) {
      const pkg = packageInfo[0];
      if (pkg?.value) {
        packageName = forge.util.decodeUtf8(pkg.value as string);
      }
    }
  }
  const signerDigests =
    signatureDigests?.map((digest) => bytesToHex(digest.value as string)) || [];
  return { packageName, signerDigests };
}

function parseAuthorizationList(listNode: forge.asn1.Asn1): ParsedAuthorizationList {
  const result: ParsedAuthorizationList = {};
  const entries = (listNode.value as forge.asn1.Asn1[]) || [];
  for (const entry of entries) {
    if (entry.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC) {
      continue;
    }
    const tag = entry.type;
    const valueNode = (entry.value as forge.asn1.Asn1[])[0] || entry;
    switch (tag) {
      case 702:
        result.deviceLocked = asn1Boolean(valueNode);
        break;
      case 704:
        result.verifiedBootKey = asn1OctetString(valueNode).toString("hex");
        break;
      case 705:
        result.verifiedBootState = asn1Enumerated(valueNode) === 0 ? "VERIFIED" : "UNVERIFIED";
        break;
      case 706:
        result.verifiedBootHash = asn1OctetString(valueNode).toString("hex");
        break;
      case 7060:
        result.osPatchLevelRaw = asn1Integer(valueNode);
        result.osPatchLevel = result.osPatchLevelRaw;
        break;
      case 7061:
        result.vendorPatchLevelRaw = asn1Integer(valueNode);
        result.vendorPatchLevel = result.vendorPatchLevelRaw;
        break;
      case 7062:
        result.bootPatchLevelRaw = asn1Integer(valueNode);
        result.bootPatchLevel = result.bootPatchLevelRaw;
        break;
      case 7063:
        result.teePatchLevel = asn1Integer(valueNode);
        break;
      case 7050:
        result.osVersionRaw = asn1Integer(valueNode);
        break;
      case 709:
        result.attestationApplicationId = parseAttestationApplicationId(asn1OctetString(valueNode));
        break;
      default:
        break;
    }
  }
  return result;
}

function parseSecurityLevel(node: forge.asn1.Asn1): string {
  const value = asn1Enumerated(node);
  switch (value) {
    case 0:
      return "SOFTWARE";
    case 1:
      return "TEE";
    case 2:
      return "STRONGBOX";
    default:
      return "UNKNOWN";
  }
}

export function parseKeyAttestation(certificate: forge.pki.Certificate): ParsedAttestation {
  const extension = certificate.getExtension(ANDROID_KEY_ATTESTATION_OID);
  if (!extension || !extension.value) {
    throw new Error("Missing Android key attestation extension");
  }
  const extBytes = Buffer.from(extension.value as string, "binary");
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(extBytes.toString("binary"), "binary"));
  const seq = asn1.value as forge.asn1.Asn1[];
  if (!seq || seq.length < 8) {
    throw new Error("Invalid attestation extension format");
  }
  const attestationSecurityLevel = parseSecurityLevel(seq[1]);
  const keymasterSecurityLevel = parseSecurityLevel(seq[3]);
  const challenge = asn1OctetString(seq[4]).toString("hex");
  const softwareEnforced = parseAuthorizationList(seq[6]);
  const teeEnforced = parseAuthorizationList(seq[7]);
  const app =
    teeEnforced.attestationApplicationId ||
    softwareEnforced.attestationApplicationId || { signerDigests: [] };
  const publicKeyAsn1 = forge.pki.publicKeyToAsn1(certificate.publicKey);
  const publicKeyDer = forge.asn1.toDer(publicKeyAsn1).getBytes();
  return {
    attestationChallengeHex: challenge,
    attestationSecurityLevel,
    keymasterSecurityLevel,
    app: {
      packageName: app.packageName,
      signerDigests: app.signerDigests || []
    },
    deviceIntegrity: {
      ...softwareEnforced,
      ...teeEnforced
    },
    publicKeySpkiDer: Buffer.from(publicKeyDer, "binary")
  };
}

export function parseCertificateChain(chain: string[]): forge.pki.Certificate[] {
  return chain.map((der) => {
    const buffer = Buffer.from(der, "base64");
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(buffer.toString("binary"), "binary"));
    return forge.pki.certificateFromAsn1(asn1);
  });
}

export function parseCertificatePem(pem: string): forge.pki.Certificate {
  return forge.pki.certificateFromPem(pem);
}

export function verifyCertificateChain(
  chain: forge.pki.Certificate[],
  trustAnchors: forge.pki.Certificate[]
): void {
  const caStore = forge.pki.createCaStore(trustAnchors);
  forge.pki.verifyCertificateChain(caStore, chain);
}
