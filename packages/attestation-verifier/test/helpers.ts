import forge from "node-forge";

const OID = "1.3.6.1.4.1.11129.2.1.17";

export function derToBase64(cert: forge.pki.Certificate): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return Buffer.from(der, "binary").toString("base64");
}

export function toPem(cert: forge.pki.Certificate): string {
  return forge.pki.certificateToPem(cert);
}

export function makeRoot(commonName = "UA Test Root"): { cert: forge.pki.Certificate; keys: forge.pki.KeyPair } {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, keys };
}

/**
 * Builds a leaf certificate signed by `root`, carrying a minimal (content-free)
 * attestation extension -- just enough for hasAttestationExtension()/
 * verifyCertificateChainStrict() to see it as a real attestation leaf.
 *
 * Deliberately NOT a full KeyMint-shaped extension: node-forge has a real bug
 * (confirmed independently, not something in this codebase) with high-tag-number
 * (>=128, needing multi-byte identifier encoding) CONTEXT_SPECIFIC constructed
 * nodes -- exactly the tag range KeyMint's real tags (702, 705, 709, ...) fall
 * into -- where the certificate's signed bytes and its re-serialized bytes
 * diverge, so Node's independent `X509Certificate.verify()` fails even though
 * nothing is actually wrong with the certificate's content. Tests that need
 * realistic KeyMint content (parsing.test.ts) never sign+verify a certificate,
 * only parse raw DER; tests that need both a real signature AND realistic
 * parsed content (verify.integration.test.ts) sign this minimal leaf and mock
 * parseKeyAttestation's return value instead.
 */
export function makeLeafWithAttestationExtension(
  root: { cert: forge.pki.Certificate; keys: forge.pki.KeyPair },
  serial = "02"
): forge.pki.Certificate {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date(Date.now() - 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  cert.setSubject([{ name: "commonName", value: "UA Test Leaf" }]);
  cert.setIssuer(root.cert.subject.attributes);
  cert.setExtensions([
    {
      id: OID,
      critical: false,
      value: forge.asn1.toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [])).getBytes()
    }
  ]);
  cert.sign(root.keys.privateKey, forge.md.sha256.create());
  return cert;
}
