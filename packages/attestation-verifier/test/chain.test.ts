import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { getCertificateSerial, parseCertificateChain, verifyCertificateChain, verifyCertificateChainStrict } from "../src/chain";

const OID = "1.3.6.1.4.1.11129.2.1.17";

function derToBase64(cert: forge.pki.Certificate): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return Buffer.from(der, "binary").toString("base64");
}

function toPem(cert: forge.pki.Certificate): string {
  return forge.pki.certificateToPem(cert);
}

function makeRoot(): { cert: forge.pki.Certificate; keys: forge.pki.KeyPair } {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: "UA Test Root" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, keys };
}

function makeLeaf(
  root: { cert: forge.pki.Certificate; keys: forge.pki.KeyPair },
  opts: { hasExtension?: boolean; wrongIssuerName?: boolean } = {}
): forge.pki.Certificate {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "02";
  cert.validity.notBefore = new Date(Date.now() - 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  cert.setSubject([{ name: "commonName", value: "UA Test Leaf" }]);
  cert.setIssuer(
    opts.wrongIssuerName
      ? [{ name: "commonName", value: "Someone Else" }]
      : root.cert.subject.attributes
  );
  if (opts.hasExtension !== false) {
    cert.setExtensions([
      {
        id: OID,
        critical: false,
        // minimal well-formed-enough DER isn't needed here -- hasAttestationExtension
        // only checks the extension is present and extractable, not its inner shape.
        value: forge.asn1
          .toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []))
          .getBytes()
      }
    ]);
  }
  cert.sign(root.keys.privateKey, forge.md.sha256.create());
  return cert;
}

describe("chain verification", () => {
  it("verifies a valid 2-cert chain (loose)", () => {
    const root = makeRoot();
    const leaf = makeLeaf(root);
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(root.cert)]);
    expect(() => verifyCertificateChain(chain, [toPem(root.cert)])).not.toThrow();
  });

  it("verifies a valid 2-cert chain (strict)", () => {
    const root = makeRoot();
    const leaf = makeLeaf(root);
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(root.cert)]);
    expect(() => verifyCertificateChainStrict(chain, [toPem(root.cert)])).not.toThrow();
  });

  it("rejects when leaf has no attestation extension", () => {
    const root = makeRoot();
    const leaf = makeLeaf(root, { hasExtension: false });
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(root.cert)]);
    expect(() => verifyCertificateChainStrict(chain, [toPem(root.cert)])).toThrow(
      "Missing attestation extension on leaf"
    );
  });

  it("rejects when a non-leaf certificate also carries the attestation extension", () => {
    const root = makeRoot();
    const leaf = makeLeaf(root);
    // Reuse makeLeaf to fabricate a "root" that itself carries the extension.
    const fakeRootWithExtension = makeLeaf(root);
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(fakeRootWithExtension)]);
    expect(() => verifyCertificateChainStrict(chain, [toPem(root.cert)])).toThrow(
      "Attestation extension present in non-leaf certificate"
    );
  });

  it("rejects on issuer/subject name-chaining mismatch", () => {
    const root = makeRoot();
    const leaf = makeLeaf(root, { wrongIssuerName: true });
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(root.cert)]);
    expect(() => verifyCertificateChainStrict(chain, [toPem(root.cert)])).toThrow(
      "Certificate name chaining failed"
    );
  });

  it("rejects an untrusted root", () => {
    const root = makeRoot();
    const otherRoot = makeRoot();
    const leaf = makeLeaf(root);
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(root.cert)]);
    expect(() => verifyCertificateChainStrict(chain, [toPem(otherRoot.cert)])).toThrow(
      "Untrusted certificate chain"
    );
  });

  // KNOWN PRE-EXISTING BUG, preserved as-is (not fixed here -- fixing it would
  // change the live /device/process validation behavior, which is out of
  // scope for this extraction and deserves its own deliberate, reviewed fix):
  // `validationDate < cert.validFrom || validationDate > cert.validTo` compares
  // a real `Date` against `X509Certificate.validFrom`/`validTo`, which are
  // STRINGS ("Jan 1 00:00:00 2020 GMT"), not Dates. JS's relational-comparison
  // coercion (`Number(dateFormatString)`) always yields NaN, so both
  // comparisons are always false -- expiry/not-yet-valid is never actually
  // enforced. Confirmed present in the original apps/backend/src/lib/attestation.ts
  // before this extraction (verified via `node -e` against real X509Certificate
  // validFrom/validTo string values), not something this refactor introduced.
  it("does NOT currently reject an expired intermediate/root (known bug, see comment above)", () => {
    const root = makeRoot();
    root.cert.validity.notAfter = new Date(Date.now() - 1000);
    root.cert.sign(root.keys.privateKey, forge.md.sha256.create());
    const leaf = makeLeaf(root);
    const chain = parseCertificateChain([derToBase64(leaf), derToBase64(root.cert)]);
    expect(() => verifyCertificateChainStrict(chain, [toPem(root.cert)])).not.toThrow();
  });

  it("extracts an uppercase certificate serial", () => {
    const root = makeRoot();
    const chain = parseCertificateChain([derToBase64(root.cert)]);
    expect(getCertificateSerial(chain[0])).toBe("01");
  });
});
