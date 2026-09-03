import fs from "fs";
import path from "path";
import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { parseCertificateChain } from "../src/chain";
import { hasAttestationExtension, parseKeyAttestation } from "../src/parsing";

const OID = "1.3.6.1.4.1.11129.2.1.17";

function asn1Integer(value: number) {
  const hex = value.toString(16).padStart(2, "0");
  return forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.INTEGER,
    false,
    forge.util.hexToBytes(hex)
  );
}

function asn1Enumerated(value: number) {
  const hex = value.toString(16).padStart(2, "0");
  return forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.ENUMERATED,
    false,
    forge.util.hexToBytes(hex)
  );
}

function asn1Octet(value: Buffer) {
  return forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.OCTETSTRING,
    false,
    forge.util.createBuffer(value.toString("binary"), "binary").getBytes()
  );
}

/**
 * A synthetic KeyDescription extension using ONLY plain UNIVERSAL-class
 * fields at the outer level -- deliberately NOT exercising the
 * AuthorizationList's high-tag-number (>=128) CONTEXT_SPECIFIC entries
 * (verifiedBootKey, osVersion, attestationApplicationId, etc.). Confirmed via
 * isolated testing that node-forge's DER encoder does not reliably round-trip
 * those (a bare `fromDer(bytes)` -> `toDer()` cycle, with no certificate or
 * signing involved at all, produces same-length but different bytes for
 * structures containing them) -- a real node-forge limitation, not something
 * fixable in this codebase. Content parsing of the full realistic structure
 * (including those tags) is covered instead by the real-device-fixture test
 * below, using bytes forge never re-serializes.
 */
function buildMinimalAttestationExtension(challengeHex: string) {
  const emptySeq = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []);
  const attestation = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      asn1Integer(4),
      asn1Enumerated(1),
      asn1Integer(4),
      asn1Enumerated(1),
      asn1Octet(Buffer.from(challengeHex, "hex")),
      asn1Octet(Buffer.alloc(0)),
      emptySeq,
      emptySeq
    ]
  );
  return forge.asn1.toDer(attestation).getBytes();
}

describe("attestation parsing", () => {
  it("parses the outer KeyDescription fields (challenge, security levels)", () => {
    const keys = forge.pki.rsa.generateKeyPair(1024);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 60 * 1000);
    const attrs = [{ name: "commonName", value: "UA Test" }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    const challengeHex = "aabbccddeeff";
    cert.setExtensions([
      {
        id: OID,
        critical: false,
        value: buildMinimalAttestationExtension(challengeHex)
      }
    ]);
    cert.sign(keys.privateKey);

    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const chain = parseCertificateChain([Buffer.from(der, "binary").toString("base64")]);
    expect(hasAttestationExtension(chain[0])).toBe(true);
    const parsed = parseKeyAttestation(chain[0]);
    expect(parsed.attestationChallengeHex).toBe(challengeHex);
    expect(parsed.attestationSecurityLevel).toBe("TEE");
    expect(parsed.keymasterSecurityLevel).toBe("TEE");
    // No AuthorizationList content in this fixture -- no app identity.
    expect(parsed.app.packageName).toBeUndefined();
  });

  it("parses a real device attestation leaf certificate", () => {
    const certBase64 = fs.readFileSync(path.join(__dirname, "fixtures", "attestation-leaf.b64"), "utf8").trim();
    const der = Buffer.from(certBase64, "base64");
    expect(hasAttestationExtension(der)).toBe(true);
    const parsed = parseKeyAttestation(der);
    expect(parsed.attestationChallengeHex).toBeTruthy();
    expect(parsed.attestationSecurityLevel).toBeTruthy();
    expect(parsed.keymasterSecurityLevel).toBeTruthy();
    // This is where the AuthorizationList / app-identity / root-of-trust
    // content actually gets exercised, against real high-tag-number
    // CONTEXT_SPECIFIC KeyMint tags -- using bytes from an actual device,
    // never round-tripped through node-forge's DER encoder.
    expect(parsed.app.packageName).toBeTruthy();
    expect(parsed.app.signerDigests.length).toBeGreaterThan(0);
    expect(parsed.deviceIntegrity.verifiedBootKey).toBeTruthy();
  });
});
