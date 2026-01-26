import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { parseCertificateChain, parseKeyAttestation } from "../src/lib/attestation";

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

function asn1Utf8(value: string) {
  return forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.UTF8,
    false,
    forge.util.encodeUtf8(value)
  );
}

function asn1Boolean(value: boolean) {
  return forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.BOOLEAN,
    false,
    value ? "\u00ff" : "\u0000"
  );
}

function contextSpecific(tag: number, child: forge.asn1.Asn1) {
  return forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, tag, true, [child]);
}

function buildAttestationExtension({
  challengeHex,
  packageName,
  signerDigestHex
}: {
  challengeHex: string;
  packageName: string;
  signerDigestHex: string;
}) {
  const packageInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    asn1Utf8(packageName),
    asn1Integer(1)
  ]);
  const packageInfos = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [packageInfo]
  );
  const signerDigests = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    [asn1Octet(Buffer.from(signerDigestHex, "hex"))]
  );
  const appId = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [packageInfos, signerDigests]
  );
  const appIdDer = forge.asn1.toDer(appId).getBytes();

  const softwareEnforced = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [contextSpecific(702, asn1Boolean(true))]
  );
  const teeEnforced = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    contextSpecific(705, asn1Enumerated(0)),
    contextSpecific(709, asn1Octet(Buffer.from(appIdDer, "binary")))
  ]);

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
      softwareEnforced,
      teeEnforced
    ]
  );
  return forge.asn1.toDer(attestation).getBytes();
}

describe("attestation parsing", () => {
  it("parses key attestation extension", () => {
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
    const signerDigestHex = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";
    cert.setExtensions([
      {
        id: OID,
        critical: false,
        value: buildAttestationExtension({
          challengeHex,
          packageName: "com.example.app",
          signerDigestHex
        })
      }
    ]);
    cert.sign(keys.privateKey);

    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const chain = parseCertificateChain([Buffer.from(der, "binary").toString("base64")]);
    const parsed = parseKeyAttestation(chain[0]);
    expect(parsed.attestationChallengeHex).toBe(challengeHex);
    expect(parsed.app.packageName).toBe("com.example.app");
    expect(parsed.app.signerDigests[0]).toBe(signerDigestHex);
  });
});
