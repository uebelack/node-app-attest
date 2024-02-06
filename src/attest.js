import cbor from 'cbor';
import { createHash, X509Certificate } from 'crypto';
import asn1js from 'asn1js';
import pkijs from 'pkijs';

// eslint-disable-next-line max-len
const APPLE_APP_ATTESTATION_ROOT_CA = new X509Certificate('-----BEGIN CERTIFICATE-----\nMIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD\n-----END CERTIFICATE-----');

function attest(attestParams) {
  const { bundleIdentifier, teamIdentifier } = attestParams;
  if (!bundleIdentifier) {
    throw new Error('bundleIdentifier is required');
  }

  if (!teamIdentifier) {
    throw new Error('teamIdentifier is required');
  }

  return {
    verifyAttestation: (verifyAttestationParams) => {
      const { attestation, challenge, keyId } = verifyAttestationParams;

      if (!attestation) {
        throw new Error('attestation is required');
      }

      if (!challenge) {
        throw new Error('challenge is required');
      }

      if (!keyId) {
        throw new Error('keyId is required');
      }

      let decodedAttestations;

      try {
        decodedAttestations = cbor.decodeAllSync(Buffer.from(attestation, 'base64'));
      } catch (e) {
        throw new Error('invalid attestation');
      }

      if (decodedAttestations.length !== 1) {
        throw new Error('number of decoded attestations is not 1');
      }

      const decodedAttestation = decodedAttestations[0];

      if (decodedAttestation.fmt !== 'apple-appattest'
       || decodedAttestation.attStmt?.x5c?.length !== 2
       || !decodedAttestation.attStmt?.receipt
       || !decodedAttestation.authData
      ) {
        throw new Error('invalid attestation');
      }

      // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
      // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
      //    starting from the credential certificate in the first data buffer in the array (credcert).
      //    Verify the validity of the certificates using Apple’s App Attest root certificate.
      let certificates;
      try {
        certificates = decodedAttestation.attStmt.x5c.map((data) => new X509Certificate(data));
      } catch (e) {
        throw new Error('invalid certificate');
      }

      const subCaCertificate = certificates.find((certificate) => certificate.subject.indexOf('Apple App Attestation CA 1') !== -1);

      if (!subCaCertificate) {
        throw new Error('no sub CA certificate found');
      }

      if (!subCaCertificate.verify(APPLE_APP_ATTESTATION_ROOT_CA.publicKey)) {
        throw new Error('sub CA certificate is not signed by Apple App Attestation Root CA');
      }

      const clientCertificate = certificates.find((certificate) => certificate.subject.indexOf('Apple App Attestation CA 1') === -1);

      if (!clientCertificate) {
        throw new Error('no client CA certificate found');
      }

      if (!clientCertificate.verify(subCaCertificate.publicKey)) {
        throw new Error('client CA certificate is not signed by Apple App Attestation CA 1');
      }

      // 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your
      //    app before performing the attestation, and append that hash to the end of the authenticator
      //    data (authData from the decoded object).
      const clientDataHash = createHash('sha256').update(Buffer.from(challenge, 'base64')).digest();

      const nonceData = Buffer.concat([decodedAttestation.authData, clientDataHash]);

      // 3. Generate a new SHA256 hash of the composite item to create nonce.
      const nonce = createHash('sha256').update(nonceData).digest('hex');

      // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1
      //    sequence. Decode the sequence and extract the single octet string that it contains. Verify that the
      //    string equals nonce.
      const asn1 = asn1js.fromBER(clientCertificate.raw);
      const certificate = new pkijs.Certificate({ schema: asn1.result });
      const extension = certificate.extensions.find((e) => e.extnID === '1.2.840.113635.100.8.2');
      try {
        const actualNonce = Buffer.from(extension.parsedValue.valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex).toString('hex');
        if (actualNonce !== nonce) {
          throw new Error('nonce does not match');
        }
      } catch {
        throw new Error('nonce does not match');
      }

      // 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app
      // const publicKey = await certificate.getPublicKey()
      const publicKey = Buffer.from(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
      const publicKeyHash = createHash('sha256').update(publicKey, 'hex').digest('base64');
      if (publicKeyHash !== keyId) {
        throw new Error('keyId does not match');
      }
    },
  };
}

export default attest;
