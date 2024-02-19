import cbor from 'cbor';
import { createHash, X509Certificate } from 'crypto';
import asn1js from 'asn1js';
import pkijs from 'pkijs';

// eslint-disable-next-line max-len
const APPLE_APP_ATTESTATION_ROOT_CA = new X509Certificate('-----BEGIN CERTIFICATE-----\nMIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD\n-----END CERTIFICATE-----');

const APPATTESTDEVELOP = Buffer.from('appattestdevelop').toString('hex');
const APPATTESTPROD = Buffer.concat([Buffer.from('appattest'), Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])]).toString('hex');

function verifyAttestation(params) {
  const {
    attestation,
    challenge,
    keyId,
    bundleIdentifier,
    teamIdentifier,
    allowDevelopmentEnvironment,
  } = params;

  if (!bundleIdentifier) {
    throw new Error('bundleIdentifier is required');
  }

  if (!teamIdentifier) {
    throw new Error('teamIdentifier is required');
  }

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
    decodedAttestations = cbor.decodeAllSync(attestation);
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
       || !Buffer.isBuffer(decodedAttestation.attStmt.x5c[0])
       || !Buffer.isBuffer(decodedAttestation.attStmt.x5c[1])
       || !Buffer.isBuffer(decodedAttestation.attStmt.receipt)
       || !Buffer.isBuffer(decodedAttestation.authData)
  ) {
    throw new Error('invalid attestation');
  }

  const { authData, attStmt } = decodedAttestation;

  // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
  // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
  //    starting from the credential certificate in the first data buffer in the array (credcert).
  //    Verify the validity of the certificates using Apple’s App Attest root certificate.
  let certificates;
  try {
    certificates = attStmt.x5c.map((data) => new X509Certificate(data));
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
  const clientDataHash = createHash('sha256').update(challenge).digest();

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

  // 6. Compute the SHA256 hash of your app’s App ID, and verify that it’s the same as the authenticator data’s RP ID hash.
  const appIdHash = createHash('sha256').update(`${teamIdentifier}.${bundleIdentifier}`).digest('base64');
  const rpiIdHash = authData.subarray(0, 32).toString('base64');

  if (appIdHash !== rpiIdHash) {
    throw new Error('appId does not match');
  }

  // 7. Verify that the authenticator data’s counter field equals 0.
  const signCount = authData.subarray(33, 37).readInt32BE();
  /* istanbul ignore if */
  if (signCount !== 0) {
    throw new Error('signCount is not 0');
  }

  // 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development
  //    environment, or appattest followed by seven 0x00 bytes if operating in the production environment.
  const aaguid = authData.subarray(37, 53).toString('hex');

  /* istanbul ignore if */
  if (aaguid !== APPATTESTDEVELOP && aaguid !== APPATTESTPROD) {
    throw new Error('aaguid is not valid');
  }

  if (aaguid === APPATTESTDEVELOP && !allowDevelopmentEnvironment) {
    throw new Error('development environment is not allowed');
  }

  // 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
  const credentialIdLength = authData.subarray(53, 55).readInt16BE();
  const credentialId = authData.subarray(55, 55 + credentialIdLength);

  /* istanbul ignore if */
  if (credentialId.toString('base64') !== keyId) {
    throw new Error('credentialId does not match');
  }

  return {
    keyId,
    publicKey: clientCertificate.publicKey.export({ type: 'spki', format: 'pem' }),
    receipt: decodedAttestation.attStmt.receipt,
    environment: aaguid === APPATTESTPROD ? 'production' : 'development',
  };
}

export default verifyAttestation;
