import { decodeSequence } from "cbor2";
import { createHash, verify as cryptoVerify, X509Certificate } from "crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const APPLE_APP_ATTESTATION_ROOT_CA = new X509Certificate(
  "-----BEGIN CERTIFICATE-----\nMIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD\n-----END CERTIFICATE-----",
);

const APPATTESTDEVELOP = Buffer.from("appattestdevelop").toString("hex");
const APPATTESTPROD = Buffer.concat([
  Buffer.from("appattest"),
  Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
]).toString("hex");

// Signature-algorithm OID -> digest, used to verify a certificate's signature
// with the hash the certificate itself declares. Apple's App Attest chain only uses ECDSA.
/** @type {Record<string, string>} */
const SIGNATURE_ALGORITHM_DIGESTS = {
  "1.2.840.10045.4.3.2": "sha256", // ecdsa-with-SHA256
  "1.2.840.10045.4.3.3": "sha384", // ecdsa-with-SHA384
  "1.2.840.10045.4.3.4": "sha512", // ecdsa-with-SHA512
};

/**
 * Verify that `certificate` was signed by `issuerPublicKey`.
 *
 * This replaces `X509Certificate.prototype.verify()`, which is unreliable on
 * non-Node runtimes for CROSS-CURVE ECDSA chains: Apple's App Attest chain has
 * a P-256 leaf signed ecdsa-with-SHA256 by a P-384 sub-CA, and Deno's
 * node:crypto compatibility layer returns false for it (Node returns true for
 * the same bytes), apparently deriving the digest from the issuer key's curve
 * instead of from the certificate's declared signatureAlgorithm. Since every
 * App Attest chain contains that link, verification failed 100% of the time on
 * those runtimes. See https://github.com/denoland/deno/issues/36309
 *
 * Taking the digest explicitly from the certificate's own signatureAlgorithm
 * is correct on every runtime, and keeps this function synchronous.
 *
 * @param {X509Certificate} certificate
 * @param {import("crypto").KeyObject} issuerPublicKey
 * @returns {boolean}
 */
function isSignedBy(certificate, issuerPublicKey) {
  const parsed = pkijs.Certificate.fromBER(certificate.raw);
  const digest = SIGNATURE_ALGORITHM_DIGESTS[parsed.signatureAlgorithm.algorithmId];

  if (!digest) {
    return false;
  }

  return cryptoVerify(
    digest,
    Buffer.from(parsed.tbsView),
    issuerPublicKey,
    Buffer.from(parsed.signatureValue.valueBlock.valueHex),
  );
}

/**
 * @typedef {object} AuthenticatorExtensionsPolicy
 * @property {number[]} [allowedValidationCategories] Apple validation categories accepted by the server.
 * @property {string[]} [allowedBundleVersions] Bundle versions accepted by the server.
 * @property {boolean} [required] Require both supported Apple authenticator extensions.
 */

/**
 * @typedef {object} AuthenticatorExtensionsResult
 * @property {number} [validationCategory] The verified Apple validation category.
 * @property {string} [bundleVersion] The verified app bundle version.
 */

/**
 * @typedef {object} VerifyAttestationParams
 * @property {Uint8Array} attestation The attestation object created by DCAppAttestService.attestKey.
 * @property {string | Uint8Array} challenge The one-time challenge the server sent to the app.
 * @property {string} keyId The base64 key identifier created by DCAppAttestService.generateKey.
 * @property {string} bundleIdentifier The app's bundle identifier, e.g. org.example.AppAttestExample.
 * @property {string} teamIdentifier The Apple developer team identifier, e.g. V8H6LQ9448.
 * @property {boolean} [allowDevelopmentEnvironment] Accept attestations from the development environment.
 *   Should only be true on test environments.
 * @property {AuthenticatorExtensionsPolicy} [authenticatorExtensions] Validate Apple's authenticator extensions.
 *   When omitted, attestations without extensions verify as before.
 */

/**
 * @typedef {object} VerifyAttestationResult
 * @property {string} keyId The verified key identifier.
 * @property {string} publicKey The public key of the attested key pair as PEM (SPKI). Store it to verify assertions.
 * @property {Buffer} receipt The App Attest receipt, e.g. for fraud risk assessment.
 * @property {"production" | "development"} environment The environment the attestation was created in.
 * @property {number} [validationCategory] The verified apple_validation_category_01, if present.
 * @property {string} [bundleVersion] The verified apple_bundle_version_01, if present.
 */

/**
 * @param {any} policy
 */
function validateAuthenticatorExtensionsPolicy(policy) {
  const categories = policy?.allowedValidationCategories;
  const versions = policy?.allowedBundleVersions;
  const valid =
    policy !== null &&
    typeof policy === "object" &&
    !Array.isArray(policy) &&
    (policy.required === undefined || typeof policy.required === "boolean") &&
    (categories === undefined ||
      (Array.isArray(categories) &&
        categories.every(
          (/** @type {any} */ category) =>
            Number.isInteger(category) && category >= 0 && category <= 0xffffffff,
        ))) &&
    (versions === undefined ||
      (Array.isArray(versions) &&
        versions.every(
          (/** @type {unknown} */ version) => typeof version === "string" && version.length > 0,
        )));

  if (!valid) {
    throw new Error("invalid authenticator extensions policy");
  }
}

/**
 * @param {Uint8Array} authData
 * @param {AuthenticatorExtensionsPolicy} [authenticatorExtensions]
 * @returns {AuthenticatorExtensionsResult}
 */
export function parseAuthenticatorExtensions(authData, authenticatorExtensions = {}) {
  validateAuthenticatorExtensionsPolicy(authenticatorExtensions);
  if (!(authData instanceof Uint8Array) || authData.length < 55) {
    throw new Error("invalid authenticator data");
  }

  const data = Buffer.from(authData);
  const credentialIdLength = data.readUInt16BE(53);
  const credentialDataOffset = 55 + credentialIdLength;
  if (credentialDataOffset > data.length) {
    throw new Error("invalid authenticator data");
  }

  // The credential public key is followed by the extensions map, if any. Apple does not set the
  // "extension data included" flag in authData (see the sample in Apple's validation guide), so
  // the presence of a second CBOR item is what counts.
  /** @type {any[]} untrusted CBOR, its structure is validated below */
  let decodedCredentialData;
  try {
    decodedCredentialData = [...decodeSequence(data.subarray(credentialDataOffset))];
  } catch {
    throw new Error("invalid authenticator data");
  }

  if (decodedCredentialData.length < 2) {
    if (authenticatorExtensions.required) {
      throw new Error("authenticator extensions are required");
    }
    return {};
  }

  if (decodedCredentialData.length !== 2) {
    throw new Error("invalid authenticator extensions");
  }

  const extensions = decodedCredentialData[1];
  const isPlainObject =
    extensions !== null &&
    typeof extensions === "object" &&
    !Array.isArray(extensions) &&
    !(extensions instanceof Uint8Array) &&
    (Object.getPrototypeOf(extensions) === Object.prototype ||
      Object.getPrototypeOf(extensions) === null);
  if (!(extensions instanceof Map) && !isPlainObject) {
    throw new Error("invalid authenticator extensions");
  }
  const getExtension = (/** @type {string} */ name) =>
    extensions instanceof Map ? extensions.get(name) : extensions?.[name];
  const validationCategory = getExtension("apple_validation_category_01");
  const bundleVersion = getExtension("apple_bundle_version_01");
  /** @type {AuthenticatorExtensionsResult} */
  const result = {};

  if (validationCategory !== undefined) {
    if (!(validationCategory instanceof Uint8Array) || validationCategory.length !== 4) {
      throw new Error("invalid apple_validation_category_01 extension");
    }
    result.validationCategory = Buffer.from(validationCategory).readUInt32LE();
    if (
      authenticatorExtensions.allowedValidationCategories &&
      !authenticatorExtensions.allowedValidationCategories.includes(result.validationCategory)
    ) {
      throw new Error("validation category is not allowed");
    }
  }

  if (bundleVersion !== undefined) {
    if (typeof bundleVersion !== "string" || bundleVersion.length === 0) {
      throw new Error("invalid apple_bundle_version_01 extension");
    }
    result.bundleVersion = bundleVersion;
    if (
      authenticatorExtensions.allowedBundleVersions &&
      !authenticatorExtensions.allowedBundleVersions.includes(result.bundleVersion)
    ) {
      throw new Error("bundle version is not allowed");
    }
  }

  if (
    authenticatorExtensions.required &&
    (result.validationCategory === undefined || result.bundleVersion === undefined)
  ) {
    throw new Error("authenticator extensions are required");
  }

  return result;
}

/**
 * Verifies an App Attest attestation.
 *
 * @param {VerifyAttestationParams} params
 * @returns {VerifyAttestationResult}
 * @throws {Error} If the attestation is invalid.
 */
function verifyAttestation(params) {
  const {
    attestation,
    challenge,
    keyId,
    bundleIdentifier,
    teamIdentifier,
    allowDevelopmentEnvironment,
    authenticatorExtensions,
  } = params;

  if (!bundleIdentifier) {
    throw new Error("bundleIdentifier is required");
  }

  if (!teamIdentifier) {
    throw new Error("teamIdentifier is required");
  }

  if (!attestation) {
    throw new Error("attestation is required");
  }

  if (!challenge) {
    throw new Error("challenge is required");
  }

  if (!keyId) {
    throw new Error("keyId is required");
  }

  /** @type {any[]} untrusted CBOR, its structure is validated below */
  let decodedAttestations;

  try {
    decodedAttestations = [...decodeSequence(attestation)];
  } catch {
    throw new Error("invalid attestation");
  }

  if (decodedAttestations.length !== 1) {
    throw new Error("number of decoded attestations is not 1");
  }

  const decodedAttestation = decodedAttestations[0];

  if (
    decodedAttestation.fmt !== "apple-appattest" ||
    decodedAttestation.attStmt?.x5c?.length !== 2 ||
    !decodedAttestation.attStmt?.receipt ||
    !decodedAttestation.authData ||
    !(decodedAttestation.attStmt.x5c[0] instanceof Uint8Array) ||
    !(decodedAttestation.attStmt.x5c[1] instanceof Uint8Array) ||
    !(decodedAttestation.attStmt.receipt instanceof Uint8Array) ||
    !(decodedAttestation.authData instanceof Uint8Array)
  ) {
    throw new Error("invalid attestation");
  }

  const { attStmt } = decodedAttestation;
  const authData = Buffer.from(decodedAttestation.authData);
  const receipt = Buffer.from(attStmt.receipt);

  // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
  // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
  //    starting from the credential certificate in the first data buffer in the array (credcert).
  //    Verify the validity of the certificates using Apple’s App Attest root certificate.
  /** @type {X509Certificate[]} */
  let certificates;
  try {
    certificates = attStmt.x5c.map((/** @type {Uint8Array} */ data) => new X509Certificate(data));
  } catch {
    throw new Error("invalid certificate");
  }

  const subCaCertificate = certificates.find(
    (certificate) => certificate.subject.indexOf("Apple App Attestation CA 1") !== -1,
  );

  if (!subCaCertificate) {
    throw new Error("no sub CA certificate found");
  }

  if (!isSignedBy(subCaCertificate, APPLE_APP_ATTESTATION_ROOT_CA.publicKey)) {
    throw new Error("sub CA certificate is not signed by Apple App Attestation Root CA");
  }

  const clientCertificate = certificates.find(
    (certificate) => certificate.subject.indexOf("Apple App Attestation CA 1") === -1,
  );

  if (!clientCertificate) {
    throw new Error("no client CA certificate found");
  }

  if (!isSignedBy(clientCertificate, subCaCertificate.publicKey)) {
    throw new Error("client CA certificate is not signed by Apple App Attestation CA 1");
  }

  // 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your
  //    app before performing the attestation, and append that hash to the end of the authenticator
  //    data (authData from the decoded object).
  const clientDataHash = createHash("sha256").update(challenge).digest();

  const nonceData = Buffer.concat([authData, clientDataHash]);

  // 3. Generate a new SHA256 hash of the composite item to create nonce.
  const nonce = createHash("sha256").update(nonceData).digest("hex");

  // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1
  //    sequence. Decode the sequence and extract the single octet string that it contains. Verify that the
  //    string equals nonce.
  const asn1 = asn1js.fromBER(clientCertificate.raw);
  const certificate = new pkijs.Certificate({ schema: asn1.result });
  try {
    const extension = certificate.extensions?.find((e) => e.extnID === "1.2.840.113635.100.8.2");
    const actualNonce = Buffer.from(
      extension?.parsedValue.valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex,
    ).toString("hex");
    if (actualNonce !== nonce) {
      throw new Error("nonce does not match");
    }
  } catch {
    throw new Error("nonce does not match");
  }

  // 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app
  // const publicKey = await certificate.getPublicKey()
  const publicKey = Buffer.from(
    certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex,
  );
  const publicKeyHash = createHash("sha256").update(publicKey).digest("base64");
  if (publicKeyHash !== keyId) {
    throw new Error("keyId does not match");
  }

  // 6. Compute the SHA256 hash of your app’s App ID, and verify that it’s the same as the authenticator data’s RP ID hash.
  const appIdHash = createHash("sha256")
    .update(`${teamIdentifier}.${bundleIdentifier}`)
    .digest("base64");
  const rpiIdHash = authData.subarray(0, 32).toString("base64");

  if (appIdHash !== rpiIdHash) {
    throw new Error("appId does not match");
  }

  // 7. Verify that the authenticator data’s counter field equals 0.
  const signCount = authData.subarray(33, 37).readInt32BE();
  /* istanbul ignore if */
  if (signCount !== 0) {
    throw new Error("signCount is not 0");
  }

  // 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development
  //    environment, or appattest followed by seven 0x00 bytes if operating in the production environment.
  const aaguid = authData.subarray(37, 53).toString("hex");

  /* istanbul ignore if */
  if (aaguid !== APPATTESTDEVELOP && aaguid !== APPATTESTPROD) {
    throw new Error("aaguid is not valid");
  }

  if (aaguid === APPATTESTDEVELOP && !allowDevelopmentEnvironment) {
    throw new Error("development environment is not allowed");
  }

  // 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
  const credentialIdLength = authData.subarray(53, 55).readInt16BE();
  const credentialId = authData.subarray(55, 55 + credentialIdLength);

  /* istanbul ignore if */
  if (credentialId.toString("base64") !== keyId) {
    throw new Error("credentialId does not match");
  }

  const verifiedExtensions = parseAuthenticatorExtensions(authData, authenticatorExtensions);

  return {
    keyId,
    publicKey: /** @type {string} */ (
      clientCertificate.publicKey.export({
        type: "spki",
        format: "pem",
      })
    ),
    receipt,
    environment: aaguid === APPATTESTPROD ? "production" : "development",
    ...verifiedExtensions,
  };
}

export default verifyAttestation;
