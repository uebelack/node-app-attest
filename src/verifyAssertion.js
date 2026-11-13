import { decode } from "cbor2";
import { createHash, createVerify } from "crypto";

/**
 * @typedef {object} VerifyAssertionParams
 * @property {Uint8Array} assertion The assertion object created by DCAppAttestService.generateAssertion.
 * @property {string | Uint8Array} payload The client data the assertion was created for.
 * @property {string} publicKey The PEM public key returned by verifyAttestation.
 * @property {string} bundleIdentifier The app's bundle identifier, e.g. org.example.AppAttestExample.
 * @property {string} teamIdentifier The Apple developer team identifier, e.g. V8H6LQ9448.
 * @property {number} signCount The stored counter: 0 after the attestation, then the signCount returned by
 *   the previous verifyAssertion call.
 */

/**
 * @typedef {object} VerifyAssertionResult
 * @property {number} signCount The new counter value. Store it for the next assertion.
 */

/**
 * Verifies an App Attest assertion.
 *
 * @param {VerifyAssertionParams} params
 * @returns {VerifyAssertionResult}
 * @throws {Error} If the assertion is invalid.
 */
function verifyAssertion(params) {
  const { assertion, payload, publicKey, bundleIdentifier, teamIdentifier, signCount } = params;

  if (!bundleIdentifier) {
    throw new Error("bundleIdentifier is required");
  }

  if (!teamIdentifier) {
    throw new Error("teamIdentifier is required");
  }

  if (!assertion) {
    throw new Error("assertion is required");
  }

  if (!payload) {
    throw new Error("payload is required");
  }

  if (!publicKey) {
    throw new Error("publicKey is required");
  }

  if (!Number.isInteger(signCount) || signCount < 0) {
    throw new Error("signCount is required");
  }

  /** @type {any} untrusted CBOR, its structure is validated below */
  let decodedAssertion;

  try {
    decodedAssertion = decode(assertion);
  } catch {
    throw new Error("invalid assertion");
  }

  if (
    !(decodedAssertion?.signature instanceof Uint8Array) ||
    !(decodedAssertion.authenticatorData instanceof Uint8Array)
  ) {
    throw new Error("invalid assertion");
  }

  const { signature } = decodedAssertion;
  const authenticatorData = Buffer.from(decodedAssertion.authenticatorData);

  // 1. Compute clientDataHash as the SHA256 hash of clientData.
  const clientDataHash = createHash("sha256").update(payload).digest();

  // 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
  const nonce = createHash("sha256")
    .update(Buffer.concat([authenticatorData, clientDataHash]))
    .digest();

  // 3. Use the public key that you store from the attestation object to verify that the assertion’s signature is valid for nonce.
  const verifier = createVerify("SHA256");
  verifier.update(nonce);
  if (!verifier.verify(publicKey, signature)) {
    throw new Error("invalid signature");
  }

  // 4. Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
  const appIdHash = createHash("sha256")
    .update(`${teamIdentifier}.${bundleIdentifier}`)
    .digest("base64");
  const rpiIdHash = authenticatorData.subarray(0, 32).toString("base64");

  if (appIdHash !== rpiIdHash) {
    throw new Error("appId does not match");
  }

  // 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
  const nextSignCount = authenticatorData.subarray(33, 37).readInt32BE();
  if (nextSignCount <= signCount) {
    throw new Error("invalid signCount");
  }

  // 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
  // This step is not covered and needs to be done in the application using this library.

  return { signCount: nextSignCount };
}

export default verifyAssertion;
