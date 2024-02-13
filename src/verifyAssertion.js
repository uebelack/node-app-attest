import cbor from 'cbor';
import { createHash, createVerify } from 'crypto';

function verifyAssertion(params) {
  const {
    assertion,
    payload,
    publicKey,
    bundleIdentifier,
    teamIdentifier,
    signCount,
  } = params;

  if (!bundleIdentifier) {
    throw new Error('bundleIdentifier is required');
  }

  if (!teamIdentifier) {
    throw new Error('teamIdentifier is required');
  }

  if (!assertion) {
    throw new Error('assertion is required');
  }

  if (!payload) {
    throw new Error('payload is required');
  }

  if (!publicKey) {
    throw new Error('publicKey is required');
  }

  let decodedAssertion;

  try {
    // eslint-disable-next-line prefer-destructuring
    decodedAssertion = cbor.decodeAllSync(assertion)[0];
  } catch (e) {
    throw new Error('invalid assertion');
  }

  const { signature, authenticatorData } = decodedAssertion;

  // 1. Compute clientDataHash as the SHA256 hash of clientData.
  const clientDataHash = createHash('sha256').update(payload).digest();

  // 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
  const nonce = createHash('sha256').update(Buffer.concat([authenticatorData, clientDataHash])).digest();

  // 3. Use the public key that you store from the attestation object to verify that the assertion’s signature is valid for nonce.
  const verifier = createVerify('SHA256');
  verifier.update(nonce);
  if (!verifier.verify(publicKey, signature)) {
    throw new Error('invalid signature');
  }

  // 4. Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
  const appIdHash = createHash('sha256').update(`${teamIdentifier}.${bundleIdentifier}`).digest('base64');
  const rpiIdHash = authenticatorData.subarray(0, 32).toString('base64');

  if (appIdHash !== rpiIdHash) {
    throw new Error('appId does not match');
  }

  // 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
  const nextSignCount = authenticatorData.subarray(33, 37).readInt32BE();
  if (nextSignCount <= signCount) {
    throw new Error('invalid signCount');
  }

  // 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
  // This step is not covered and needs to be done in the application using this library.

  return { signCount: nextSignCount };
}

export default verifyAssertion;
