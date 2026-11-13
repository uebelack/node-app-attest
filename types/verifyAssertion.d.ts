export type VerifyAssertionParams = {
    /**
     * The assertion object created by DCAppAttestService.generateAssertion.
     */
    assertion: Uint8Array;
    /**
     * The client data the assertion was created for.
     */
    payload: string | Uint8Array;
    /**
     * The PEM public key returned by verifyAttestation.
     */
    publicKey: string;
    /**
     * The app's bundle identifier, e.g. org.example.AppAttestExample.
     */
    bundleIdentifier: string;
    /**
     * The Apple developer team identifier, e.g. V8H6LQ9448.
     */
    teamIdentifier: string;
    /**
     * The stored counter: 0 after the attestation, then the signCount returned by
     * the previous verifyAssertion call.
     */
    signCount: number;
};
export type VerifyAssertionResult = {
    /**
     * The new counter value. Store it for the next assertion.
     */
    signCount: number;
};
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
declare function verifyAssertion(params: VerifyAssertionParams): VerifyAssertionResult;
export default verifyAssertion;
//# sourceMappingURL=verifyAssertion.d.ts.map