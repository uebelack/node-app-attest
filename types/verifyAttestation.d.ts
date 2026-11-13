export type VerifyAttestationParams = {
    /**
     * The attestation object created by DCAppAttestService.attestKey.
     */
    attestation: Uint8Array;
    /**
     * The one-time challenge the server sent to the app.
     */
    challenge: string | Uint8Array;
    /**
     * The base64 key identifier created by DCAppAttestService.generateKey.
     */
    keyId: string;
    /**
     * The app's bundle identifier, e.g. org.example.AppAttestExample.
     */
    bundleIdentifier: string;
    /**
     * The Apple developer team identifier, e.g. V8H6LQ9448.
     */
    teamIdentifier: string;
    /**
     * Accept attestations from the development environment.
     * Should only be true on test environments.
     */
    allowDevelopmentEnvironment?: boolean;
};
export type VerifyAttestationResult = {
    /**
     * The verified key identifier.
     */
    keyId: string;
    /**
     * The public key of the attested key pair as PEM (SPKI). Store it to verify assertions.
     */
    publicKey: string;
    /**
     * The App Attest receipt, e.g. for fraud risk assessment.
     */
    receipt: Buffer;
    /**
     * The environment the attestation was created in.
     */
    environment: "production" | "development";
};
/**
 * @typedef {object} VerifyAttestationParams
 * @property {Uint8Array} attestation The attestation object created by DCAppAttestService.attestKey.
 * @property {string | Uint8Array} challenge The one-time challenge the server sent to the app.
 * @property {string} keyId The base64 key identifier created by DCAppAttestService.generateKey.
 * @property {string} bundleIdentifier The app's bundle identifier, e.g. org.example.AppAttestExample.
 * @property {string} teamIdentifier The Apple developer team identifier, e.g. V8H6LQ9448.
 * @property {boolean} [allowDevelopmentEnvironment] Accept attestations from the development environment.
 *   Should only be true on test environments.
 */
/**
 * @typedef {object} VerifyAttestationResult
 * @property {string} keyId The verified key identifier.
 * @property {string} publicKey The public key of the attested key pair as PEM (SPKI). Store it to verify assertions.
 * @property {Buffer} receipt The App Attest receipt, e.g. for fraud risk assessment.
 * @property {"production" | "development"} environment The environment the attestation was created in.
 */
/**
 * Verifies an App Attest attestation.
 *
 * @param {VerifyAttestationParams} params
 * @returns {VerifyAttestationResult}
 * @throws {Error} If the attestation is invalid.
 */
declare function verifyAttestation(params: VerifyAttestationParams): VerifyAttestationResult;
export default verifyAttestation;
//# sourceMappingURL=verifyAttestation.d.ts.map