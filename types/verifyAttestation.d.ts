export type AuthenticatorExtensionsPolicy = {
    /**
     * Apple validation categories accepted by the server.
     */
    allowedValidationCategories?: number[];
    /**
     * Bundle versions accepted by the server.
     */
    allowedBundleVersions?: string[];
    /**
     * Require both supported Apple authenticator extensions.
     */
    required?: boolean;
};
export type AuthenticatorExtensionsResult = {
    /**
     * The verified Apple validation category.
     */
    validationCategory?: number;
    /**
     * The verified app bundle version.
     */
    bundleVersion?: string;
};
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
    /**
     * Validate Apple's authenticator extensions.
     * When omitted, attestations without extensions verify as before.
     */
    authenticatorExtensions?: AuthenticatorExtensionsPolicy;
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
    /**
     * The verified apple_validation_category_01, if present.
     */
    validationCategory?: number;
    /**
     * The verified apple_bundle_version_01, if present.
     */
    bundleVersion?: string;
};
/**
 * @param {Uint8Array} authData
 * @param {AuthenticatorExtensionsPolicy} [authenticatorExtensions]
 * @returns {AuthenticatorExtensionsResult}
 */
export declare function parseAuthenticatorExtensions(authData: Uint8Array, authenticatorExtensions?: AuthenticatorExtensionsPolicy): AuthenticatorExtensionsResult;
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