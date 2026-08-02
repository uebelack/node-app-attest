/**
 * @param {Buffer} authData
 * @param {AuthenticatorExtensionsPolicy} [authenticatorExtensions]
 * @returns {AuthenticatorExtensionsResult}
 */
export function parseAuthenticatorExtensions(
  authData: Buffer,
  authenticatorExtensions?: AuthenticatorExtensionsPolicy,
): AuthenticatorExtensionsResult;
export default verifyAttestation;
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
export type VerifyAttestationParams = Record<string, any> & {
  authenticatorExtensions?: AuthenticatorExtensionsPolicy;
};
export type VerifyAttestationResult = {
  keyId: any;
  publicKey: any;
  receipt: any;
  environment: string;
  validationCategory?: number;
  bundleVersion?: string;
};
/**
 * @param {VerifyAttestationParams} params
 * @returns {VerifyAttestationResult}
 */
declare function verifyAttestation(
  params: VerifyAttestationParams,
): VerifyAttestationResult;
//# sourceMappingURL=verifyAttestation.d.ts.map
