import cbor from 'cbor';
import verifyAttestation from '../src/verifyAttestation.js';
import attestationDevelopment from './fixtures/attestation-development.json';
import attestationProduction from './fixtures/attestation-production.json';

const ATTESTATION = attestationDevelopment.attestation;
const CHALLENGE = attestationDevelopment.challenge;
const KEY_ID = attestationDevelopment.keyId;

const DECODED_ATTESTATION = cbor.Decoder.decodeAllSync(Buffer.from(attestationDevelopment.attestation, 'base64'))[0];
const CLIENT_CERTIFICATE = DECODED_ATTESTATION.attStmt.x5c[0];
const SUB_CA = DECODED_ATTESTATION.attStmt.x5c[1];

// eslint-disable-next-line max-len
const CLIENT_CERTIFICATE_INVALID = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIBrjCCATSgAwIBAgIUMGdUjJHmGFXLyqbIn9ffOMZ7SJQwCgYIKoZIzj0EAwIw\nDjEMMAoGA1UEAwwDMTIzMB4XDTI0MDIwNTIxMzQwNFoXDTM0MDIwMjIxMzQwNFow\nDjEMMAoGA1UEAwwDMTIzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPcy+aBrD4yUv\nyh2fio3AZTQyIVUF4UllUcpWu8bBFHjCDN4W2TsIBrcyueFQYor2cGnFJ00gAT0u\nc2L81EMgFU6xqmKzRbnJrJB8vB9qY2UWk3FJJPP6gf2abzpsMwVjo1MwUTAdBgNV\nHQ4EFgQUqYyT9rPWmVIgODa5vTCoNNGcWHYwHwYDVR0jBBgwFoAUqYyT9rPWmVIg\nODa5vTCoNNGcWHYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNoADBlAjEA\nyT6UP8AXVS++9I3+40EHEnK1rQFj102VLPoNBPxl9uaRxCOklIyh5zQIv1l3UKjE\nAjAf6viaXK8SqjdzZbR5DcrSfISX8lQq9TD/7ZapZWI4sY0d+xnHu9jUIQLGyrd9\nFaM=\n-----END CERTIFICATE-----');
// eslint-disable-next-line max-len
const SUB_CA_INVALID = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB2zCCAWKgAwIBAgIUJhfzN8zcnwqeLHuNojCXC9AeyKwwCgYIKoZIzj0EAwIw\nJTEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDEwHhcNMjQwMjA1\nMjEzMjM1WhcNMzQwMjAyMjEzMjM1WjAlMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0\nZXN0YXRpb24gQ0EgMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABDWODnUr+2ZOqKpI\nOoh84eoSDG8S4c8UUwVLJz1iAr0AvmpkjY8KDFN0RNVV5ZuwNADIdidFbx4wzIpi\nwzS3POBvFyuIA6sc9kx9RRa9Bzh7ceT4oxg316VxZbhv5QaQ7qNTMFEwHQYDVR0O\nBBYEFKSU6lCnGCeDEblgUa4o6n6Xv2WUMB8GA1UdIwQYMBaAFKSU6lCnGCeDEblg\nUa4o6n6Xv2WUMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDZwAwZAIwBX04\n5z39UxHncfHQz+j3609/Hra2aDHbEBW+rWlnPQTMCb1XJP+/OKtUJkgRbBeNAjAv\nR89IsaUewdrMIV7UuUKjjcdOU+IQUaxauRUMj8nEE1yN2Co4jw+rjSFifmi/x+U=\n-----END CERTIFICATE-----');

const BUNDLE_IDENTIFIER = 'io.uebelacker.AppAttestExample';
const TEAM_IDENTIFIER = 'V8H6LQ9448';

describe('verifyAttestation', () => {
  it('should verify attestation successfully', async () => {
    const developmentResult = verifyAttestation({
      ...attestationDevelopment, bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER, allowDevelopmentEnvironment: true,
    });

    expect(developmentResult.environment).toEqual('development');
    expect(developmentResult.clientCertificate).not.toBeNull();
    expect(developmentResult.keyId).toEqual(attestationDevelopment.keyId);

    const productionResult = verifyAttestation({
      ...attestationProduction, bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER,
    });

    expect(productionResult.keyId).toEqual(attestationProduction.keyId);
    expect(productionResult.clientCertificate).not.toBeNull();
    expect(productionResult.environment).toEqual('production');
  });

  it('should verify bundleIdentifier', () => {
    expect(() => {
      verifyAttestation({ teamIdentifier: TEAM_IDENTIFIER });
    }).toThrow('bundleIdentifier is required');
  });

  it('should verify teamIdentifier', () => {
    expect(() => {
      verifyAttestation({ bundleIdentifier: BUNDLE_IDENTIFIER });
    }).toThrow('teamIdentifier is required');
  });

  it('should verify attestation', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER, challenge: CHALLENGE, keyId: KEY_ID,
      });
    }).toThrow('attestation is required');
  });

  it('should verify challenge', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER, attestation: ATTESTATION, keyId: KEY_ID,
      });
    }).toThrow('challenge is required');
  });

  it('should verify keyId', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER, attestation: ATTESTATION, challenge: CHALLENGE,
      });
    }).toThrow('keyId is required');
  });

  it('should verify attestation', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: {},
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('invalid attestation');
  });

  it('should verify number of decoded attestations', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({}, {}),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('number of decoded attestations is not 1');
  });

  it('should verify decoded attestation', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({}),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('invalid attestation');
  });

  it('should verify certificates', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({
          fmt: 'apple-appattest',
          attStmt: {
            x5c: [Buffer.from('test'), Buffer.from('test')],
            receipt: Buffer.from('test'),
          },
          authData: Buffer.from('test'),
        }),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('invalid certificate');
  });

  it('should verify existance of sub CA certificate', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({
          fmt: 'apple-appattest',
          attStmt: {
            x5c: [CLIENT_CERTIFICATE, CLIENT_CERTIFICATE],
            receipt: Buffer.from('test'),
          },
          authData: Buffer.from('test'),
        }),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('no sub CA certificate found');
  });

  it('should verify existance of client certificate', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({
          fmt: 'apple-appattest',
          attStmt: {
            x5c: [SUB_CA, SUB_CA],
            receipt: Buffer.from('test'),
          },
          authData: Buffer.from('test'),
        }),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('no client CA certificate found');
  });

  it('should verify sub CA certificate signature', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({
          fmt: 'apple-appattest',
          attStmt: {
            x5c: [CLIENT_CERTIFICATE, SUB_CA_INVALID],
            receipt: Buffer.from('test'),
          },
          authData: Buffer.from('test'),
        }),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('sub CA certificate is not signed by Apple App Attestation Root CA');
  });

  it('should verify client certificate signature', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: cbor.encode({
          fmt: 'apple-appattest',
          attStmt: {
            x5c: [CLIENT_CERTIFICATE_INVALID, SUB_CA],
            receipt: Buffer.from('test'),
          },
          authData: Buffer.from('test'),
        }),
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('client CA certificate is not signed by Apple App Attestation CA 1');
  });

  it('should verify challenge', async () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: ATTESTATION,
        challenge: 'wrong',
        keyId: KEY_ID,
      });
    }).toThrow('nonce does not match');
  });

  it('should verify keyId', async () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        allowDevelopmentEnvironment: true,
        attestation: ATTESTATION,
        challenge: CHALLENGE,
        keyId: 'wrong',
      });
    }).toThrow('keyId does not match');
  });

  it('should verify appId', async () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: 'invalid',
        teamIdentifier: TEAM_IDENTIFIER,
        attestation: ATTESTATION,
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('appId does not match');
  });

  it('should verify environment', async () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        attestation: ATTESTATION,
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('development environment is not allowed');
  });
});
