import cbor from 'cbor';
import verifyAttestation from '../src/verifyAttestation.js';
import attestationDevelopment from './fixtures/attestation-development.json';
import attestationProduction from './fixtures/attestation-production.json';

const ATTESTATION = Buffer.from(attestationDevelopment.attestation, 'base64');
const CHALLENGE = Buffer.from(attestationDevelopment.challenge, 'base64');
const KEY_ID = attestationDevelopment.keyId;

const DECODED_ATTESTATION = cbor.Decoder.decodeAllSync(Buffer.from(attestationDevelopment.attestation, 'base64'))[0];
const CLIENT_CERTIFICATE = DECODED_ATTESTATION.attStmt.x5c[0];
const SUB_CA = DECODED_ATTESTATION.attStmt.x5c[1];

const CLIENT_CERTIFICATE_INVALID = Buffer.from(
  '-----BEGIN CERTIFICATE-----\nMIIBrjCCATSgAwIBAgIUMGdUjJHmGFXLyqbIn9ffOMZ7SJQwCgYIKoZIzj0EAwIw\nDjEMMAoGA1UEAwwDMTIzMB4XDTI0MDIwNTIxMzQwNFoXDTM0MDIwMjIxMzQwNFow\nDjEMMAoGA1UEAwwDMTIzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPcy+aBrD4yUv\nyh2fio3AZTQyIVUF4UllUcpWu8bBFHjCDN4W2TsIBrcyueFQYor2cGnFJ00gAT0u\nc2L81EMgFU6xqmKzRbnJrJB8vB9qY2UWk3FJJPP6gf2abzpsMwVjo1MwUTAdBgNV\nHQ4EFgQUqYyT9rPWmVIgODa5vTCoNNGcWHYwHwYDVR0jBBgwFoAUqYyT9rPWmVIg\nODa5vTCoNNGcWHYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNoADBlAjEA\nyT6UP8AXVS++9I3+40EHEnK1rQFj102VLPoNBPxl9uaRxCOklIyh5zQIv1l3UKjE\nAjAf6viaXK8SqjdzZbR5DcrSfISX8lQq9TD/7ZapZWI4sY0d+xnHu9jUIQLGyrd9\nFaM=\n-----END CERTIFICATE-----',
);
const SUB_CA_INVALID = Buffer.from(
  '-----BEGIN CERTIFICATE-----\nMIIB2zCCAWKgAwIBAgIUJhfzN8zcnwqeLHuNojCXC9AeyKwwCgYIKoZIzj0EAwIw\nJTEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDEwHhcNMjQwMjA1\nMjEzMjM1WhcNMzQwMjAyMjEzMjM1WjAlMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0\nZXN0YXRpb24gQ0EgMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABDWODnUr+2ZOqKpI\nOoh84eoSDG8S4c8UUwVLJz1iAr0AvmpkjY8KDFN0RNVV5ZuwNADIdidFbx4wzIpi\nwzS3POBvFyuIA6sc9kx9RRa9Bzh7ceT4oxg316VxZbhv5QaQ7qNTMFEwHQYDVR0O\nBBYEFKSU6lCnGCeDEblgUa4o6n6Xv2WUMB8GA1UdIwQYMBaAFKSU6lCnGCeDEblg\nUa4o6n6Xv2WUMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDZwAwZAIwBX04\n5z39UxHncfHQz+j3609/Hra2aDHbEBW+rWlnPQTMCb1XJP+/OKtUJkgRbBeNAjAv\nR89IsaUewdrMIV7UuUKjjcdOU+IQUaxauRUMj8nEE1yN2Co4jw+rjSFifmi/x+U=\n-----END CERTIFICATE-----',
);

const BUNDLE_IDENTIFIER = 'io.uebelacker.AppAttestExample';
const TEAM_IDENTIFIER = 'V8H6LQ9448';

describe('verifyAttestation', () => {
  it('should verify attestation successfully', async () => {
    const developmentResult = verifyAttestation({
      attestation: ATTESTATION,
      challenge: CHALLENGE,
      keyId: KEY_ID,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      allowDevelopmentEnvironment: true,
    });

    expect(developmentResult.environment).toEqual('development');
    expect(developmentResult.publicKey.indexOf('BEGIN PUBLIC KEY') > 0).toBeTruthy();
    expect(developmentResult.keyId).toEqual(attestationDevelopment.keyId);

    expect(Buffer.from(developmentResult.receipt).toString('base64')).toEqual(
      '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',
    );

    const productionResult = verifyAttestation({
      attestation: Buffer.from(attestationProduction.attestation, 'base64'),
      challenge: Buffer.from(attestationProduction.challenge, 'base64'),
      keyId: attestationProduction.keyId,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
    });

    expect(productionResult.keyId).toEqual(attestationProduction.keyId);
    expect(productionResult.publicKey.indexOf('BEGIN PUBLIC KEY') > 0).toBeTruthy();
    expect(productionResult.environment).toEqual('production');

    expect(Buffer.from(productionResult.receipt).toString('base64')).toEqual(
      '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',
    );
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
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        challenge: CHALLENGE,
        keyId: KEY_ID,
      });
    }).toThrow('attestation is required');
  });

  it('should verify challenge', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        attestation: ATTESTATION,
        keyId: KEY_ID,
      });
    }).toThrow('challenge is required');
  });

  it('should verify keyId', () => {
    expect(() => {
      verifyAttestation({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        attestation: ATTESTATION,
        challenge: CHALLENGE,
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
