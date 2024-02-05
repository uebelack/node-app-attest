import cbor from 'cbor';
import attest from '../src/attest.js';
import data from './data.json';

const ATTESTATION = Buffer.from(data.ATTESTATION, 'base64');
const CHALLENGE = Buffer.from(data.CHALLENGE, 'base64');
const {
  KEY_ID, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_INVALID, SUB_CA, SUB_CA_INVALID,
} = data;

describe('verifyAttestation', () => {
  it('should verify attestation successfully', async () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: ATTESTATION,
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).not.toThrow();
  });

  it('should verify bundleIdentifier', () => {
    expect(() => {
      attest({ teamIdentifier: 'teamIdentifier' });
    }).toThrow('bundleIdentifier is required');
  });

  it('should verify teamIdentifier', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app' });
    }).toThrow('teamIdentifier is required');
  });

  it('should verify attestation', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('attestation is required');
  });

  it('should verify challenge', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: ATTESTATION,
          keyId: KEY_ID,
        });
    }).toThrow('challenge is required');
  });

  it('should verify keyId', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: ATTESTATION,
          challenge: CHALLENGE,
        });
    }).toThrow('keyId is required');
  });

  it('should verify attestation', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: {},
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('invalid attestation');
  });

  it('should verify number of decoded attestations', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({}, {}),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('number of decoded attestations is not 1');
  });

  it('should verify decoded attestation', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({}),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('invalid attestation');
  });

  it('should verify certificates', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({
            fmt: 'apple-appattest',
            attStmt: {
              x5c: [{}, {}],
              receipt: {},
            },
            authData: {},
          }),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('invalid certificate');
  });

  it('should verify existance of sub CA certificate', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({
            fmt: 'apple-appattest',
            attStmt: {
              x5c: [CLIENT_CERTIFICATE, CLIENT_CERTIFICATE],
              receipt: {},
            },
            authData: {},
          }),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('no sub CA certificate found');
  });

  it('should verify existance of client certificate', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({
            fmt: 'apple-appattest',
            attStmt: {
              x5c: [SUB_CA, SUB_CA],
              receipt: {},
            },
            authData: {},
          }),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('no client CA certificate found');
  });

  it('should verify sub CA certificate signature', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({
            fmt: 'apple-appattest',
            attStmt: {
              x5c: [CLIENT_CERTIFICATE, SUB_CA_INVALID],
              receipt: {},
            },
            authData: {},
          }),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('sub CA certificate is not signed by Apple App Attestation Root CA');
  });

  it('should verify client certificate signature', () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: cbor.encode({
            fmt: 'apple-appattest',
            attStmt: {
              x5c: [CLIENT_CERTIFICATE_INVALID, SUB_CA],
              receipt: {},
            },
            authData: {},
          }),
          challenge: CHALLENGE,
          keyId: KEY_ID,
        });
    }).toThrow('client CA certificate is not signed by Apple App Attestation CA 1');
  });

  it('should verify challenge', async () => {
    expect(() => {
      attest({ bundleIdentifier: 'com.example.app', teamIdentifier: 'teamIdentifier' })
        .verifyAttestation({
          attestation: ATTESTATION,
          challenge: 'wrong',
          keyId: KEY_ID,
        });
    }).toThrow('nonce does not match');
  });
});
