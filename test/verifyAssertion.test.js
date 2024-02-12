// attestation result: {
//   "keyId": "Hd4oXPcGoPNNey/nljS6O+CdmZr3e45hklxO3EZR1sg=",
//   "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL\n8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==\n-----END PUBLIC KEY-----\n",
//   "environment": "development"
// }
// 2024-02-11T16:55:15.317Z DEBUG    assertion: omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB
// 2024-02-11T16:55:15.317Z DEBUG    hash: POWXJx3BO/8ORI1dUnbOz69f1PruPwBxhBa9iyc+lMI=
// 2024-02-11T16:55:15.317Z DEBUG    body: {"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}
// 2024-02-11T16:55:15.317Z DEBUG    send-message: {"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}

import verifyAssertion from '../src/verifyAssertion.js';

// eslint-disable-next-line max-len
const ASSERTION = Buffer.from('omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB', 'base64');
// eslint-disable-next-line max-len
const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL\n8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==\n-----END PUBLIC KEY-----\n';
const BUNDLE_IDENTIFIER = 'io.uebelacker.AppAttestExample';
const TEAM_IDENTIFIER = 'V8H6LQ9448';

describe('verifyAssertion', () => {
  it('should verify assertion successfully', async () => {
    verifyAssertion({
      assertion: ASSERTION,
      payload: '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
      publicKey: PUBLIC_KEY,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
    });
  });

  it('should verify bundleIdentifier', () => {
    expect(() => {
      verifyAssertion({ teamIdentifier: TEAM_IDENTIFIER });
    }).toThrow('bundleIdentifier is required');
  });

  it('should verify teamIdentifier', () => {
    expect(() => {
      verifyAssertion({ bundleIdentifier: BUNDLE_IDENTIFIER });
    }).toThrow('teamIdentifier is required');
  });

  it('should verify assertion', () => {
    expect(() => {
      verifyAssertion({ bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER });
    }).toThrow('assertion is required');
  });

  it('should verify payload', () => {
    expect(() => {
      verifyAssertion({ assertion: ASSERTION, bundleIdentifier: BUNDLE_IDENTIFIER, teamIdentifier: TEAM_IDENTIFIER });
    }).toThrow('payload is required');
  });

  it('should verify publicKey', () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload: '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow('publicKey is required');
  });

  it('should throw invalid assertion', () => {
    expect(() => {
      verifyAssertion({
        assertion: Buffer.from('invalid-assertion'),
        payload: '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        // eslint-disable-next-line max-len
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow('invalid assertion');
  });

  it('should throw invalid signature', () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload: '{}',
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow('invalid signature');
  });

  it('should throw invalid appId', () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload: '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        publicKey: PUBLIC_KEY,
        teamIdentifier: TEAM_IDENTIFIER,
        bundleIdentifier: 'INVALID',
      });
    }).toThrow('appId does not match');
  });

  it('should throw invalid signCount', () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload: '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 10,
      });
    }).toThrow('invalid signCount');
  });
});
