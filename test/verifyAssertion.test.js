import { encode } from "cbor2";
import verifyAssertion from "../src/verifyAssertion.js";

const ASSERTION = Buffer.from(
  "omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB",
  "base64",
);
const PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL\n8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==\n-----END PUBLIC KEY-----\n";
const BUNDLE_IDENTIFIER = "io.uebelacker.AppAttestExample";
const TEAM_IDENTIFIER = "V8H6LQ9448";

describe("verifyAssertion", () => {
  it("should verify assertion successfully", () => {
    const result = verifyAssertion({
      assertion: ASSERTION,
      payload:
        '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
      publicKey: PUBLIC_KEY,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      signCount: 0,
    });

    expect(result).toEqual({ signCount: 1 });
  });

  it("should accept the assertion as a Uint8Array", () => {
    const result = verifyAssertion({
      assertion: new Uint8Array(ASSERTION),
      payload:
        '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
      publicKey: PUBLIC_KEY,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      signCount: 0,
    });

    expect(result).toEqual({ signCount: 1 });
  });

  it("should verify bundleIdentifier", () => {
    expect(() => {
      verifyAssertion({ teamIdentifier: TEAM_IDENTIFIER });
    }).toThrow("bundleIdentifier is required");
  });

  it("should verify teamIdentifier", () => {
    expect(() => {
      verifyAssertion({ bundleIdentifier: BUNDLE_IDENTIFIER });
    }).toThrow("teamIdentifier is required");
  });

  it("should verify assertion", () => {
    expect(() => {
      verifyAssertion({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("assertion is required");
  });

  it("should verify payload", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("payload is required");
  });

  it("should verify publicKey", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("publicKey is required");
  });

  it.each([undefined, null, "0", -1, 0.5, Number.NaN])(
    "should require signCount (%s)",
    (signCount) => {
      expect(() => {
        verifyAssertion({
          assertion: ASSERTION,
          payload:
            '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
          publicKey: PUBLIC_KEY,
          bundleIdentifier: BUNDLE_IDENTIFIER,
          teamIdentifier: TEAM_IDENTIFIER,
          signCount,
        });
      }).toThrow("signCount is required");
    },
  );

  it("should throw invalid assertion", () => {
    expect(() => {
      verifyAssertion({
        assertion: Buffer.from("invalid-assertion"),
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',

        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 0,
      });
    }).toThrow("invalid assertion");
  });

  it.each([
    ["not a map", encode("assertion")],
    ["missing signature", encode({ authenticatorData: new Uint8Array(37) })],
    ["missing authenticatorData", encode({ signature: new Uint8Array(70) })],
    ["trailing data", Buffer.concat([ASSERTION, encode(0)])],
  ])("should throw invalid assertion (%s)", (_, assertion) => {
    expect(() => {
      verifyAssertion({
        assertion,
        payload: "{}",
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 0,
      });
    }).toThrow("invalid assertion");
  });

  it("should throw invalid signature", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload: "{}",
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 0,
      });
    }).toThrow("invalid signature");
  });

  it("should throw invalid appId", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        publicKey: PUBLIC_KEY,
        teamIdentifier: TEAM_IDENTIFIER,
        bundleIdentifier: "INVALID",
        signCount: 0,
      });
    }).toThrow("appId does not match");
  });

  it("should throw invalid signCount", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 1,
      });
    }).toThrow("invalid signCount");
  });
});
