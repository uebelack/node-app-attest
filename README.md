<div id="top"></div>

[![Build][build-shield]][build-url]
[![Coverage][coverage-shield]][coverage-url]
[![Language][language-shield]][build-url]
[![MIT License][license-shield]][license-url]

<br />
<div align="center">
  <h1 align="center">node-app-attest</h1>
  <p align="center">
    JavaScript implementation of the App Attest protocol for node.js
  </p>
</div>

## About

The App Attest service, offers a method for confirming that connections to your server originate from authentic instances of your app. While generating assertions and attestations within your app is relatively straightforward, the process of verifying them on the server side is a bit of a challenge. This library provides two methods for verifying attestations and assertions on the server side for JavaScript or TypeScript based backends.

See https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity for details.

## Installation

```bash
yarn add node-app-attest / node install node-app-attest
```

## Usage

This library provides two methods, one to verify an attestation and another to verify the attestations:

```javascript
import { verifyAttestation, verifyAssertion } from 'node-app-attest';

const { keyId, publicKey } = verifyAttestation({
  attestation: Buffer,
  challenge: Buffer or String,
  keyId: String,
  bundleIdentifier: String (e.g. org.example.AppAttestExample),
  teamIdentifier: String (e.g. V8H6LQ9448),
  allowDevelopmentEnvironment: boolean (should only be true on test environments),
});

const { signCount } = verifyAssertion({
  assertion: Buffer,
  payload: Buffer or String,
  publicKey: String,
  bundleIdentifier: String (e.g. org.example.AppAttestExample),
  teamIdentifier: String (e.g. V8H6LQ9448),
  signCount: Number,
});

```

## Detailed Usage

The full example containing code for the app and for the backend you can find in this repository: https://github.com/uebelack/node-app-attest-example

APP

```swift
 func attestChallenge() async throws -> String {
    let (data, _) = try await URLSession.shared.data(from: url("/attest/challenge"))
    let json = try JSONDecoder().decode([String: String].self, from: data)
    return json["challenge"]!
  }
```

SERVER

```javascript
import express from 'express';
import { v4 as uuid } from 'uuid';

app.get('/attest/challenge', (req, res) => {
  const challenge = uuid();
  db.storeChallenge(challenge);
  log.debug(`challange was requested, returning ${challenge}`);
  res.send(JSON.stringify({ challenge }));
});
```

The app requests a challenge from the server, such as a randomly generated string, which the server stores in its database.

APP

```swift
import CryptoKit
import DeviceCheck
import Foundation

func attestKey() async throws -> String {
    let service = DCAppAttestService.shared
    if service.isSupported {
        let challenge = try await attestChallenge()
        let keyId = try await service.generateKey()
        let clientDataHash = Data(SHA256.hash(data: challenge.data(using: .utf8)!))
        let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)

        var request = URLRequest(url: url("/attest/verify"))
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(
            [
                "keyId": keyId,
                "challenge": challenge,
                "attestation": attestation.base64EncodedString(),
            ]
        )
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )

        let (_, response) = try await URLSession.shared.data(for: request)

        if let httpResponse = response as? HTTPURLResponse {
            if httpResponse.statusCode == 204 {
                UserDefaults.standard.set(keyId, forKey: "AttestKeyId")
                return keyId
            }
        }

        throw ApiClientError.attestVerificationFailed
    }
    throw ApiClientError.attestNotSupported
}
```

Using the DCAppAttestService, the app generates a keyId. With the challenge and keyId, the app requests the DCAppAttestService to generate an attestation. In the background, the DCAppAttestService creates a public/private key pair on the device. The app transmits this attestation, which includes the new public key, to the server.

SERVER

```javascript
import { verifyAttestation, verifyAssertion } from 'node-app-attest';
app.post(`${API_PREFIX}/attest/verify`, (req, res) => {
  try {
    log.debug(`verify was requested: ${JSON.stringify(req.body, null, 2)}`);

    if (!db.findChallenge(req.body.challenge)) {
      throw new Error('Invalid challenge');
    }

    const result = verifyAttestation({
      attestation: Buffer.from(req.body.attestation, 'base64'),
      challenge: req.body.challenge,
      keyId: req.body.keyId,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      allowDevelopmentEnvironment: true,
    });

    log.debug(`attestation result: ${JSON.stringify(result, null, 2)}`);

    db.storeAttestation({ keyId: req.body.keyId, publicKey: result.publicKey, signCount: 0 });

    res.sendStatus(204);
    db.deleteChallenge(req.body.challenge);
  } catch (error) {
    log.error(error);
    res.status(401).send({ error: 'Unauthorized' });
  }
});
```

Upon receiving the attestation, the server conducts nine validation checks (refer to https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server) and stores the new public key securely.

APP

```swift
func createAssertion(_ payload: Data) async throws -> String {
    var keyId = UserDefaults.standard.string(forKey: "AttestKeyId")

    if keyId == nil {
        keyId = try await attestKey()
    }

    let hash = Data(SHA256.hash(data: payload))
    let service = DCAppAttestService.shared
    let assertion = try await service.generateAssertion(keyId!, clientDataHash: hash)

    return try JSONEncoder().encode([
        "keyId": keyId,
        "assertion": assertion.base64EncodedString(),
    ]).base64EncodedString()
}

func sendMessage(subject: String, message: String) async throws {
    let challenge = try await attestChallenge()
    let payload = try JSONEncoder().encode([
        "subject": subject,
        "message": message,
        "challenge": challenge,
    ])

    let assertion = try await createAssertion(payload)

    var request = URLRequest(url: url("/send-message"))
    request.httpMethod = "POST"
    request.httpBody = payload
    request.setValue(
        "application/json",
        forHTTPHeaderField: "Content-Type"
    )

    request.setValue(
        assertion,
        forHTTPHeaderField: "authentication"
    )

    let (_, response) = try await URLSession.shared.data(for: request)

    if let httpResponse = response as? HTTPURLResponse {
        if httpResponse.statusCode == 401 {
            UserDefaults.standard.removeObject(forKey: "AttestKeyId")
            throw ApiClientError.assertionFailed
        }
    }
}
```

For subsequent requests, the app again requests a challenge from the server, incorporates it into the request payloads, and signs the requests with the private key. These signatures, along with additional information, need to be send with the request to the server (e.g. as header).

SERVER

```javascript
import { verifyAttestation, verifyAssertion } from 'node-app-attest';

app.post(`${API_PREFIX}/send-message`, (req, res) => {
  try {
    const { authentication } = req.headers;

    if (!authentication) {
      throw new Error('No authentication header');
    }

    const { keyId, assertion } = JSON.parse(Buffer.from(authentication, 'base64').toString());

    if (keyId === undefined || assertion === undefined) {
      throw new Error('Invalid authentication');
    }

    if (!db.findChallenge(req.body.challenge)) {
      throw new Error('Invalid challenge');
    }

    db.deleteChallenge(req.body.challenge);

    const attestation = db.findAttestation(keyId);

    if (!attestation) {
      throw new Error('No attestation found');
    }

    const result = verifyAssertion({
      assertion: Buffer.from(assertion, 'base64'),
      payload: JSON.stringify(req.body),
      publicKey: attestation.publicKey,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      signCount: attestation.signCount,
    });

    db.storeAttestation({ keyId, signCount: result.signCount });

    log.debug(`Received message: ${JSON.stringify(req.body)}`);

    res.sendStatus(204);
  } catch (error) {
    log.error(error);
    res.status(401).send({ error: 'Unauthorized' });
  }
});
```

The server verifies these assertions against the challenge and the stored public key to ensure the integrity and authenticity of the requests.

## Other implementations

- Swift: https://github.com/iansampson/AppAttest
- Kotlin/Java: https://github.com/veehaitch/devicecheck-appattest
- Node: https://github.com/srinivas1729/appattest-checker-node

## License

MIT License. See `LICENSE` for more information.

[build-shield]: https://img.shields.io/github/actions/workflow/status/uebelack/node-app-attest/ci.yml?branch=main&style=for-the-badge
[build-url]: https://github.com/uebelack/node-app-attest/actions/workflows/ci.yml
[language-shield]: https://img.shields.io/github/languages/top/uebelack/node-app-attest.svg?style=for-the-badge
[language-url]: https://github.com/uebelack/node-app-attest
[coverage-shield]: https://img.shields.io/coveralls/github/uebelack/node-app-attest.svg?style=for-the-badge
[coverage-url]: https://coveralls.io/github/uebelack/node-app-attest
[license-shield]: https://img.shields.io/github/license/uebelack/node-app-attest.svg?style=for-the-badge
[license-url]: https://github.com/uebelack/node-app-attest/blob/master/LICENSE
