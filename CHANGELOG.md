# Changelog

## [2.1.0] - 2026-11-13

### Security

- 🔒 require signCount in verifyAssertion

### Refactoring

- ♻️ replace cbor with cbor2

### Other

- 🏷️ add JSDoc types for parameters and results

## [2.0.0] - 2026-11-13

### Breaking changes

- 💥 require Node.js 24

### Dependencies

- ⬆️ update TypeScript to v7
- ⬆️ update asn1js and pkijs to v4
- ⬆️ update dependencies

### Tests

- ✅ encode test attestations with cbor2, cbor's encoder is broken on Node.js 26
- ✅ migrate from Jest to Vitest
- ✅ assert the result of a successful assertion verification

### CI

- 👷 add release workflow and git-cliff config
- 👷 update CI workflow for pnpm and Node 24/26

### Chores

- 🔧 improve linting workflow and add jest coverage configuration
- 📦 tidy package metadata and publish only src and types
- 🔧 replace ESLint and Prettier with oxlint and oxfmt
- 🔧 migrate from Yarn to pnpm
- 🔧 improve linting workflow and add jest coverage configuration

### Other

- 🔀 merge main into upgrade

## [1.0.1] - 2026-02-20

### Features

- ✨ upgrade to v1.0.1 with dependency updates and ESLint v10 migration

### Other

- Bump asn1js from 3.0.6 to 3.0.7
- Bump eslint from 9.39.1 to 9.39.2
- Bump eslint-plugin-jest from 29.0.1 to 29.12.1
- Bump prettier from 3.6.2 to 3.8.0
- Bump eslint-plugin-prettier from 5.5.4 to 5.5.5
- Bump typescript from 5.9.2 to 5.9.3
- Bump jest from 30.1.1 to 30.2.0
- Bump pkijs from 3.2.5 to 3.3.3
- Bump eslint from 9.34.0 to 9.39.1

## [0.0.8] - 2025-08-29

### Other

- v0.0.8
- updated linter and added prettier
- update node test version
- updated version

## [0.0.7] - 2025-08-29

### Bug fixes

- fixed dependabot config
- fixed licence in readme

### Other

- v0.0.7
- upgrade dependencies
- Bump eslint-plugin-jest from 28.10.0 to 28.11.0
- Bump typescript from 5.7.2 to 5.7.3
- Bump pkijs from 3.2.4 to 3.2.5
- Bump asn1js from 3.0.5 to 3.0.6
- Fix import of non-default export
- Bump pkijs from 3.1.0 to 3.2.4
- Bump cbor from 9.0.2 to 10.0.3
- Bump typescript from 5.4.5 to 5.7.2
- Bump eslint-plugin-jest from 28.6.0 to 28.10.0
- Bump typescript from 5.4.2 to 5.4.5
- Bump pkijs from 3.0.16 to 3.1.0
- Bump eslint-plugin-jest from 27.9.0 to 28.6.0
- Bump pkijs from 3.0.15 to 3.0.16
- Bump eslint from 8.56.0 to 8.57.0
- Bump typescript from 5.3.3 to 5.4.2
- return receipt in attestation result
- Bump eslint-plugin-jest from 27.6.3 to 27.9.0
- added typescript types
- added keywords
- added docs, verifyAssertions returns signCount
- updated version
- cleanup
- added github actions, dependabot and some badges to readme
- finished implementation of verifyAssertion
- implemented step 1-3 in verifyAssertion
- finished implementation of verifyAttestation
- implemented rules 6, 7 and 8
- implemented rule 5
- 🚀 real initial commit
- Create README.md
- Initial commit
