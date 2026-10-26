# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.3](https://github.com/Authkestra/authkestra/compare/authkestra-resource-v0.13.2...authkestra-resource-v0.13.3) - 2026-10-26

### Added

- *(policy,ssf)* wire CedarPolicyEngine and OpenID CAEP/SSF receiver into resource, mcp, axum, and actix ([#418](https://github.com/Authkestra/authkestra/pull/418))

## [0.13.1](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.13.0...authkestra-resource-v0.13.1) - 2026-09-26

### Other

- give every published crate its own crates.io keywords/categories ([#412](https://github.com/marcjazz/authkestra/pull/412))

## [0.13.0](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.12.0...authkestra-resource-v0.13.0) - 2026-09-23

### Added

- *(resource,policy)* say why a token or an authorization was refused ([#408](https://github.com/marcjazz/authkestra/pull/408))

## [0.11.0](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.10.2...authkestra-resource-v0.11.0) - 2026-09-14

### Fixed

- *(engine)* de-feature token — always compile token machinery in ([#377](https://github.com/marcjazz/authkestra/pull/377))

## [0.10.0](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.9.5...authkestra-resource-v0.10.0) - 2026-09-14

### Fixed

- *(engine)* [**breaking**] enforce JWKS key-use separation when selecting a verification key ([#342](https://github.com/marcjazz/authkestra/pull/342))

## [0.9.3](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.9.2...authkestra-resource-v0.9.3) - 2026-09-07

### Added

- instrument the token-validation path, and fix flaky log-capture tests ([#358](https://github.com/marcjazz/authkestra/pull/358))
- *(engine)* name and expose the clock-skew leeway JWT validation applies ([#351](https://github.com/marcjazz/authkestra/pull/351))

## [0.9.2](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.9.1...authkestra-resource-v0.9.2) - 2026-09-06

### Fixed

- *(resource)* verify tokens under a multi-family algorithm policy ([#340](https://github.com/marcjazz/authkestra/pull/340))

## [0.7.1](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.7.0...authkestra-resource-v0.7.1) - 2026-09-01

### Added

- *(resource)* let JwksCache fetch through a caller-supplied HTTP client ([#301](https://github.com/marcjazz/authkestra/pull/301))

## [0.7.0](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.6.3...authkestra-resource-v0.7.0) - 2026-08-31

### Other

- Merge next into main (DPoP, migrations, and fixes) ([#292](https://github.com/marcjazz/authkestra/pull/292))

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.5.5...authkestra-resource-v0.6.0) - 2026-08-27

### Added

- *(resource)* resolve JWKS per issuer for multi-issuer resource servers ([#254](https://github.com/marcjazz/authkestra/pull/254))

### Fixed

- *(resource)* gracefully reject untrusted issuers and enforce iss claim ([#260](https://github.com/marcjazz/authkestra/pull/260))

### Other

- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))
- *(resource)* [**breaking**] mark ValidationConfig non_exhaustive and pin its defaults ([#250](https://github.com/marcjazz/authkestra/pull/250))

## [0.5.4](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.5.3...authkestra-resource-v0.5.4) - 2026-08-24

> **⚠️ Note on Semantic Versioning Break**
> This release introduced a breaking change by adding `require_cert_binding` to `ValidationConfig`, which was an exhaustive struct at the time. Downstream users employing struct-literal construction (`ValidationConfig { ... }`) will face compilation failures ("missing field"). This is permanently corrected in `0.6.0` by making the struct `#[non_exhaustive]`.

### Added

- *(op)* RFC 8705 certificate-bound access tokens for client_credentials ([#231](https://github.com/marcjazz/authkestra/pull/231))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.3.3...authkestra-resource-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.3.2...authkestra-resource-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.3.1...authkestra-resource-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.5...v0.3.0) - 2026-07-31

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
