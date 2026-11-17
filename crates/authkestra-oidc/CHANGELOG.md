# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.3](https://github.com/Authkestra/authkestra/compare/authkestra-oidc-v0.15.2...authkestra-oidc-v0.15.3) - 2026-11-15

### Other

- fix CI badge links and harden release-plz workflow ([#453](https://github.com/Authkestra/authkestra/pull/453))

## [0.13.1](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.13.0...authkestra-oidc-v0.13.1) - 2026-09-26

### Other

- give every published crate its own crates.io keywords/categories ([#412](https://github.com/marcjazz/authkestra/pull/412))

## [0.11.0](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.10.2...authkestra-oidc-v0.11.0) - 2026-09-14

### Fixed

- *(engine)* de-feature token — always compile token machinery in ([#377](https://github.com/marcjazz/authkestra/pull/377))

## [0.9.3](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.9.2...authkestra-oidc-v0.9.3) - 2026-09-07

### Added

- *(engine)* name and expose the clock-skew leeway JWT validation applies ([#351](https://github.com/marcjazz/authkestra/pull/351))

## [0.8.1](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.8.0...authkestra-oidc-v0.8.1) - 2026-09-04

### Other

- Generate an OAuth2 nonce only when the provider validates one ([#318](https://github.com/marcjazz/authkestra/pull/318))

## [0.7.2](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.7.1...authkestra-oidc-v0.7.2) - 2026-09-03

### Other

- refresh engine guides, provider docs and the book against current code ([#305](https://github.com/marcjazz/authkestra/pull/305))

## [0.7.0](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.6.3...authkestra-oidc-v0.7.0) - 2026-08-31

### Other

- add coverage for auth strategies and flow orchestration ([#297](https://github.com/marcjazz/authkestra/pull/297)) ([#298](https://github.com/marcjazz/authkestra/pull/298))
- Merge next into main (DPoP, migrations, and fixes) ([#292](https://github.com/marcjazz/authkestra/pull/292))

## [0.6.2](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.6.1...authkestra-oidc-v0.6.2) - 2026-08-28

### Other

- correct API drift across README, crate docs, website and book ([#269](https://github.com/marcjazz/authkestra/pull/269))

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.5.5...authkestra-oidc-v0.6.0) - 2026-08-27

### Added

- *(resource)* resolve JWKS per issuer for multi-issuer resource servers ([#254](https://github.com/marcjazz/authkestra/pull/254))

### Fixed

- *(oidc)* [**breaking**] make Claims non-exhaustive and omit spec step 3 ([#258](https://github.com/marcjazz/authkestra/pull/258))
- *(oidc)* [**breaking**] accept array-valued `aud` in ID tokens and verify `azp` ([#244](https://github.com/marcjazz/authkestra/pull/244)) ([#251](https://github.com/marcjazz/authkestra/pull/251))

## [0.5.3](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.5.2...authkestra-oidc-v0.5.3) - 2026-08-24

### Fixed

- *(oidc)* derive ID-token Validation from discovery instead of Validation::default() ([#228](https://github.com/marcjazz/authkestra/pull/228))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.3.3...authkestra-oidc-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine, authkestra-resource

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.3.2...authkestra-oidc-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.3.1...authkestra-oidc-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.0) - 2026-07-31

### Other

- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))
