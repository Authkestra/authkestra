# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.2](https://github.com/Authkestra/authkestra/compare/authkestra-v0.13.1...authkestra-v0.13.2) - 2026-10-26

### Added

- *(mcp)* add authkestra-mcp crate, Axum/Actix adapters, and AI agent security ([#415](https://github.com/Authkestra/authkestra/pull/415))

## [0.13.1](https://github.com/marcjazz/authkestra/compare/authkestra-v0.13.0...authkestra-v0.13.1) - 2026-09-26

### Other

- give every published crate its own crates.io keywords/categories ([#412](https://github.com/marcjazz/authkestra/pull/412))

## [0.13.0](https://github.com/marcjazz/authkestra/compare/authkestra-v0.12.0...authkestra-v0.13.0) - 2026-09-23

### Added

- *(engine)* magic-link authentication behind a feature flag ([#400](https://github.com/marcjazz/authkestra/pull/400))

### Other

- Bring the READMEs up to v0.13 ([#409](https://github.com/marcjazz/authkestra/pull/409))
- Recovery codes as a look-up secret authenticator ([#404](https://github.com/marcjazz/authkestra/pull/404))
- Email and SMS one-time codes ([#402](https://github.com/marcjazz/authkestra/pull/402))

## [0.11.1](https://github.com/marcjazz/authkestra/compare/authkestra-v0.11.0...authkestra-v0.11.1) - 2026-09-15

### Added

- *(policy)* Cedar policy engine proof of concept + RFC-005 ([#310](https://github.com/marcjazz/authkestra/pull/310))
- *(ssf)* ingest and validate Security Event Tokens (RFC 8417) with typed CAEP events ([#309](https://github.com/marcjazz/authkestra/pull/309))

## [0.11.0](https://github.com/marcjazz/authkestra/compare/authkestra-v0.10.2...authkestra-v0.11.0) - 2026-09-14

### Fixed

- *(engine)* de-feature token — always compile token machinery in ([#377](https://github.com/marcjazz/authkestra/pull/377))
- *(engine)* [**breaking**] remove authkestra-engine's no-op `session` feature ([#375](https://github.com/marcjazz/authkestra/pull/375))

### Other

- *(facade)* [**breaking**] one name for the engine, and drop the two empty features ([#384](https://github.com/marcjazz/authkestra/pull/384))

## [0.10.2](https://github.com/marcjazz/authkestra/compare/authkestra-v0.10.1...authkestra-v0.10.2) - 2026-09-14

### Other

- Gate facade features, make authkestra-engine optional ([#325](https://github.com/marcjazz/authkestra/pull/325)) ([#369](https://github.com/marcjazz/authkestra/pull/369))

## [0.9.5](https://github.com/marcjazz/authkestra/compare/authkestra-v0.9.4...authkestra-v0.9.5) - 2026-09-13

### Other

- Move the docs out, put a landing page in their place ([#362](https://github.com/marcjazz/authkestra/pull/362))

## [0.9.3](https://github.com/marcjazz/authkestra/compare/authkestra-v0.9.2...authkestra-v0.9.3) - 2026-09-07

### Added

- *(facade)* forward the sub-crate features the facade never exposed ([#347](https://github.com/marcjazz/authkestra/pull/347))

### Other

- *(facade)* move the facade tests where they can actually fail ([#348](https://github.com/marcjazz/authkestra/pull/348))

## [0.8.0](https://github.com/marcjazz/authkestra/compare/authkestra-v0.7.2...authkestra-v0.8.0) - 2026-09-03

### Other

- Merge next into main: storage rework, DPoP, PKCE/scope hardening ([#300](https://github.com/marcjazz/authkestra/pull/300))

## [0.7.2](https://github.com/marcjazz/authkestra/compare/authkestra-v0.7.1...authkestra-v0.7.2) - 2026-09-03

### Other

- refresh engine guides, provider docs and the book against current code ([#305](https://github.com/marcjazz/authkestra/pull/305))

## [0.7.0](https://github.com/marcjazz/authkestra/compare/authkestra-v0.6.3...authkestra-v0.7.0) - 2026-08-31

### Other

- add coverage for auth strategies and flow orchestration ([#297](https://github.com/marcjazz/authkestra/pull/297)) ([#298](https://github.com/marcjazz/authkestra/pull/298))

## [0.6.2](https://github.com/marcjazz/authkestra/compare/authkestra-v0.6.1...authkestra-v0.6.2) - 2026-08-28

### Other

- correct API drift across README, crate docs, website and book ([#269](https://github.com/marcjazz/authkestra/pull/269))

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-v0.5.5...authkestra-v0.6.0) - 2026-08-27

### Other

- *(examples)* migrate attestation and devsig examples to the unified engine patterns ([#194](https://github.com/marcjazz/authkestra/pull/194)) ([#262](https://github.com/marcjazz/authkestra/pull/262))
- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))
- *(examples)* modernise examples for the unified engine ([#194](https://github.com/marcjazz/authkestra/pull/194)) ([#255](https://github.com/marcjazz/authkestra/pull/255))

## [0.5.5](https://github.com/marcjazz/authkestra/compare/authkestra-v0.5.4...authkestra-v0.5.5) - 2026-08-24

### Other

- *(engine)* add SD-JWT runnable example, doctests, and book/README docs ([#241](https://github.com/marcjazz/authkestra/pull/241))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-v0.3.3...authkestra-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine, authkestra-engine, authkestra-providers, authkestra-providers, authkestra-resource, authkestra-resource, authkestra-op, authkestra-axum, authkestra-axum, authkestra-oidc, authkestra-oidc, authkestra-actix, authkestra-actix

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-v0.3.2...authkestra-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-v0.3.1...authkestra-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

### Other

- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))

## [0.3.1](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.1) - 2026-07-31

### Fixed

- move examples to root crate to permanently resolve cyclic publish failures ([#168](https://github.com/marcjazz/authkestra/pull/168))

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.0) - 2026-07-31

### Other

- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))
