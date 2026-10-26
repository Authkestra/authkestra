# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.2](https://github.com/Authkestra/authkestra/compare/authkestra-store-testsuite-v0.13.1...authkestra-store-testsuite-v0.13.2) - 2026-10-26

### Added

- *(mcp)* add authkestra-mcp crate, Axum/Actix adapters, and AI agent security ([#415](https://github.com/Authkestra/authkestra/pull/415))

## [0.13.1](https://github.com/marcjazz/authkestra/compare/authkestra-store-testsuite-v0.13.0...authkestra-store-testsuite-v0.13.1) - 2026-09-26

### Other

- give every published crate its own crates.io keywords/categories ([#412](https://github.com/marcjazz/authkestra/pull/412))

## [0.13.0](https://github.com/marcjazz/authkestra/compare/authkestra-store-testsuite-v0.12.0...authkestra-store-testsuite-v0.13.0) - 2026-09-23

### Other

- Bring the READMEs up to v0.13 ([#409](https://github.com/marcjazz/authkestra/pull/409))
- A conformance suite for CredentialStore ([#405](https://github.com/marcjazz/authkestra/pull/405))
- Email and SMS one-time codes ([#402](https://github.com/marcjazz/authkestra/pull/402))

## [0.11.1](https://github.com/marcjazz/authkestra/compare/authkestra-store-testsuite-v0.11.0...authkestra-store-testsuite-v0.11.1) - 2026-09-15

### Added

- *(policy)* Cedar policy engine proof of concept + RFC-005 ([#310](https://github.com/marcjazz/authkestra/pull/310))
- *(ssf)* ingest and validate Security Event Tokens (RFC 8417) with typed CAEP events ([#309](https://github.com/marcjazz/authkestra/pull/309))

## [0.9.5](https://github.com/marcjazz/authkestra/compare/authkestra-store-testsuite-v0.9.4...authkestra-store-testsuite-v0.9.5) - 2026-09-13

### Other

- Move the docs out, put a landing page in their place ([#362](https://github.com/marcjazz/authkestra/pull/362))

## [0.8.0](https://github.com/marcjazz/authkestra/compare/authkestra-store-testsuite-v0.7.2...authkestra-store-testsuite-v0.8.0) - 2026-09-03

### Added

- *(actix)* achieve macro feature parity ([#61](https://github.com/marcjazz/authkestra/pull/61)) ([#94](https://github.com/marcjazz/authkestra/pull/94))
- *(engine)* Implement central AuthEngine with typestate builder ([#29](https://github.com/marcjazz/authkestra/pull/29))
- Refactor device flow and enhance providers

### Fixed

- *(release)* drop the version pin on store-testsuite's store-sqlx dev-dep ([#314](https://github.com/marcjazz/authkestra/pull/314))
- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

### Other

- Merge next into main: storage rework, DPoP, PKCE/scope hardening ([#300](https://github.com/marcjazz/authkestra/pull/300))
- refresh engine guides, provider docs and the book against current code ([#305](https://github.com/marcjazz/authkestra/pull/305))
- add coverage for auth strategies and flow orchestration ([#297](https://github.com/marcjazz/authkestra/pull/297)) ([#298](https://github.com/marcjazz/authkestra/pull/298))
- correct API drift across README, crate docs, website and book ([#269](https://github.com/marcjazz/authkestra/pull/269))
- *(engine)* add SD-JWT runnable example, doctests, and book/README docs ([#241](https://github.com/marcjazz/authkestra/pull/241))
- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))
- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))
- release v0.2.4 ([#131](https://github.com/marcjazz/authkestra/pull/131))
- Develop ([#123](https://github.com/marcjazz/authkestra/pull/123))
- rebuild starlight documentation, fix ci, and configure github pages deployment ([#96](https://github.com/marcjazz/authkestra/pull/96))
- apply Ak naming convention globally and cleanup legacy macros ([#93](https://github.com/marcjazz/authkestra/pull/93))
- reorganize workspace into crates/ directory and update publish CI ([#76](https://github.com/marcjazz/authkestra/pull/76))
- address structural debt for workspace and actix parity ([#60](https://github.com/marcjazz/authkestra/pull/60))
- structural cleanup and documentation organization ([#59](https://github.com/marcjazz/authkestra/pull/59))
- Refactor examples into atomic pieces ([#34](https://github.com/marcjazz/authkestra/pull/34))
- [Migration Phase 1] 6. Rename Guard to Resource ([#33](https://github.com/marcjazz/authkestra/pull/33))
- Feat/authentication strategy ([#1](https://github.com/marcjazz/authkestra/pull/1))
- Update crate versions to 0.1.1
- Refine Authkestra typestate and simplify APIs
- remove Testing & Troubleshooting section from README
- clean up README title
- update README with getting started guide and facade crate info
- update README and add CONTRIBUTING guide
- *(core)* rename authly crates to authkestra
- update README and enhance publish workflow
- remove design documents and update README roadmap
- Update README and fix clippy warning
- overhaul README and update roadmap with strategic additions
- Initial commit: Monorepo setup
