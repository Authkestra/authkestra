# Device-signature profile v1: conformance vectors

`vectors.json` is the shared test set of [RFC-014](../../docs/rfc-014-devsig-profile-v1.md): what a
device-signed request looks like, and what a verifier must answer for it. Authkestra
(`authkestra-devsig`), fespalier (`fespalier_sign_keypair`) and CrateStack (its device-signature
provider) run the same file, so they agree on one table rather than on three.

**Every key and credential in it is a fixed test value that protects nothing.**

## Format

| Member | |
| --- | --- |
| `verifier` | the configuration every vector runs with: trusted issuers, audience, issuer and device algorithms, clock skew, longest signature, header names |
| `issuer_keys` | the issuer's public JWKs, each with its `iss` and `kid` |
| `refusals` | the refusal table: code, status, whether a `401` carries `WWW-Authenticate`, the client action, and who produces it (`verifier`, `adapter`, `application`) |
| `legacy_aliases` | names clients shipped before v1, and the v1 code each stands for |
| `vectors[]` | the cases |

Each vector:

| Member | |
| --- | --- |
| `id`, `description` | what it checks |
| `required` | `false` only for what a verifier MAY support (an EdDSA device key) |
| `now` | the Unix time to verify at |
| `request` | `method`, `path` (as sent, percent-encoded), `query` (raw, no `?`; `null` for none, `""` for a bare `?`), `body` (UTF-8 text; `null` for none), `headers` (an absent header is left out) |
| `replay` | `store`: `available` or `unavailable` (every call fails: the verifier must refuse); `seen_jtis`: `jti`s already used before this request |
| `expect` | `{"outcome": "accept", "sub", "did", "jkt", "role"}`, or `{"outcome": "refuse", "status", "error", "body", "www_authenticate"}` |

Run each vector with a **fresh** replay store. `role` is `ambient` or `user_present`
(`att.role`, RFC-014 §3.3).

## Using the vectors in another project

1. Copy `vectors.json` from a commit of this repository, and record that commit next to it
   (for example in a `PIN` file with the commit and the file's SHA-256).
2. Add a test that recomputes the SHA-256 of the copy and compares it with the pin, so the copy
   is never edited by hand.
3. Run every vector through your verifier at `now`, and compare the verdict with `expect`. A
   client that only *reads* refusals can still run the `refusals` table through its classifier.
4. To update, copy the file from a newer commit and change the pin in the same change.

## Regenerating

The file is generated, never edited:

```bash
AUTHKESTRA_UPDATE_VECTORS=1 cargo test -p authkestra-devsig --test profile_v1
```

Without the variable the same test fails when the committed file is stale, then runs every vector
against `authkestra_devsig::verify_at`. The generator is
`crates/authkestra-devsig/tests/profile_v1.rs` and `tests/profile_v1_mint/`; its keys are fixed
and its signature algorithms deterministic (ES256 with RFC 6979 nonces, Ed25519, RSA PKCS#1 v1.5),
so regenerating an unchanged generator writes the same bytes. Expected verdicts are written by
hand in the generator, never computed by the verifier.
