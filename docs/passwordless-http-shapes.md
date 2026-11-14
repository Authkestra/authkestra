# Authkestra Passwordless HTTP API Specification

**Specification Version**: 1.0.0  
**Target Release**: Authkestra v0.15.0+  
**Associated Issues**: Client Interop Epic #437, RFC-009, RFC-010, RFC-011, RFC-012  

---

## 1. Architecture Overview

Authkestra provides a modular, memory-safe, RFC-compliant authentication framework written in Rust. Application-level passwordless authentication in Authkestra is centered around the core `authkestra-engine` crate, which coordinates authentication ceremonies, stores, and cryptographic identity assertions across web frameworks such as `authkestra-axum` and `authkestra-actix`.

### 1.1 The Engine Core, `AuthMethod`, and `AuthInput`

Per Authkestra Architecture Decision 0005, the framework owns **no user table**. The framework delegates user account persistence to the host application while strictly enforcing cryptographic handshakes, single-use guarantees, replay guards, and attempt budgeting.

All passwordless authenticators implement the framework-agnostic `authkestra_engine::auth::AuthMethod` trait:

```rust
AuthMethod::authenticate(&self, input: AuthInput) -> Result<Identity, AuthError>
```

First-factor `Password`, `Totp`, and `WebAuthnAuthentication` inputs — plus two-step `MfaChallenge` continuations wrapping `Totp`, `WebAuthnAuthentication`, or `RecoveryCode` — are also dispatched centrally through `Engine::authenticate(&self, input: AuthInput) -> Result<AuthResult, AuthError>`. Standalone primary `MagicLink`, `Otp`, and `RecoveryCode` flows are invoked directly via `MagicLinkAuthMethod::authenticate`, `OtpAuthMethod::authenticate`, and `RecoveryCodeAuthMethod::authenticate`.

Authentication payloads use the unified enum `authkestra_engine::auth::AuthInput`, serialized and deserialized with serde's adjacently tagged representation `#[serde(tag = "type", content = "data")]`:

```json
{
  "type": "<Variant>",
  "data": { ... }
}
```

The supported passwordless variants of `AuthInput` are:
1. `WebAuthnAuthentication`: Cryptographic assertion from a WebAuthn passkey (FIDO2 / W3C WebAuthn).
2. `MagicLink`: Single-use link secret delivered out-of-band to a mailbox, with optional browser context binding.
3. `Otp`: 6-digit one-time code delivered out-of-band via email or SMS, subject-keyed with attempt limiting.
4. `RecoveryCode`: Long-lived, factor-agnostic look-up secret authenticator (NIST SP 800-63B §5.1.2).
5. `MfaChallenge`: Wraps `Totp`, `WebAuthnAuthentication`, or `RecoveryCode` inside a temporary signed JWT continuation token when multi-factor step-up is required.

### 1.2 Route Scope & Reference Server vs Built-in Adapter Routes

Authkestra decouples protocol primitives from transport frameworks:
- **`authkestra-axum`** and **`authkestra-actix`** provide framework extractors, session/cookie helpers, and pre-built routers for OAuth2 Relying Party (`/auth/*`), OpenID Provider (`op_*_router`), MCP, and SSF endpoints — they do **not** currently bundle built-in `/auth/passkey/*`, `/auth/magic-link/*`, `/auth/otp/*`, or `/auth/recovery/*` routes.
- Instead, the HTTP endpoint paths, session-wrapping responses, and JSON error envelopes specified below define the **reference HTTP integration contract** implemented by [`crates/authkestra/examples/axum_passwordless_server.rs`](../crates/authkestra/examples/axum_passwordless_server.rs) (and portable identically to Actix-web using `web::Data`, `web::Json`, `HttpRequest::cookie`, and `ActixError`).

---

## 2. Passkey / WebAuthn Endpoints

Passkey authentication conforms to the W3C WebAuthn Level 3 specification and FIDO2 standards, backed by `webauthn-rs`.

### 2.1 User Handle Derivation

In Authkestra, the WebAuthn user handle (`user.id` in `PublicKeyCredentialCreationOptions`) is deterministic and stable:
- If `user_id` parses as a UUID, it is passed through byte-for-byte.
- Any non-UUID identifier (e.g. CUID, ULID, email, database integer) is deterministically hashed using UUIDv5 over `USER_HANDLE_NAMESPACE` (`uuid5(NAMESPACE_URL, "https://authkestra.dev/webauthn/user-handle")` = `ef84b322-b2dd-5ab4-aea2-8221f829229e`).

This guarantees that discoverable ("usernameless") credentials can always be resolved back to a single unique account across any language or platform.

---

### 2.2 Registration Start: `POST /auth/passkey/register/start`

Initiates the passkey registration ceremony. This endpoint is security-sensitive and **must be gated** by `ReproofRequirement` (RFC-009) to prevent stolen session cookies or XSS from enrolling unauthorized credentials.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/passkey/register/start`
- **Headers**:
  - `Content-Type: application/json`
  - `Cookie: ak_session=<session_id>` (or `Authorization: Bearer <token>`)

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "username": {
      "type": "string",
      "description": "Account identifier or email to enroll"
    },
    "display_name": {
      "type": "string",
      "description": "Optional human-readable display name for the passkey authenticator"
    }
  },
  "required": ["username"]
}
```

#### Example Request
```http
POST /auth/passkey/register/start HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Cookie: ak_session=sess_9876543210abcdef

{
  "username": "alice@example.com",
  "display_name": "Alice Smith"
}
```

#### Server Processing & Session State
1. Authenticates current session; validates `ReproofRequirement::check(&identity)`. If `auth_time` is absent or older than `max_age_secs`, rejects with HTTP 403 `reproof_required`.
2. Invokes `WebAuthnAuthMethod::start_register(&identity, &gate, username)`.
3. The engine creates a `(CreationChallengeResponse, PasskeyEnrolment)` pair.
4. The server stores `PasskeyEnrolment` (carrying `subject` and `PasskeyRegistration` state) inside the server-side session.

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Cache-Control: no-store`

#### Response Body Schema (`CreationChallengeResponse`)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "publicKey": {
      "type": "object",
      "properties": {
        "rp": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "id": { "type": "string" }
          },
          "required": ["name", "id"]
        },
        "user": {
          "type": "object",
          "properties": {
            "id": { "type": "string", "description": "Base64url encoded user handle" },
            "name": { "type": "string" },
            "displayName": { "type": "string" }
          },
          "required": ["id", "name", "displayName"]
        },
        "challenge": { "type": "string", "description": "Base64url encoded challenge nonce" },
        "pubKeyCredParams": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "type": { "type": "string", "enum": ["public-key"] },
              "alg": { "type": "integer" }
            },
            "required": ["type", "alg"]
          }
        },
        "timeout": { "type": "integer" },
        "excludeCredentials": { "type": "array" },
        "authenticatorSelection": { "type": "object" },
        "attestation": { "type": "string" }
      },
      "required": ["rp", "user", "challenge", "pubKeyCredParams"]
    }
  },
  "required": ["publicKey"]
}
```

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "publicKey": {
    "rp": {
      "name": "Authkestra Demo",
      "id": "example.com"
    },
    "user": {
      "id": "74SzA-s5S5SqooIh-Cknng",
      "name": "alice@example.com",
      "displayName": "Alice Smith"
    },
    "challenge": "jW0-1k6c7aB4N0U3k9W01k6c7aB4N0U3k9W01k6c7aA",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "excludeCredentials": [],
    "authenticatorSelection": {
      "authenticatorAttachment": null,
      "requireResidentKey": false,
      "residentKey": "preferred",
      "userVerification": "preferred"
    },
    "attestation": "none",
    "extensions": {}
  }
}
```

---

### 2.3 Registration Finish: `POST /auth/passkey/register/finish`

Completes registration using the navigator's credential creation output.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/passkey/register/finish`
- **Headers**:
  - `Content-Type: application/json`
  - `Cookie: ak_session=<session_id>`

#### Request Body Schema (`RegisterPublicKeyCredential`)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "Base64url credential identifier" },
    "rawId": { "type": "string", "description": "Base64url credential raw ID" },
    "type": { "type": "string", "enum": ["public-key"] },
    "response": {
      "type": "object",
      "properties": {
        "clientDataJSON": { "type": "string", "description": "Base64url client data JSON" },
        "attestationObject": { "type": "string", "description": "Base64url attestation CBOR object" }
      },
      "required": ["clientDataJSON", "attestationObject"]
    },
    "clientExtensionResults": { "type": "object" }
  },
  "required": ["id", "rawId", "type", "response"]
}
```

#### Example Request
```http
POST /auth/passkey/register/finish HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Cookie: ak_session=sess_9876543210abcdef

{
  "id": "ADca8G63...truncated...",
  "rawId": "ADca8G63...truncated...",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiandvLTFr...truncated...",
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW...truncated..."
  },
  "clientExtensionResults": {}
}
```

#### Server Processing
1. Extracts `PasskeyEnrolment` from session. If absent, returns HTTP 400 Bad Request (`invalid_request`).
2. Invokes `WebAuthnAuthMethod::finish_register(enrolment, reg_response)`.
3. Verifies challenge signature, origin, and RP ID.
4. Serializes passkey and persists to `CredentialStore::save_credential(user_id, "webauthn", val)`.
5. Removes `PasskeyEnrolment` from session.

#### HTTP Response (Success)
- **Status Code**: `200 OK` (or `201 Created`)
- **Headers**: `Content-Type: application/json`

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "credential_id": "ADca8G63...truncated..."
}
```

---

### 2.4 Authentication Start: `POST /auth/passkey/login/start`

Initiates passkey assertion for an account-specified login.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/passkey/login/start`
- **Headers**: `Content-Type: application/json`

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "username": {
      "type": "string",
      "description": "Required account identifier matching the subject external_id stored during registration."
    }
  },
  "required": ["username"]
}
```

#### Example Request
```http
POST /auth/passkey/login/start HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "username": "alice@example.com"
}
```

#### Server Processing & Session State
1. Requires non-empty `username` (`400 invalid_request` if missing or blank) and queries store for enrolled credentials: `store.get_credentials(user_id, "webauthn")`.
2. Invokes `webauthn.start_passkey_authentication(&passkeys)`.
3. Saves `PasskeyAuthentication` state in a bounded TTL ceremony store.

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Cache-Control: no-store`

#### Response Body Schema (`RequestChallengeResponse`)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "publicKey": {
      "type": "object",
      "properties": {
        "challenge": { "type": "string" },
        "timeout": { "type": "integer" },
        "rpId": { "type": "string" },
        "allowCredentials": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "type": { "type": "string", "enum": ["public-key"] },
              "id": { "type": "string" },
              "transports": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["type", "id"]
          }
        },
        "userVerification": { "type": "string" }
      },
      "required": ["challenge", "rpId"]
    }
  },
  "required": ["publicKey"]
}
```

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "publicKey": {
    "challenge": "4T8mKq1Qe4A3mKq1Qe4A3mKq1Qe4A3mKq1Qe4A3mKq0",
    "timeout": 60000,
    "rpId": "example.com",
    "allowCredentials": [],
    "userVerification": "preferred",
    "extensions": {}
  }
}
```

---

### 2.5 Authentication Finish: `POST /auth/passkey/login/finish`

Verifies the passkey signature, increments the authenticator counter, stamps authentication attributes (`amr: "webauthn"`, `step_up_satisfied: "true"`), and establishes the authenticated session.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/passkey/login/finish`
- **Headers**:
  - `Content-Type: application/json`
  - `Cookie: ak_session=<session_id>`

#### Request Body Schema (`AuthInput::WebAuthnAuthentication`)
When submitted via `AuthInput`, the request matches:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "type": { "type": "string", "const": "WebAuthnAuthentication" },
    "data": {
      "type": "object",
      "properties": {
        "user_id": { "type": "string" },
        "credential_id": { "type": "string", "description": "Base64url credential ID" },
        "client_data_json": { "type": "string", "description": "Base64url clientDataJSON" },
        "authenticator_data": { "type": "string", "description": "Base64url authenticatorData" },
        "signature": { "type": "string", "description": "Base64url signature" },
        "user_handle": { "type": "string", "description": "Base64url user handle from authenticator" }
      },
      "required": ["user_id", "credential_id", "client_data_json", "authenticator_data", "signature"]
    }
  },
  "required": ["type", "data"]
}
```

> **Security Note**: `auth_state_json` is an internal field of `AuthInput::WebAuthnAuthentication`. The HTTP client **must not** supply it. The server endpoint extracts the serialized `PasskeyAuthentication` from the server session and injects it into `AuthInput` before calling `Engine::authenticate`.

#### Example Request
```http
POST /auth/passkey/login/finish HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Cookie: ak_session=sess_1234567890abcdef

{
  "type": "WebAuthnAuthentication",
  "data": {
    "user_id": "alice@example.com",
    "credential_id": "ADca8G63...truncated...",
    "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNFQ4bUt...truncated...",
    "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAIA...truncated...",
    "signature": "MEYCIQCp...truncated...",
    "user_handle": "74SzA-s5S5SqooIh-Cknng"
  }
}
```

#### Server Processing
1. Extracts `PasskeyAuthentication` from session. If missing -> HTTP 401 Unauthorized (`invalid_credentials`).
2. Dispatches `Engine::authenticate(AuthInput::WebAuthnAuthentication { ... auth_state_json })`.
3. Verifies signature against stored credential public key.
4. Updates signature counter via `CredentialStore::update_credential`.
5. Clears ceremony state from session.
6. Returns authenticated identity with `amr: "webauthn"` and `step_up_satisfied: "true"` (WebAuthn is MFA-equivalent).

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Set-Cookie: ak_session=<new_authenticated_session>; HttpOnly; Secure; SameSite=Lax; Path=/`

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "identity": {
    "provider_id": "webauthn",
    "external_id": "alice@example.com",
    "username": "passkey_user",
    "attributes": {
      "amr": "webauthn",
      "auth_time": "1700000000",
      "step_up_satisfied": "true"
    }
  }
}
```

---

## 3. Magic Link Endpoints

Magic link authentication proves control over a mailbox. In Authkestra (RFC-010):
- Minted secrets are **256 bits of CSPRNG output** (never guessable).
- Secrets are stored as **SHA-256 hashes**; live plaintext credentials are never persisted.
- Tokens are single-use via `AtomicConsume::consume`.
- Context binding (`MagicLinkBinding::SameContext`) protects against link forwarding while preserving security against mail-scanner prefetches.

---

### 3.1 Request / Mint: `POST /auth/magic-link/request`

Requests a magic link to be dispatched out-of-band to the subject's email.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/magic-link/request`
- **Headers**: `Content-Type: application/json`

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "subject": {
      "type": "string",
      "description": "Email address or subject identifier"
    },
    "binding": {
      "type": "string",
      "enum": ["same_context", "any_context"],
      "default": "same_context",
      "description": "Context binding mode. 'same_context' binds to the requesting browser cookie; 'any_context' allows cross-device link following."
    }
  },
  "required": ["subject"]
}
```

#### Example Request
```http
POST /auth/magic-link/request HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "subject": "alice@example.com",
  "binding": "same_context"
}
```

#### Server Processing & Cookie Setting
1. Resolves `subject`. To prevent account enumeration (RFC-010 §4.8), the endpoint takes identical execution time and returns an identical response whether the user exists or not.
2. If `same_context` is chosen, generates a 256-bit unguessable nonce `ml_binding`.
3. Calls `MagicLinkAuthMethod::mint(subject, ttl, MagicLinkBinding::SameContext(ml_binding))`.
4. Transports link out-of-band: `https://example.com/auth/magic-link/verify?token=<secret>`.
5. Sets HTTP response cookie: `Set-Cookie: ml_binding=<nonce>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=<ttl_secs>`.

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Set-Cookie: ml_binding=...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900`

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: ml_binding=mK8Z3wX1Pq2R4vT6...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900

{
  "status": "pending",
  "message": "If an account exists, a sign-in link has been sent to your email.",
  "expires_at": 1700000900
}
```

---

### 3.2 Consumption: `POST /auth/magic-link/consume`

Consumes a magic link secret and exchanges it for an authenticated session.

> **Mail Scanner Defense (RFC-010 §4.7)**: Following the URL via `GET /auth/magic-link/verify?token=...` **must not** consume the secret. It must render an HTML landing page with a confirmation button that issues `POST /auth/magic-link/consume`. This guarantees automated email security scanners and link-prefetch engines do not burn single-use tokens before the user clicks.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/magic-link/consume`
- **Headers**:
  - `Content-Type: application/json`
  - `Cookie: ml_binding=<nonce>` (required if link was minted with `same_context`)

#### Request Body Schema
Can be submitted as either flat JSON or `AuthInput`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "token": { "type": "string", "description": "The secret extracted from the email link URL" },
    "binding": { "type": "string", "description": "Optional explicit binding nonce (if not sent via cookie)" }
  },
  "required": ["token"]
}
```

Or via direct `AuthInput`:
```json
{
  "type": "MagicLink",
  "data": {
    "token": "4vT6mK8Z3wX1Pq2R...",
    "binding": "mK8Z3wX1Pq2R4vT6..."
  }
}
```

#### Example Request
```http
POST /auth/magic-link/consume HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Cookie: ml_binding=mK8Z3wX1Pq2R4vT6...

{
  "token": "4vT6mK8Z3wX1Pq2R..."
}
```

#### Server Processing
1. Extracts `token` from request body and `binding` from `ml_binding` cookie.
2. Calls `MagicLinkAuthMethod::authenticate(AuthInput::MagicLink { token, binding })`.
3. Invokes `AtomicConsume::consume(&hash_secret(&token))`.
4. If record absent, expired, or binding mismatched: returns HTTP 401 Unauthorized (`invalid_credentials`).
   - If binding mismatches, the token is consumed immediately and burned to close timing oracles.
5. Clears `ml_binding` cookie (`Max-Age=0`).
6. Yields authenticated `Identity` (`provider_id: "magic-link"`) and stamps `amr: "magic-link"` (`METHOD_NAME_MAGIC_LINK`).

#### HTTP Response (Success - API Form)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Set-Cookie: ml_binding=; Max-Age=0; Path=/`
  - `Set-Cookie: ak_session=<session_id>; HttpOnly; Secure; SameSite=Lax; Path=/`

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: ml_binding=; Max-Age=0; Path=/
Set-Cookie: ak_session=sess_abcdef1234567890; HttpOnly; Secure; SameSite=Lax; Path=/

{
  "status": "success",
  "identity": {
    "provider_id": "magic-link",
    "external_id": "alice@example.com",
    "attributes": {
      "amr": "magic-link",
      "auth_time": "1700000000"
    }
  }
}
```

#### HTTP Response (Success - Browser Form / Redirect Mode)
- **Status Code**: `303 See Other`
- **Headers**:
  - `Location: /dashboard`
  - `Set-Cookie: ml_binding=; Max-Age=0; Path=/`
  - `Set-Cookie: ak_session=<session_id>; HttpOnly; Secure; SameSite=Lax; Path=/`

---

## 4. OTP (Email & SMS) Endpoints

One-time code authentication (RFC-011) delivers a 6-digit numeric code out-of-band. Because short codes cannot be stored as random keys without leaking enumeration, OTP challenges are **keyed by subject** with an atomic decrement attempt budget (5 attempts max).

---

### 4.1 Request / Mint: `POST /auth/otp/request`

Mints and delivers a 6-digit OTP code to the given subject over the selected channel.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/otp/request`
- **Headers**: `Content-Type: application/json`

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "subject": { "type": "string", "description": "Email address or E.164 phone number" },
    "channel": { "type": "string", "enum": ["email", "sms"], "description": "Delivery channel" }
  },
  "required": ["subject", "channel"]
}
```

#### Example Request
```http
POST /auth/otp/request HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "subject": "+15551234567",
  "channel": "sms"
}
```

#### Server Processing & Rate Limiting (Resend Cooldown)
1. Checks resend cooldown (`with_resend_cooldown`, e.g. 60 seconds) via `AtomicInsert::insert_if_absent`.
2. If another mint occurred within the cooldown window, returns HTTP 429 Too Many Requests (`rate_limited`) with a `Retry-After: 60` header.
3. Generates 6-digit code using unbiased rejection sampling.
4. Replaces any prior active challenge for that subject.
5. Inits attempt counter to 5 attempts.
6. Dispatches delivery out-of-band.

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**: `Content-Type: application/json`

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "pending",
  "channel": "sms",
  "expires_at": 1700000300
}
```

---

### 4.2 Verification: `POST /auth/otp/verify`

Submits the 6-digit code for verification.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/otp/verify`
- **Headers**: `Content-Type: application/json`

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "subject": { "type": "string" },
    "code": { "type": "string", "pattern": "^[0-9]{6}$" }
  },
  "required": ["subject", "code"]
}
```

Or via direct `AuthInput`:
```json
{
  "type": "Otp",
  "data": {
    "subject": "+15551234567",
    "code": "847291"
  }
}
```

#### Example Request
```http
POST /auth/otp/verify HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "type": "Otp",
  "data": {
    "subject": "+15551234567",
    "code": "847291"
  }
}
```

#### Server Processing & Attempt Budgeting
1. Calls `OtpAuthMethod::authenticate(AuthInput::Otp { subject, code })`.
2. Spends attempt budget *before* checking code: calls `store.decrement(counter_key)`.
3. Hashes presented code with SHA-256 and compares constant-time via `subtle::ConstantTimeEq`.
4. If code is wrong:
   - If remaining attempts reach 0, the challenge is **destroyed and deleted immediately** from the store.
   - Returns HTTP 401 Unauthorized (`invalid_credentials`).
5. If code is correct:
   - Calls `store.consume()` to ensure atomic winner among concurrent requests.
   - Cleans up attempt counter key.
   - Returns identity (`provider_id: "otp"`) with `otp_channel`; the HTTP handler stamps `amr: "otp sms"` (or `"otp email"`) and `auth_time` onto session identity attributes.

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Set-Cookie: ak_session=<session_id>; HttpOnly; Secure; SameSite=Lax; Path=/`

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: ak_session=sess_567890abcdef1234; HttpOnly; Secure; SameSite=Lax; Path=/

{
  "status": "success",
  "identity": {
    "provider_id": "otp",
    "external_id": "+15551234567",
    "attributes": {
      "otp_channel": "sms",
      "amr": "otp sms",
      "auth_time": "1700000000"
    }
  }
}
```

---

## 5. Recovery Codes Endpoints

Recovery codes (RFC-012) implement a **look-up secret authenticator** (NIST SP 800-63B §5.1.2) as an account fallback across all registered factors (passkeys, TOTP, magic links, OTP).

---

### 5.1 Generation: `POST /auth/recovery/generate`

Generates a fresh set of recovery codes, replacing any existing set. Gated by `ReproofRequirement`.

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/recovery/generate`
- **Headers**:
  - `Content-Type: application/json`
  - `Cookie: ak_session=<session_id>`

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "count": {
      "type": "integer",
      "minimum": 1,
      "maximum": 20,
      "default": 10,
      "description": "Number of recovery codes to generate"
    }
  }
}
```

#### Example Request
```http
POST /auth/recovery/generate HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Cookie: ak_session=sess_authenticated_user

{
  "count": 10
}
```

#### Server Processing & Re-proof Gate
1. Verifies current identity freshness via `ReproofRequirement::check(&identity)`. If stale or step-up not satisfied, returns HTTP 403 Forbidden (`reproof_required`).
2. Generates 80-bit CSPRNG codes formatted in 4-character base32 groups (e.g. `4KDW-9JMQ-2XPT-R7HV`).
3. Saves normalized hashes (`SHA-256(normalise(code))`) in `CredentialStore`.
4. Retires prior recovery credentials by ID (write-new-then-delete-old ordering prevents leaving accounts with zero recovery paths during transient store errors).
5. Returns plaintext codes. **Warning**: Plaintext codes are displayed only once.

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Cache-Control: no-store`

#### Response Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "codes": {
      "type": "array",
      "items": { "type": "string", "pattern": "^[0-9A-Z]{4}(-[0-9A-Z]{4})+$" }
    },
    "warning": { "type": "string" }
  },
  "required": ["codes"]
}
```

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "codes": [
    "4KDW-9JMQ-2XPT-R7HV",
    "8MNQ-5TRW-1BCZ-9KLA",
    "3DFG-7HYU-4PLM-6QWE",
    "9VBN-2XAZ-8QWE-1RTY",
    "5UIO-3PAS-7DFG-2HJK",
    "1LZX-6CVB-9NMQ-4WER",
    "7TYU-2IOP-5ASD-8FGH",
    "2JKL-4ZXA-1QSC-7VDE",
    "6RFV-9TGB-3YHN-5UJM",
    "8IKM-1OLP-4QAZ-2WSX"
  ],
  "warning": "Save these recovery codes in a secure location. They will not be displayed again."
}
```

---

### 5.2 Redemption: `POST /auth/recovery/redeem`

Redeems one code from the account's unredeemed set. Can be called either as a standalone recovery login or as an MFA step-up continuation factor (`AuthInput::MfaChallenge`).

#### HTTP Request
- **Method**: `POST`
- **Path**: `/auth/recovery/redeem`
- **Headers**: `Content-Type: application/json`

#### Request Body Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "user_id": { "type": "string" },
    "code": { "type": "string", "description": "Recovery code. Case, spaces, and dashes are normalized." }
  },
  "required": ["user_id", "code"]
}
```

Or via direct `AuthInput`:
```json
{
  "type": "RecoveryCode",
  "data": {
    "user_id": "alice@example.com",
    "code": "4kdw 9jmq 2xpt r7hv"
  }
}
```

Or as an MFA continuation factor:
```json
{
  "type": "MfaChallenge",
  "data": {
    "mfa_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "challenge_input": {
      "type": "RecoveryCode",
      "data": {
        "user_id": "alice@example.com",
        "code": "4KDW-9JMQ-2XPT-R7HV"
      }
    }
  }
}
```

#### Server Processing & Atomic Single-Use Contract
1. Calls `RecoveryCodeAuthMethod::authenticate(AuthInput::RecoveryCode { user_id, code })` (or `Engine::authenticate(AuthInput::MfaChallenge { ... })` during second-factor step-up).
2. Normalizes presented code: strips whitespace and hyphens, converts to uppercase.
3. Hashes normalized string with SHA-256.
4. Finds matching unredeemed credential in store (`METHOD_NAME_RECOVERY_CODE` = `"recovery-code"`).
5. Atomically deletes the credential via `CredentialStore::delete_credential`. Per the RFC-012 contract, `delete_credential` returns `true` only to the single winning thread among concurrent redemptions. If `delete_credential` returns `false` or code does not exist, returns HTTP 401 Unauthorized (`invalid_credentials`).
6. Returns authenticated identity (`provider_id: "recovery-code"`) with `amr: "recovery-code"` (`step_up_satisfied: "true"` is additionally stamped when redeemed inside `AuthInput::MfaChallenge`).

#### HTTP Response (Success)
- **Status Code**: `200 OK`
- **Headers**:
  - `Content-Type: application/json`
  - `Set-Cookie: ak_session=<session_id>; HttpOnly; Secure; SameSite=Lax; Path=/`

#### Example Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: ak_session=sess_recovery_session_abc; HttpOnly; Secure; SameSite=Lax; Path=/

{
  "status": "success",
  "identity": {
    "provider_id": "recovery-code",
    "external_id": "alice@example.com",
    "attributes": {
      "amr": "recovery-code",
      "auth_time": "1700000000"
    }
  },
  "remaining_codes": 9
}
```

---

## 6. HTTP Status Codes & Wire Error Shapes

All endpoints return structured error payloads using standard OAuth 2.0 / RFC 6749 and Authkestra wire error semantics.

### 6.1 Wire Error JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "error": {
      "type": "string",
      "enum": [
        "invalid_request",
        "invalid_credentials",
        "invalid_token",
        "reproof_required",
        "rate_limited",
        "device_revoked",
        "server_error"
      ]
    },
    "error_description": {
      "type": "string",
      "description": "Human-readable ASCII text providing additional explanation."
    }
  },
  "required": ["error"]
}
```

### 6.2 Error Code Mapping Table

| HTTP Status | Error Code (`error`) | Description | Common Triggers |
|-------------|----------------------|-------------|-----------------|
| `400 Bad Request` | `invalid_request` | The request is malformed, missing required fields, or violates syntax rules. | Missing required JSON fields, malformed Base64url data, `count = 0` on recovery code generate, `ttl = 0` on OTP mint, unparseable user handle. |
| `401 Unauthorized` | `invalid_credentials` | Credential verification failed or the secret is invalid/expired. | Passkey signature verification failure, wrong OTP code, expired magic link, non-existent or previously consumed recovery code, magic link binding mismatch. |
| `401 Unauthorized` | `invalid_token` | An authentication continuation token or bearer token is invalid, expired, or signature verification failed. | Stale or tampered `mfa_token` JWT submitted to `AuthInput::MfaChallenge`, invalid Bearer authorization header. |
| `403 Forbidden` | `reproof_required` | The current session is not fresh enough or lacks step-up assurance for a security posture change. | Enrolling a passkey or generating recovery codes when `auth_time` is absent, older than `max_age_secs`, or when step-up requirement is not met. |
| `403 Forbidden` | `device_revoked` | The device attestation identity has been revoked. | Reissue requested for a revoked key principal at `/reissue` or device verification. |
| `429 Too Many Requests` | `rate_limited` | Request refused due to rate limiting or active cooldown period. | Requesting an OTP within the resend cooldown window (`AuthError::Throttled`). Response includes `Retry-After: <seconds>`. |
| `500 Internal Server Error` | `server_error` | An unexpected internal server or storage failure occurred. | Database connection failure, unconfigured crypto engine component. Details are redacted in production responses. |

### 6.3 Exact Wire Error Examples

#### 1. `invalid_request` (HTTP 400 Bad Request)
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
X-Content-Type-Options: nosniff
Cache-Control: no-store

{
  "error": "invalid_request",
  "error_description": "Field 'subject' is required and must not be empty."
}
```

#### 2. `invalid_credentials` (HTTP 401 Unauthorized)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
X-Content-Type-Options: nosniff
Cache-Control: no-store

{
  "error": "invalid_credentials",
  "error_description": "Invalid or expired one-time code."
}
```

#### 3. `invalid_token` (HTTP 401 Unauthorized)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
X-Content-Type-Options: nosniff
Cache-Control: no-store

{
  "error": "invalid_token",
  "error_description": "MFA continuation token has expired or is invalid."
}
```

#### 4. `reproof_required` (HTTP 403 Forbidden)
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Content-Type-Options: nosniff
Cache-Control: no-store

{
  "error": "reproof_required",
  "error_description": "Recent authentication required: session is stale (older than 300 seconds)."
}
```

#### 5. `rate_limited` (HTTP 429 Too Many Requests)
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-Content-Type-Options: nosniff
Cache-Control: no-store
Retry-After: 60

{
  "error": "rate_limited",
  "error_description": "Resend cooldown active. Please wait before requesting another code."
}
```

---

## 7. Standard HTTP Headers & CORS Compliance

### 7.1 Response Headers
All JSON responses from Authkestra authentication endpoints must include:
- `Content-Type: application/json`
- `Cache-Control: no-store` (prevents caching of challenges, tokens, or security responses)
- `X-Content-Type-Options: nosniff` (mitigates MIME-type confusion attacks)
- `Retry-After: <seconds>` (mandatory on HTTP 429 responses)

### 7.2 CORS & Header Exposure
When Authkestra runs as an authentication API consumed by browser Single Page Applications (SPAs) on a different domain, cross-origin resource sharing headers must expose custom response headers:
```http
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: DPoP-Nonce, Retry-After
```
Browsers silently drop access to `DPoP-Nonce` and `Retry-After` unless `Access-Control-Expose-Headers` explicitly permits them.

---

## 8. Implementing Across Axum vs Actix-web

The reference passwordless endpoints (implemented in `crates/authkestra/examples/axum_passwordless_server.rs`) map directly onto both web framework crates:

### 8.1 Framework Route Mapping Comparison

| Aspect | `authkestra-axum` | `authkestra-actix` |
|--------|-------------------|--------------------|
| State Extraction | `axum::extract::State(state)` | `actix_web::web::Data(data)` |
| JSON Extractor | `axum::Json(payload)` | `actix_web::web::Json(payload)` |
| Cookie Management | `tower_cookies::Cookies` | `actix_web::HttpRequest::cookie()` / `HttpResponseBuilder::cookie()` |
| Error Conversion | `impl axum::response::IntoResponse for AxumError` | `impl actix_web::ResponseError for ActixError` |
| JSON Body Response | `(StatusCode::OK, Json(resp)).into_response()` | `HttpResponse::Ok().json(resp)` |
| Error Body Response | `(StatusCode::BAD_REQUEST, Json(err)).into_response()` | `HttpResponse::BadRequest().json(err)` |

Both framework implementations deserialize and serialize identical serde data structures, guaranteeing identical wire formats for external clients (e.g. `fespalier`, mobile apps, SPAs).
