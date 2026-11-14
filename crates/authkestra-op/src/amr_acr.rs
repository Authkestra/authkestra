//! `acr`/`amr` claim derivation for issued ID tokens (OIDC Core §2).
//!
//! `authkestra_engine::Engine::authenticate` is the only place that knows
//! which [`AuthMethod`](authkestra_engine::auth::AuthMethod) actually ran —
//! the primary one, and (if the caller completed one) a step-up. It has no
//! reason to know about OIDC claim vocabulary, so it stamps that fact onto
//! [`Identity::attributes`] instead, under the
//! [`IDENTITY_ATTR_AMR`](authkestra_engine::auth::IDENTITY_ATTR_AMR) /
//! [`IDENTITY_ATTR_STEP_UP_SATISFIED`](authkestra_engine::auth::IDENTITY_ATTR_STEP_UP_SATISFIED)
//! keys — the same established idiom `identity.attributes["nonce"]` already
//! uses to thread flow-local data through `Identity` without changing its
//! shape (see `authkestra_engine::flow::oauth2`). This module is the other
//! end: it turns those attributes into the two standard OIDC ID token
//! claims when an issued token's identity carries them.
//!
//! See `docs/rfc-006-acr-amr-claims.md` for the full design rationale.
//!
//! ## AMR value set
//!
//! `authkestra-engine`'s internal auth-method names (`"password"`, `"totp"`,
//! `"webauthn"`) are remapped to the wire values below, moving closer to the
//! IANA registry in RFC 8176 where a value already fits it exactly:
//!
//! - `"password"` → [`AMR_PASSWORD`] (`"pwd"`, RFC 8176's canonical token).
//! - `"totp"` emits **both** [`AMR_OTP`] (`"otp"`, the RFC 8176 registry
//!   term) and [`AMR_TOTP`] (`"totp"`, the specific one). `amr` is an array,
//!   so there is nothing to trade off: a relying party matching strictly
//!   against the registry — which off-the-shelf RP libraries commonly do —
//!   finds `"otp"` and recognises the factor, while a consumer that cares
//!   reads `"totp"` and learns what `"otp"` alone loses (not HOTP, not a
//!   mailed or SMS code). Emitting only the specific value would leave the
//!   strict matcher seeing a token that names no second factor it knows.
//! - `"webauthn"` stays `"webauthn"`: RFC 8176 has `"hwk"` (hardware key)
//!   and `"swk"` (software key), but this crate's WebAuthn integration
//!   doesn't distinguish a roaming authenticator from a platform one, so
//!   asserting either would overclaim what was actually verified.
//!   `"webauthn"` names the actual mechanism without guessing.
//! - [`AMR_MFA_MARKER`] (RFC 8176's own generic multi-factor marker,
//!   `"mfa"`) is appended whenever [`ACR_MFA`] applies (see below),
//!   mirroring how several production IdPs report both the constituent
//!   method(s) and this summary value together.
//! - Any other internal method name (a custom
//!   [`AuthMethod`](authkestra_engine::auth::AuthMethod) an integrator
//!   registered) passes through unchanged — this crate has no way to know
//!   what it should map to, and passing it through verbatim is more honest
//!   than dropping it.
//!
//! ## ACR scheme
//!
//! `authkestra-engine`'s step-up model is binary — primary auth, or
//! primary+step-up — so `acr` is too: exactly two self-issued URN values,
//! [`ACR_SINGLE_FACTOR`] and [`ACR_MFA`]. This is deliberately *not* a NIST
//! SP 800-63 AAL1/2/3 ladder or an eIDAS LoA scheme: this engine cannot back
//! a claim that specific (no phishing-resistance attestation, no identity
//! proofing tier, no re-authentication/`max_age` freshness tracking), and a
//! relying party parsing an AAL-shaped string that doesn't mean what AAL
//! means would be actively misled.
//!
//! An identity whose `attributes` carry no `amr` at all — e.g. one that
//! never passed through `Engine::authenticate` at all, such as a federated
//! login handed straight to `handle_authorize` — gets neither claim:
//! omitting `acr`/`amr` is legal per OIDC Core §2 (both OPTIONAL), and
//! asserting a scheme this crate has no evidence for would be worse than
//! saying nothing.
//!
//! ## `auth_time`
//!
//! Derived independently of `acr`/`amr` from
//! [`IDENTITY_ATTR_AUTH_TIME`](authkestra_engine::auth::IDENTITY_ATTR_AUTH_TIME):
//! "how recently did this user prove themselves" is a different question from
//! "with what", and OIDC Core §2 defines all three as separate OPTIONAL
//! claims. For a login that completed a step-up it is when the *step-up*
//! finished — the most recent proof, which is what a re-authentication gate
//! asking "prove it again within N seconds" actually needs.
//!
//! Because the value rides on the `Identity`, a token minted later by the
//! refresh-token or token-exchange grant reports when the user originally
//! authenticated rather than when that token was issued — which is what
//! `auth_time` is defined to mean, and the reason it is not simply `now()`
//! at issuance time.
//!
//! Enforcing freshness — honouring a `max_age` request parameter or
//! `prompt=login` — is deliberately *not* here; this is the observability
//! half. See issue #381.

use authkestra_engine::auth::state::{
    Identity, IDENTITY_ATTR_AMR, IDENTITY_ATTR_AUTH_TIME, IDENTITY_ATTR_OTP_CHANNEL,
    IDENTITY_ATTR_STEP_UP_SATISFIED, METHOD_NAME_MAGIC_LINK, METHOD_NAME_OTP, METHOD_NAME_PASSWORD,
    METHOD_NAME_RECOVERY_CODE, METHOD_NAME_TOTP, METHOD_NAME_WEBAUTHN, OTP_CHANNEL_SMS,
};
use std::collections::HashMap;

/// `acr` value for a token backed only by primary authentication — no
/// step-up ran, and the primary method itself isn't step-up-equivalent.
pub const ACR_SINGLE_FACTOR: &str = "urn:authkestra:acr:single-factor";

/// `acr` value for a token backed by step-up: either a completed step-up
/// (MFA) challenge on top of primary auth, or a single primary
/// [`AuthMethod`](authkestra_engine::auth::AuthMethod) that itself reports
/// [`is_mfa_equivalent`](authkestra_engine::auth::AuthMethod::is_mfa_equivalent)
/// (e.g. this engine's built-in WebAuthn method used as a primary).
pub const ACR_MFA: &str = "urn:authkestra:acr:mfa";

/// RFC 8176's own generic "multiple-factor" AMR value.
pub const AMR_MFA_MARKER: &str = "mfa";

/// The RFC 8176 token for password authentication — `authkestra-engine`'s
/// internal auth-method name for the same thing is `"password"`.
pub const AMR_PASSWORD: &str = "pwd";

/// RFC 8176's generic one-time-password value. Emitted alongside [`AMR_TOTP`]
/// for a TOTP factor so that a relying party matching strictly against the
/// registry still recognises the factor.
pub const AMR_OTP: &str = "otp";

/// RFC 8176's value for a code delivered by SMS. Emitted alongside
/// [`AMR_OTP`] when, and only when, the identity says that is how the code
/// travelled — an emailed code claiming `sms` would be a plain falsehood
/// about the channel a relying party may well be making decisions on.
pub const AMR_SMS: &str = "sms";

/// The specific value for a TOTP factor, emitted alongside [`AMR_OTP`]. Not
/// an RFC 8176 registry entry — the registry is explicitly extensible — and
/// it carries what `"otp"` alone loses: this was TOTP, not HOTP and not a
/// mailed or SMS code.
pub const AMR_TOTP: &str = "totp";

/// What each first-party auth-method name emits on the wire.
///
/// A table rather than a `match` arm so a test can read it. Every name in
/// [`FIRST_PARTY_METHOD_NAMES`] must appear here, which is what stops a new
/// built-in method from silently inheriting the pass-through below — see
/// `every_first_party_method_name_has_a_deliberate_mapping` and issue #395.
///
/// A row that repeats the method's own name is a *decision to pass through*,
/// not a missing mapping. The two are indistinguishable in behaviour and
/// entirely different in meaning, and the difference is the reason this
/// table exists.
const FIRST_PARTY_AMR: &[(&str, &[&str])] = &[
    (METHOD_NAME_PASSWORD, &[AMR_PASSWORD]),
    // Both, deliberately. `"otp"` is the RFC 8176 registry term, and a
    // relying party matching strictly against the registry — which
    // off-the-shelf RP libraries commonly do — would otherwise see a
    // token naming no second factor it recognises. `"totp"` carries the
    // detail the registry term loses (not HOTP, not a mailed or SMS
    // code). `amr` is an array, so there is no reason to choose: the
    // strict matcher finds `"otp"`, and a consumer that cares about the
    // distinction reads `"totp"`.
    (METHOD_NAME_TOTP, &[AMR_OTP, AMR_TOTP]),
    // Pass-through, chosen rather than fallen into. RFC 8176 has `"hwk"`
    // and `"swk"`, but this workspace's WebAuthn integration cannot tell a
    // roaming authenticator from a platform one, so either would overclaim
    // what was verified. The factor is not invisible to a strict matcher
    // regardless: WebAuthn reports `is_mfa_equivalent`, so `AMR_MFA_MARKER`
    // is always appended alongside it.
    (METHOD_NAME_WEBAUTHN, &[METHOD_NAME_WEBAUTHN]),
    // Pass-through, and for once the registry genuinely offers nothing.
    // RFC 8176 has no value meaning "followed a link sent to an inbox":
    // `"otp"` would be a lie, since nothing here is a one-time *password*
    // and nothing is typed, and `"mfa"` is unavailable because magic link
    // reports `is_mfa_equivalent() == false` — proving control of an inbox
    // is one factor. So a strict registry matcher sees no factor it
    // recognises, correctly: there isn't one.
    //
    // Email/SMS OTP, next on the same track, is the opposite case and must
    // not copy this row. `"otp"` fits it exactly, and pass-through there
    // would hide a real second factor from every RP that matches strictly.
    (METHOD_NAME_MAGIC_LINK, &[METHOD_NAME_MAGIC_LINK]),
    // The base mapping, and the case #395 was written for: a delivered code
    // is exactly what RFC 8176's `"otp"` means, so passing `"otp"` through as
    // its own name — which is what the fall-through would have done — happens
    // to be right here by coincidence rather than by decision. The row says
    // it is a decision.
    //
    // A code delivered by SMS additionally claims `"sms"`, which this table
    // cannot express because it cannot see the channel. That refinement is in
    // `amr_acr_extra_claims`, which can.
    (METHOD_NAME_OTP, &[AMR_OTP]),
    // Pass-through, and the registry genuinely offers nothing. RFC 8176 has
    // no value for a look-up secret: `"otp"` would be a lie (this is neither
    // one-time-password machinery nor time-based), and `"mfa"` is ruled out
    // because recovery codes report `is_mfa_equivalent() == false` — whoever
    // holds the paper holds the account.
    //
    // Same call as magic link's row, for the same reason: name the mechanism
    // rather than overclaim a registry term.
    (METHOD_NAME_RECOVERY_CODE, &[METHOD_NAME_RECOVERY_CODE]),
];

/// Remaps an `authkestra-engine` internal auth-method name to its wire AMR
/// value. See the module docs for the reasoning behind each mapping.
///
/// An unrecognised name passes through unchanged. That is correct for a
/// custom [`AuthMethod`](authkestra_engine::auth::AuthMethod) an integrator
/// registered — this crate has no way to know what it should map to — and is
/// prevented from quietly applying to first-party methods by
/// [`FIRST_PARTY_AMR`].
fn internal_method_to_amr(method: &str) -> Vec<String> {
    FIRST_PARTY_AMR
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, values)| values.iter().map(|v| v.to_string()).collect())
        .unwrap_or_else(|| vec![method.to_string()])
}

/// Builds the `amr`/`acr` entries for an `extra` claims map (as taken by
/// [`TokenManager::issue_id_token_with_extra`](authkestra_engine::token::TokenManager::issue_id_token_with_extra))
/// from the auth-method bookkeeping `Engine::authenticate` stamped onto
/// `identity.attributes`.
///
/// Returns an empty map — no `amr`, no `acr` — when `identity.attributes`
/// carries no [`IDENTITY_ATTR_AMR`] entry, which is the case for any
/// `Identity` that didn't come from `Engine::authenticate` (see the module
/// docs).
pub fn amr_acr_extra_claims(identity: &Identity) -> HashMap<String, serde_json::Value> {
    let mut extra = HashMap::new();

    // `auth_time` is derived independently of `amr`: it answers "how recently
    // did this user prove themselves", which is a different question from
    // "with what", and OIDC Core §2 defines them as separate OPTIONAL claims.
    // A malformed value is dropped rather than guessed at — emitting a
    // non-numeric or unparseable `auth_time` would be worse than omitting it,
    // since a relying party comparing it against `max_age` would get a
    // nonsense answer instead of a missing one.
    if let Some(parsed) = identity
        .attributes
        .get(IDENTITY_ATTR_AUTH_TIME)
        .and_then(|raw| raw.parse::<i64>().ok())
    {
        extra.insert("auth_time".to_string(), serde_json::json!(parsed));
    }

    let Some(raw_amr) = identity.attributes.get(IDENTITY_ATTR_AMR) else {
        return extra;
    };

    let mut amr: Vec<String> = raw_amr
        .split_whitespace()
        .flat_map(internal_method_to_amr)
        .collect();

    let step_up_satisfied = identity
        .attributes
        .get(IDENTITY_ATTR_STEP_UP_SATISFIED)
        .map(|v| v == "true")
        .unwrap_or(false);

    // The channel refinement the static table cannot make. RFC 8176 registers
    // `sms` as its own value, so a texted code claims both it and `otp` —
    // more specific first, matching how the `totp` row orders its pair. An
    // emailed code must not claim `sms`, which is the whole reason the
    // channel rides on the identity at all.
    if amr.iter().any(|m| m == AMR_OTP)
        && identity
            .attributes
            .get(IDENTITY_ATTR_OTP_CHANNEL)
            .is_some_and(|c| c == OTP_CHANNEL_SMS)
        && !amr.iter().any(|m| m == AMR_SMS)
    {
        let at = amr.iter().position(|m| m == AMR_OTP).unwrap_or(0);
        amr.insert(at, AMR_SMS.to_string());
    }

    if step_up_satisfied && !amr.iter().any(|m| m == AMR_MFA_MARKER) {
        amr.push(AMR_MFA_MARKER.to_string());
    }

    extra.insert(
        "amr".to_string(),
        serde_json::Value::Array(amr.into_iter().map(serde_json::Value::String).collect()),
    );
    extra.insert(
        "acr".to_string(),
        serde_json::Value::String(
            if step_up_satisfied {
                ACR_MFA
            } else {
                ACR_SINGLE_FACTOR
            }
            .to_string(),
        ),
    );

    extra
}

/// Builds the full `extra` claims map for an issued ID token, combining
/// [`amr_acr_extra_claims`] (`auth_time`, `acr`, `amr` from `raw_identity`)
/// with the standard OIDC Core §5.1 top-level profile and email claims
/// (`email`, `email_verified`, `name`, `preferred_username`) survived on
/// `sanitized_identity` after
/// [`sanitize_identity_for_scopes`](authkestra_engine::token::sanitize_identity_for_scopes).
///
/// Relying parties reading top-level OIDC claims (rather than Authkestra's
/// nested `identity` object) see the same scope-gated `email`,
/// `email_verified`, `name`, and `preferred_username` claims on the ID token
/// that `/userinfo` returns (issue #445).
pub fn id_token_extra_claims(
    raw_identity: &Identity,
    sanitized_identity: &Identity,
) -> HashMap<String, serde_json::Value> {
    let mut extra = amr_acr_extra_claims(raw_identity);

    if let Some(email) = sanitized_identity
        .email
        .as_ref()
        .or_else(|| sanitized_identity.attributes.get("email"))
        .filter(|s| !s.is_empty())
    {
        extra.insert(
            "email".to_string(),
            serde_json::Value::String(email.clone()),
        );
    }

    if let Some(verified) = sanitized_identity
        .attributes
        .get("email_verified")
        .and_then(|raw| raw.parse::<bool>().ok())
    {
        extra.insert(
            "email_verified".to_string(),
            serde_json::Value::Bool(verified),
        );
    }

    if let Some(name) = sanitized_identity
        .attributes
        .get("name")
        .or(sanitized_identity.username.as_ref())
        .filter(|s| !s.is_empty())
    {
        extra.insert("name".to_string(), serde_json::Value::String(name.clone()));
    }

    if let Some(preferred_username) = sanitized_identity
        .attributes
        .get("preferred_username")
        .or(sanitized_identity.username.as_ref())
        .filter(|s| !s.is_empty())
    {
        extra.insert(
            "preferred_username".to_string(),
            serde_json::Value::String(preferred_username.clone()),
        );
    }

    extra
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_engine::auth::state::FIRST_PARTY_METHOD_NAMES;
    use std::collections::HashMap as StdHashMap;

    /// The guard for issue #395.
    ///
    /// `internal_method_to_amr` passes an unrecognised name through
    /// unchanged, which is right for a custom method an integrator
    /// registered and wrong for one this workspace ships — and nothing in
    /// the behaviour distinguishes them. So the engine lists its own method
    /// names, and this asserts each has a row here.
    ///
    /// If you added a built-in method and this failed: decide what it emits
    /// on the wire and add it to `FIRST_PARTY_AMR`. Passing the name through
    /// may well be the right answer (it is for WebAuthn), but it should be a
    /// row that says so rather than a default nobody chose. Email/SMS OTP is
    /// the case where it would be wrong — `"otp"` fits it exactly.
    #[test]
    fn every_first_party_method_name_has_a_deliberate_mapping() {
        for name in FIRST_PARTY_METHOD_NAMES {
            assert!(
                FIRST_PARTY_AMR.iter().any(|(mapped, _)| mapped == name),
                "`{name}` is a first-party auth method with no row in \
                 FIRST_PARTY_AMR, so it would fall through to pass-through \
                 by default rather than by decision. See issue #395."
            );
        }
    }

    /// The table is the source of the mapping, so a duplicate row would make
    /// the second one dead code that looks live.
    #[test]
    fn an_emailed_code_claims_otp_but_never_sms() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, METHOD_NAME_OTP),
            (IDENTITY_ATTR_OTP_CHANNEL, "email"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["otp"])));
    }

    #[test]
    fn a_texted_code_claims_sms_before_otp() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, METHOD_NAME_OTP),
            (IDENTITY_ATTR_OTP_CHANNEL, OTP_CHANNEL_SMS),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["sms", "otp"])));
    }

    /// A code with no channel recorded claims `otp` and nothing more. It must
    /// not guess, since `sms` is a statement about how the secret travelled.
    #[test]
    fn a_code_with_no_channel_does_not_guess_one() {
        let identity = identity_with(&[(IDENTITY_ATTR_AMR, METHOD_NAME_OTP)]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["otp"])));
    }

    /// The channel attribute is meaningless without an `otp` factor, and must
    /// not conjure one onto an unrelated login.
    #[test]
    fn the_channel_alone_adds_nothing_to_another_method() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, METHOD_NAME_PASSWORD),
            (IDENTITY_ATTR_OTP_CHANNEL, OTP_CHANNEL_SMS),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["pwd"])));
    }

    #[test]
    fn the_amr_table_names_each_method_once() {
        let mut seen: Vec<&str> = Vec::new();
        for (name, _) in FIRST_PARTY_AMR {
            assert!(!seen.contains(name), "`{name}` appears twice");
            seen.push(name);
        }
    }

    /// Pins the pass-through that is *not* covered by the table: a method
    /// this crate has never heard of still reaches the wire under its own
    /// name rather than being dropped.
    #[test]
    fn an_unknown_custom_method_still_passes_through() {
        assert_eq!(
            internal_method_to_amr("acme-badge-reader"),
            vec!["acme-badge-reader".to_string()]
        );
    }

    fn identity_with(attrs: &[(&str, &str)]) -> Identity {
        let mut attributes = StdHashMap::new();
        for (k, v) in attrs {
            attributes.insert(k.to_string(), v.to_string());
        }
        Identity {
            provider_id: "test".to_string(),
            external_id: "user-1".to_string(),
            email: None,
            username: None,
            attributes,
        }
    }

    #[test]
    fn no_amr_attribute_produces_no_claims() {
        let identity = identity_with(&[]);
        let extra = amr_acr_extra_claims(&identity);
        assert!(extra.is_empty());
    }

    #[test]
    fn primary_only_maps_to_single_factor() {
        let identity = identity_with(&[(IDENTITY_ATTR_AMR, "password")]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["pwd"])));
        assert_eq!(
            extra.get("acr"),
            Some(&serde_json::Value::String(ACR_SINGLE_FACTOR.to_string()))
        );
    }

    #[test]
    fn step_up_completed_adds_the_mfa_marker_and_acr() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, "password totp"),
            (IDENTITY_ATTR_STEP_UP_SATISFIED, "true"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        // TOTP contributes both the registry term and the specific one, so a
        // relying party matching strictly on RFC 8176 still recognises it.
        assert_eq!(
            extra.get("amr"),
            Some(&serde_json::json!(["pwd", "otp", "totp", "mfa"]))
        );
        assert_eq!(
            extra.get("acr"),
            Some(&serde_json::Value::String(ACR_MFA.to_string()))
        );
    }

    /// A relying party that only knows RFC 8176's registry must still find a
    /// value it recognises for a TOTP second factor — that is the whole point
    /// of emitting `"otp"` alongside `"totp"`.
    #[test]
    fn totp_emits_the_registry_term_alongside_the_specific_one() {
        let identity = identity_with(&[(IDENTITY_ATTR_AMR, "totp")]);
        let extra = amr_acr_extra_claims(&identity);
        let amr = extra.get("amr").expect("amr present");
        assert_eq!(amr, &serde_json::json!(["otp", "totp"]));
        assert!(
            amr.as_array().unwrap().contains(&serde_json::json!("otp")),
            "a strict RFC 8176 matcher must find a value it knows"
        );
    }

    #[test]
    fn auth_time_is_emitted_as_a_number_when_present() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, "password"),
            (IDENTITY_ATTR_AUTH_TIME, "1757843000"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("auth_time"), Some(&serde_json::json!(1757843000)));
    }

    /// `auth_time` answers a different question from `amr`, so it is derived
    /// independently — an identity carrying one but not the other still gets
    /// what it can support.
    #[test]
    fn auth_time_is_independent_of_amr() {
        let only_auth_time = identity_with(&[(IDENTITY_ATTR_AUTH_TIME, "1757843000")]);
        let extra = amr_acr_extra_claims(&only_auth_time);
        assert_eq!(extra.get("auth_time"), Some(&serde_json::json!(1757843000)));
        assert_eq!(extra.get("amr"), None);
        assert_eq!(extra.get("acr"), None);

        let only_amr = identity_with(&[(IDENTITY_ATTR_AMR, "password")]);
        let extra = amr_acr_extra_claims(&only_amr);
        assert_eq!(extra.get("auth_time"), None);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["pwd"])));
    }

    /// An unparseable timestamp is dropped rather than guessed at: a relying
    /// party comparing a nonsense `auth_time` against `max_age` would get a
    /// wrong answer, where a missing one it can detect and handle.
    #[test]
    fn a_malformed_auth_time_is_omitted_rather_than_emitted() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, "password"),
            (IDENTITY_ATTR_AUTH_TIME, "not-a-timestamp"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("auth_time"), None);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["pwd"])));
    }

    #[test]
    fn mfa_equivalent_primary_alone_still_reports_acr_mfa() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, "webauthn"),
            (IDENTITY_ATTR_STEP_UP_SATISFIED, "true"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(
            extra.get("amr"),
            Some(&serde_json::json!(["webauthn", "mfa"]))
        );
        assert_eq!(
            extra.get("acr"),
            Some(&serde_json::Value::String(ACR_MFA.to_string()))
        );
    }

    #[test]
    fn unrecognized_internal_method_names_pass_through_verbatim() {
        let identity = identity_with(&[(IDENTITY_ATTR_AMR, "sms_link")]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["sms_link"])));
    }
}
