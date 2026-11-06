//! The generator of `conformance/devsig-profile-v1/vectors.json`.
//!
//! Every key here is a **fixed test key** (derived from a constant, or the PEM below), and every
//! signature algorithm used is deterministic (ES256 through RFC 6979, Ed25519, RSA PKCS#1 v1.5),
//! so running the generator twice writes the same bytes. `profile_v1.rs` regenerates the file in
//! memory and fails when the committed copy differs; `AUTHKESTRA_UPDATE_VECTORS=1` writes it.
//!
//! **The expectations are written here by hand, never computed by running the verifier** — a
//! vector whose expected outcome came from the code under test would test nothing.
//!
//! None of these keys protects anything: they exist so other implementations can check that
//! they reach the same verdicts, and so a maintainer can add a vector. Never trust them.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{crypto, Algorithm, EncodingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The instant every vector is checked at: 2027-01-01T00:00:00Z.
pub const NOW: i64 = 1_798_761_600;

pub const ISSUER: &str = "https://issuer.example";
pub const OTHER_ISSUER: &str = "https://evil.example";
pub const AUDIENCE: &str = "https://api.example";
pub const SUBJECT: &str = "user-7f3a9c12";
pub const DEVICE: &str = "dev-8821bc04";
pub const ATTESTATION_TYP: &str = "webank-attest+jws";

/// Test-only RS256 issuer key. Fixed so the vectors are reproducible; it protects nothing.
const RS256_ISSUER_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD76aCNgcdhMRlN
07vKPEPvP1u8R8xs1R0uzb2Ldn3xmrKo9YEbM7zHInUzKM6JGnnMCgfYbHWO9atT
VnrREfSwa25I8zMLAPDNBQAefNoIKssz6XaFAn+6Ia5LeIJYWIbLFB2l4BToGrPI
ZLO9wULu++BT+g7K2UKYyeYJ3sIpF1/O/8IygrQDwoe+dgd3X/phg1SSlrfYbkjv
ZwIlkxkV0I+EZt6SbqfN+WnOhDsm5FVdYSLofCAjhfcMZmnwWeTJ0WHnejH3hURt
be1pWLEr+4HgsIrB2tfujTRRYylCd0fiEUvsBnUgiaDS2z2AG/JqYPniWXTHYQeP
Bbi8B3oZAgMBAAECggEAEkJ1Fii86Vs4GrNxIlezs2bv6PH52/4nFT5Jwc8DEkUM
s/FGrFB326XQYbbQoLC7+RmVh78V1tjRFDN5p8ehyTtiRTSmo6Kr8apt/6e8XJjw
fXjr07iShkz8b6FCrnFtRNFWlFBNp6TO2QTOn/+fEMhOUnv2wEaW/JDu5RKB151C
rpQ23jSMxLx9G8VvFiuKSS1iU/Sf8OTz4C0bueDSnzIahtj3rJyTmxd4mdBR8XAV
+xdwKKeGrZJ/i5iV/DDK0/2HyKV+8lb/ayDM9WudTFIka8/VB7WeQCuC3Ke9loly
vKnmVv9IS29YE9PgdkMIuQxDS3mso/F38gCfJ9nx0QKBgQD+iyT4ZslSzkQTDezc
FVJgObDqFUVF/onnXsfKwKCoWymJ5K/Udbh05oaysT774fHwroGx3fpyuXMj540a
/TPczluFtPatrJzIDXjObk2uWb/jTs1D2Yn8tYCN2N9T0BPfGbFT6oAKQw5Neun3
hgEKg+E7/muBFPSy7Z/vO5Pi6QKBgQD9WqEDh8JamUPbuI51WU11QXwfoXzpuQZP
knENDPRoR+FoNKe2lZn7cRSLdg8wGUYW779zaECnconPAm7GqMqsHhDSKEzFwhjA
RSKbTQGpp/qui0ys0aIotWTyt4HmnAYEDHOOylPwpK/qTvcm6kSr+7SmhdFzfDQW
oYrNJcZ/sQKBgQDZp1NikEmf474z6NlbS2QX4dzUHIISmteCnvoJ9fKqYuE/BuwO
qOakFyagj40Cxq4hlqZR2DS6erbowatXo6EAMvfxec7grNOXAGYHZixIZHf/Pzen
x9EE5JJbOFGmkisbvxVxYvg/Th1hxTNgsxYazq/+o8t7IdcnVKdIYlJPWQKBgFsB
U/cFq/2JMkPZnmpuopEs7Z4bDtiRmr+4dZ1feud+cmxRBbFjOYWFUADsbnYzjeat
RdL5rse3L+NJF2uKtApxXk9vJGyg1O0zqEOqvJ8pdLV/2hH1107SIanB2wpwHwUT
R+sRqGc3cO00Yjj7S6GPb4ulY+AczEUYz9fy6sNxAoGBAJ4GAPAdFjQGGVYL+Gyl
EnTo6yMtr5GFyj7jfIgZ3OuvBOjbK/gAjGR0LvTWuEmP39hD8syWAx4wNXiXLpMd
2dbFRFjSHP7Q+NDbbc6XDH7zs8iAphevSEcvO5HOb4I+T2CrfH51iNVpkydv6+PF
Bme708uVnhzVSbG9qN6kD9Nk
-----END PRIVATE KEY-----
";

/// A fixed key: its private half, its public JWK (exactly what goes on the wire, members in
/// RFC 7638 order), and the algorithm it signs with.
#[derive(Clone)]
pub struct Key {
    pub alg: Algorithm,
    pub encoding: EncodingKey,
    pub jwk: Value,
}

impl Key {
    /// A P-256 key whose scalar is `SHA-256(label)`.
    pub fn es256(label: &str) -> Self {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::EncodePrivateKey;

        let secret = p256::SecretKey::from_slice(&Sha256::digest(label.as_bytes()))
            .expect("a SHA-256 digest is a valid P-256 scalar with overwhelming probability");
        let pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode P-256 key");
        let point = secret.public_key().to_encoded_point(false);
        Self {
            alg: Algorithm::ES256,
            encoding: EncodingKey::from_ec_pem(pem.as_bytes()).expect("EC encoding key"),
            jwk: json!({
                "crv": "P-256",
                "kty": "EC",
                "x": b64url(point.x().expect("uncompressed x")),
                "y": b64url(point.y().expect("uncompressed y")),
            }),
        }
    }

    /// An Ed25519 key whose seed is `SHA-256(label)`.
    pub fn eddsa(label: &str) -> Self {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let der = signing.to_pkcs8_der().expect("encode Ed25519 key");
        Self {
            alg: Algorithm::EdDSA,
            encoding: EncodingKey::from_ed_der(der.as_bytes()),
            jwk: json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": b64url(signing.verifying_key().as_bytes()),
            }),
        }
    }

    /// The fixed RSA-2048 key above, signing RS256.
    pub fn rs256() -> Self {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;

        let private = rsa::RsaPrivateKey::from_pkcs8_pem(RS256_ISSUER_TEST_KEY).expect("RSA key");
        let public = private.to_public_key();
        Self {
            alg: Algorithm::RS256,
            encoding: EncodingKey::from_rsa_pem(RS256_ISSUER_TEST_KEY.as_bytes())
                .expect("RSA encoding key"),
            jwk: json!({
                "e": b64url(&public.e().to_bytes_be()),
                "kty": "RSA",
                "n": b64url(&public.n().to_bytes_be()),
            }),
        }
    }

    /// The RFC 7638 SHA-256 thumbprint of the public JWK.
    pub fn thumbprint(&self) -> String {
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(self.jwk.clone()).expect("public jwk parses");
        jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .expect("thumbprint")
    }
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A compact JWS over `header` and `claims`, signed by `key` with `key.alg`.
pub fn jws(header: &Value, claims: &Value, key: &Key) -> String {
    let input = format!(
        "{}.{}",
        b64url(canonical(header).as_bytes()),
        b64url(canonical(claims).as_bytes())
    );
    let signature = crypto::sign(input.as_bytes(), &key.encoding, key.alg).expect("sign");
    format!("{input}.{signature}")
}

fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::ES256 => "ES256",
        Algorithm::EdDSA => "EdDSA",
        Algorithm::RS256 => "RS256",
        _ => unreachable!("the vectors only use ES256, EdDSA and RS256"),
    }
}

/// One issuer signing key: who publishes it, under which `kid`.
pub struct IssuerKey {
    pub iss: &'static str,
    pub kid: &'static str,
    pub key: Key,
}

/// Everything the vectors are minted with.
pub struct Mint {
    pub es256: IssuerKey,
    pub eddsa: IssuerKey,
    pub rs256: IssuerKey,
    /// Signs attestations with a trusted `kid` but is not that `kid`'s key.
    pub impostor: Key,
    pub device: Key,
    pub device_user_present: Key,
    pub device_eddsa: Key,
    pub attacker: Key,
}

impl Mint {
    pub fn new() -> Self {
        Self {
            es256: IssuerKey {
                iss: ISSUER,
                kid: "issuer-es256-2027",
                key: Key::es256("authkestra devsig-profile-v1 issuer es256"),
            },
            eddsa: IssuerKey {
                iss: ISSUER,
                kid: "issuer-eddsa-2027",
                key: Key::eddsa("authkestra devsig-profile-v1 issuer eddsa"),
            },
            rs256: IssuerKey {
                iss: ISSUER,
                kid: "issuer-rs256-2027",
                key: Key::rs256(),
            },
            impostor: Key::es256("authkestra devsig-profile-v1 impostor issuer"),
            device: Key::es256("authkestra devsig-profile-v1 device ambient"),
            device_user_present: Key::es256("authkestra devsig-profile-v1 device user-present"),
            device_eddsa: Key::eddsa("authkestra devsig-profile-v1 device eddsa"),
            attacker: Key::es256("authkestra devsig-profile-v1 attacker"),
        }
    }

    /// The claims of a valid attestation binding `device`.
    pub fn attestation_claims(&self, device: &Key) -> Value {
        json!({
            "att": { "status": "active" },
            "cnf": { "jkt": device.thumbprint() },
            "did": DEVICE,
            "exp": NOW + 82_800,
            "iat": NOW - 3_600,
            "iss": ISSUER,
            "sub": SUBJECT,
        })
    }

    /// An attestation over `claims`, by `issuer`, with `kid` in the header.
    pub fn attestation_with(
        &self,
        issuer: &IssuerKey,
        kid: Option<&str>,
        claims: &Value,
    ) -> String {
        let mut header = json!({ "alg": alg_name(issuer.key.alg), "typ": ATTESTATION_TYP });
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        jws(&header, claims, &issuer.key)
    }

    /// The ES256 issuer's attestation for `device`.
    pub fn attestation(&self, device: &Key) -> String {
        self.attestation_with(
            &self.es256,
            Some(self.es256.kid),
            &self.attestation_claims(device),
        )
    }

    /// The claims of a fresh request signature for `method` `path`, with `qsh`/`bdh` when there
    /// is a query/body.
    pub fn signature_claims(
        &self,
        jti: &str,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: Option<&str>,
    ) -> Value {
        let mut claims = json!({
            "aud": AUDIENCE,
            "exp": NOW + 110,
            "iat": NOW - 10,
            "jti": jti,
            "mth": method,
            "pth": path,
        });
        if let Some(query) = query {
            claims["qsh"] = json!(hex_sha256(query.as_bytes()));
        }
        if let Some(body) = body {
            claims["bdh"] = json!(hex_sha256(body.as_bytes()));
        }
        claims
    }

    /// A request signature over `claims` by `device`, its public JWK in the header.
    pub fn signature_with(&self, device: &Key, claims: &Value) -> String {
        let header = json!({ "alg": alg_name(device.alg), "jwk": device.jwk });
        jws(&header, claims, device)
    }

    /// The public half of every issuer key, as a verifier's JWKS cache holds them.
    pub fn issuer_keys(&self) -> Value {
        Value::Array(
            [&self.es256, &self.eddsa, &self.rs256]
                .iter()
                .map(|k| {
                    let mut jwk = k.key.jwk.clone();
                    jwk["kid"] = json!(k.kid);
                    jwk["alg"] = json!(alg_name(k.key.alg));
                    json!({ "iss": k.iss, "kid": k.kid, "jwk": jwk })
                })
                .collect(),
        )
    }
}

/// `value` with every object's keys in ascending order, whatever map type
/// serde_json was compiled with.
pub fn sorted(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sorted).collect())
        }
        other => other,
    }
}

/// The compact JSON text of `value` with sorted keys: the bytes a vector's
/// JWS segments encode, the same under either serde_json map type.
pub fn canonical(value: &serde_json::Value) -> String {
    sorted(value.clone()).to_string()
}
