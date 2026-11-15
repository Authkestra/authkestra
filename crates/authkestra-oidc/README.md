# authkestra-oidc

OpenID Connect (OIDC) implementation for [authkestra](https://github.com/Authkestra/authkestra).

This crate provides OIDC support for the `authkestra` framework, including automatic provider discovery, JWKS handling, and ID token validation. It implements the `OAuthProvider` trait from `authkestra-engine`, making it easy to integrate any OIDC-compliant provider into your application.

## Features

- **OIDC Discovery**: Automatically fetch provider metadata from the issuer URL.
- **JWKS Handling**: Fetch and use JSON Web Key Sets for token signature verification.
- **ID Token Validation**: Securely decode and validate ID tokens, including issuer and audience checks.
- **PKCE Support**: Built-in support for Proof Key for Code Exchange (PKCE).
- **Identity Extraction**: Automatically maps OIDC claims (`sub`, `email`, `name`, `picture`) to the `authkestra` `Identity` struct.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-oidc = "0.7"
authkestra-engine = "0.7"
```

### Example

```rust,ignore
use authkestra_oidc::OidcProvider;
use authkestra_engine::OAuthProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the provider using discovery
    let provider = OidcProvider::discover(
        "your_client_id".to_string(),
        "your_client_secret".to_string(),
        "http://localhost:8080/callback".to_string(),
        "https://accounts.google.com", // Issuer URL
        std::time::Duration::from_secs(3600), // Fallback refresh interval
    ).await?;

    // Generate an authorization URL
    let auth_url = provider.get_authorization_url(
        "random_state_string",
        &["email", "profile"],
        None // Optional PKCE code challenge
    );

    println!("Redirect user to: {}", auth_url);

    // After the user is redirected back with a code:
    // let (identity, token) = provider.exchange_code_for_identity("code_from_callback", None).await?;
    
    Ok(())
}
```

## ID Token Validation Policy

By default, `exchange_code_for_identity` validates the ID token's `iss` against
the discovered issuer, its `aud` against the configured `client_id`, and
restricts signature algorithms to those the discovery document advertises via
`id_token_signing_alg_values_supported` (falling back to `RS256` if the
document omits it). Use `OidcProvider::with_validation` to override this
default — for example to accept multiple audiences, add clock-skew leeway, or
otherwise diverge from it for a specific IdP:

```rust,ignore
use jsonwebtoken::{Algorithm, Validation};

let mut validation = Validation::new(Algorithm::RS256);
validation.set_issuer(&["https://accounts.example.com"]);
validation.set_audience(&["your_client_id", "another_allowed_audience"]);

let provider = provider.with_validation(validation);
```

> **`with_validation` replaces the derived policy — it does not extend it.**
> Whatever you pass becomes the entire policy. `Validation::new(alg)` starts
> with no issuer set and no audience set, so a bare
> `provider.with_validation(Validation::new(Algorithm::RS256))` silently
> disables the `iss` and `aud` checks altogether. Always call `set_issuer`
> and `set_audience` on the `Validation` you supply, as the example above
> does.

## Part of authkestra

This crate is part of the [authkestra](https://github.com/Authkestra/authkestra) workspace.
