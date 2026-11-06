use crate::auth::{
    error::{AuthError, OAuthErrorResponse},
    state::OAuthToken,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Represents the response from the device authorization endpoint.
/// Defined in RFC 8628 Section 3.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,
    /// The end-user verification code.
    pub user_code: String,
    /// The end-user verification URI on the authorization server.
    pub verification_uri: String,
    /// A verification URI that includes the "user_code" (or other information)
    /// to optimize the end-user interaction.
    pub verification_uri_complete: Option<String>,
    /// The lifetime in seconds of the "device_code" and "user_code".
    pub expires_in: u64,
    /// The minimum amount of time in seconds that the client SHOULD wait
    /// between polling requests to the token endpoint.
    pub interval: Option<u64>,
}

/// Orchestrates the Device Authorization Flow (RFC 8628).
#[non_exhaustive]
pub struct DeviceFlow {
    client_id: String,
    device_authorization_url: String,
    token_url: String,
    http_client: reqwest::Client,
}

impl DeviceFlow {
    /// Creates a new `DeviceFlow` instance.
    pub fn new(client_id: String, device_authorization_url: String, token_url: String) -> Self {
        Self {
            client_id,
            device_authorization_url,
            token_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Initiates the device authorization request.
    /// Returns a `DeviceAuthorizationResponse` which contains the codes and URIs
    /// to be displayed to the user.
    pub async fn initiate_device_authorization(
        &self,
        scopes: &[&str],
    ) -> Result<DeviceAuthorizationResponse, AuthError> {
        let scope_param = scopes.join(" ");

        let response = self
            .http_client
            .post(&self.device_authorization_url)
            .header("Accept", "application/json")
            .form(&[("client_id", &self.client_id), ("scope", &scope_param)])
            .send()
            .await
            .map_err(|_| AuthError::Network)?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::Provider(format!(
                "Device authorization request failed: {error_text}"
            )));
        }

        let response_text = response.text().await.map_err(|e| {
            AuthError::Provider(format!(
                "Failed to read device authorization response body: {e}"
            ))
        })?;

        serde_json::from_str::<DeviceAuthorizationResponse>(&response_text).map_err(|e| {
            AuthError::Provider(format!(
                "Failed to parse device authorization response: {e}"
            ))
        })
    }

    /// Polls the token endpoint until an access token is granted or an error occurs.
    /// This function respects the `interval` specified by the provider and handles
    /// common device flow errors like `authorization_pending` and `slow_down`.
    pub async fn poll_for_token(
        &self,
        device_code: &str,
        interval: Option<u64>,
    ) -> Result<OAuthToken, AuthError> {
        let mut current_interval = interval.unwrap_or(5);

        loop {
            let response = self
                .http_client
                .post(&self.token_url)
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", &self.client_id),
                    ("device_code", &device_code.to_string()),
                    (
                        "grant_type",
                        &"urn:ietf:params:oauth:grant-type:device_code".to_string(),
                    ),
                ])
                .send()
                .await
                .map_err(|_| AuthError::Network)?;

            let response_text = response.text().await.map_err(|e| {
                AuthError::Provider(format!("Failed to read token response body: {e}"))
            })?;

            // Attempt to deserialize as OAuthErrorResponse first
            if let Ok(oauth_error) = serde_json::from_str::<OAuthErrorResponse>(&response_text) {
                match oauth_error.error.as_str() {
                    "authorization_pending" => {
                        // Continue polling
                    }
                    "slow_down" => {
                        current_interval += 5;
                    }
                    "access_denied" => {
                        return Err(AuthError::Provider("Access denied by user".into()));
                    }
                    "expired_token" => {
                        return Err(AuthError::Provider("Device code expired".into()));
                    }
                    _ => {
                        let error_description = oauth_error
                            .error_description
                            .unwrap_or_else(|| "No description provided".to_string());
                        return Err(AuthError::Provider(format!(
                            "OAuth error: {} - {}",
                            oauth_error.error, error_description
                        )));
                    }
                }
            } else if let Ok(oauth_token) = serde_json::from_str::<OAuthToken>(&response_text) {
                // If OAuthErrorResponse deserialization fails, attempt OAuthToken
                return Ok(oauth_token);
            } else {
                // If both deserialization attempts fail
                return Err(AuthError::Provider(
                    "Failed to parse token response as either OAuthToken or OAuthErrorResponse"
                        .into(),
                ));
            }

            // `tokio::time::sleep`, never `std::thread::sleep`: this is an
            // `async fn`, so blocking the thread here parks the whole worker
            // for the interval (5s by default, growing on `slow_down`).
            // On a multi-thread runtime that starves every other task on
            // that worker; on a current-thread runtime it stalls the entire
            // executor for the length of the device ceremony (#306).
            tracing::debug!(
                interval_secs = current_interval,
                "authorization still pending; waiting before polling the token endpoint again"
            );
            tokio::time::sleep(Duration::from_secs(current_interval)).await;
        }
    }
}
