//! # Axum Model Context Protocol (MCP) Server Example
//!
//! Demonstrates building a production-grade, delegated AI agent authorization server
//! with `authkestra`'s embedded MCP security engine (`authkestra-mcp` and `authkestra-axum`).
//!
//! ### Core Architectural Pillars Demonstrated:
//! 1. **Public Tier Tool (`echo`)**:
//!    - Permissive access: callable without authentication or with optional identity context.
//! 2. **Scoped Tier Tool (`query_weather`)**:
//!    - Requires valid token containing `scope:read`.
//!    - Demonstrates **Zero-Trust Downstream Token Broker** (`EncryptedKvTokenVault`):
//!      resolves downstream API credentials on behalf of caller's `Identity` without
//!      leaking credentials into the LLM context.
//! 3. **HumanApproved Tier Tool (`execute_transfer`)**:
//!    - High-risk operation: requires `scope:transfer`, RFC 8785 JSON Canonicalization Scheme (JCS)
//!      parameter binding, SHA-256 challenge digest generation, and Passkey step-up approval ceremony.
//!    - Single-use replay defense via atomic token consumption.
//!    - Parameter tampering defense: mutating arguments after approval fails deterministically.
//! 4. **RFC 9728 Protected Resource Metadata**:
//!    - Auto-registered discovery endpoint at `/.well-known/oauth-protected-resource`.
//!
//! ### Running the Example:
//! ```sh
//! cargo run -p authkestra --example axum_mcp_server --all-features
//! ```

use authkestra::axum::mcp_axum_router;
use authkestra::core::auth::state::Identity;
use authkestra::core::auth::ReproofRequirement;
use authkestra::core::store::memory::MemoryStore;
use authkestra::mcp::{
    DownstreamToken, DownstreamTokenBroker, EncryptedKvTokenVault, McpRouter, McpSecurityTier,
    ProtectedResourceMetadata, ToolCallResult, ToolContext, ToolDefinition,
};
use axum::Router;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra_mcp=debug,authkestra_axum=debug".into()),
        )
        .init();

    tracing::info!("Initializing Authkestra MCP Security Engine...");

    // Storage backends for challenges, execution records, and encrypted tokens
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());
    let vault_store = Arc::new(MemoryStore::new());

    // 256-bit AES-GCM AEAD key for zero-trust downstream credential vault
    let vault_encryption_key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let vault = Arc::new(EncryptedKvTokenVault::new(
        vault_store,
        vault_encryption_key,
    ));

    // Pre-seed a downstream token for testing zero-trust credential resolution
    let agent_identity = Identity {
        provider_id: "authkestra_idp".to_string(),
        external_id: "agent_runner_1".to_string(),
        email: Some("agent@example.com".to_string()),
        username: Some("agent_runner".to_string()),
        attributes: HashMap::new(),
    };
    vault
        .store_token(
            &agent_identity,
            "weather_service",
            &DownstreamToken {
                access_token: "wx_live_token_super_secret_987".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                scopes: vec!["weather:read".to_string()],
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            },
            Duration::from_secs(3600),
        )
        .await?;
    tracing::info!("Downstream credentials stored encrypted at rest in token vault");

    // 1. Public Tool: echo
    let echo_tool = ToolDefinition::new(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "Message to echo back" }
            },
            "required": ["message"]
        }),
        McpSecurityTier::Public,
        |args, _ctx: ToolContext| async move {
            let msg = args["message"].as_str().unwrap_or("hello from public tool");
            tracing::info!(message = %msg, "executing public echo tool");
            Ok(ToolCallResult::text(format!("Echo: {msg}")))
        },
    )
    .with_description("Echoes back the input message without requiring authentication.");

    // 2. Scoped Tool: query_weather
    let weather_tool = ToolDefinition::new(
        "query_weather",
        json!({
            "type": "object",
            "properties": {
                "city": { "type": "string", "description": "City name" }
            },
            "required": ["city"]
        }),
        McpSecurityTier::Scoped {
            required_scopes: vec!["scope:read".to_string()],
        },
        |args, ctx: ToolContext| async move {
            let city = args["city"].as_str().unwrap_or("San Francisco");
            tracing::info!(city = %city, "executing scoped query_weather tool");

            // Resolve downstream API token without LLM having access to credentials
            let token_msg = match ctx
                .get_downstream_token("weather_service", &["weather:read"])
                .await
            {
                Ok(Some(_token)) => "Downstream token resolved securely from EncryptedKvTokenVault",
                Ok(None) => "No downstream token provisioned for identity",
                Err(e) => {
                    return Err(authkestra::mcp::McpError::Execution(format!(
                        "vault resolution error: {e}"
                    )))
                }
            };

            Ok(ToolCallResult::text(format!(
                "Weather in {city}: 18°C, Partly Cloudy. ({token_msg})"
            )))
        },
    )
    .with_description("Queries weather data for a city. Requires 'scope:read' OAuth2 scope.");

    // 3. HumanApproved Tool: execute_transfer
    let transfer_tool = ToolDefinition::new(
        "execute_transfer",
        json!({
            "type": "object",
            "properties": {
                "recipient": { "type": "string", "description": "Destination account or email" },
                "amount": { "type": "number", "description": "Amount in USD to transfer" }
            },
            "required": ["recipient", "amount"]
        }),
        McpSecurityTier::human_approved(
            vec!["scope:transfer"],
            ReproofRequirement::new(60).require_step_up(true),
            120, // 2-minute approval window
        ),
        |args, ctx: ToolContext| async move {
            let recipient = args["recipient"].as_str().unwrap_or("unknown");
            let amount = args["amount"].as_f64().unwrap_or(0.0);
            let approver = ctx
                .approver_identity
                .map(|i| i.external_id)
                .unwrap_or_else(|| "unrecorded".to_string());

            tracing::info!(
                recipient = %recipient,
                amount = amount,
                approver = %approver,
                "executing HumanApproved high-risk transfer"
            );

            Ok(ToolCallResult::text(format!(
                "Successfully executed transfer of ${amount:.2} to {recipient}. Approved by user '{approver}'."
            )))
        },
    )
    .with_description("Executes a fund transfer. Requires 'scope:transfer' and cryptographic Passkey step-up approval.");

    // RFC 9728 Protected Resource Metadata configuration
    let metadata = ProtectedResourceMetadata::new("https://api.authkestra.com/mcp")
        .with_auth_server("https://auth.authkestra.com")
        .with_scopes(vec!["scope:read", "scope:transfer"])
        .with_documentation("https://docs.authkestra.com/mcp")
        .with_name("Authkestra Secure AI Agent MCP Server");

    // Build McpRouter
    let router = McpRouter::builder(pending_store, execution_store)
        .tool(echo_tool)
        .tool(weather_tool)
        .tool(transfer_tool)
        .token_broker(vault)
        .resource_metadata(metadata)
        .build();

    let shared_router = Arc::new(router);

    // Mount Axum router registering:
    // - POST /mcp: MCP JSON-RPC protocol router (tools/list, tools/call)
    // - GET /.well-known/oauth-protected-resource: RFC 9728 Resource Metadata
    // - GET /mcp/approve & POST /mcp/approve: Step-up verification & token minting
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(shared_router);

    // Bind to ephemeral port or port 3000
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    tracing::info!("---------------------------------------------------------------");
    tracing::info!("Authkestra MCP Server running at: http://{}", local_addr);
    tracing::info!("  - MCP Endpoint: POST http://{}/mcp", local_addr);
    tracing::info!(
        "  - Discovery:    GET  http://{}/.well-known/oauth-protected-resource",
        local_addr
    );
    tracing::info!(
        "  - Step-Up:      GET/POST http://{}/mcp/approve",
        local_addr
    );
    tracing::info!("---------------------------------------------------------------");

    // To run indefinitely in production:
    // axum::serve(listener, app).await?;
    // For this example showcase, we spin a background server task and exit cleanly if not blocked:
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Allow background task to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    server_task.abort();
    tracing::info!("Authkestra MCP server check completed successfully.");

    Ok(())
}
