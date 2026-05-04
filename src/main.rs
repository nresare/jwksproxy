// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The jwksproxy contributors

mod config;
mod error;
mod kubernetes;

use crate::config::Config;
use crate::error::AppError;
use anyhow::Context;
use arc_swap::ArcSwap;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/config/jwksproxy.toml"
    )]
    config_path: String,
    #[arg(long = "debug", default_value_t = false)]
    debug: bool,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    client: reqwest::Client,
    jwks_cache: Arc<ArcSwap<CachedJwks>>,
}

#[derive(Clone)]
struct CachedJwks {
    jwks_uri: String,
    body: Bytes,
    fetched_at: Instant,
}

#[derive(Deserialize)]
struct ClusterOpenidConfig {
    jwks_uri: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let log_filter = if cli.debug {
        "jwksproxy=debug,tower_http=info,axum::rejection=trace"
    } else {
        "jwksproxy=info,tower_http=info,axum::rejection=info"
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_filter))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run(cli).await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(&cli.config_path)?;
    config.validate()?;
    let bind_address: SocketAddr = config.bind_address.parse()?;
    let client = kubernetes::configure_in_cluster_client(reqwest::Client::builder())?.build()?;

    let cluster_openid_config_endpoint = config.cluster_openid_config_endpoint();
    let jwks_uri = discover_cluster_jwks_uri(&client, &cluster_openid_config_endpoint)
        .await
        .with_context(|| {
            format!("failed to discover cluster JWKS URI from '{cluster_openid_config_endpoint}'")
        })?;
    let jwks_cache = fetch_jwks(&client, &jwks_uri)
        .await
        .with_context(|| format!("failed to fetch cluster JWKS from '{jwks_uri}'"))?;

    info!(
        version = VERSION,
        config_path = %cli.config_path,
        debug = cli.debug,
        cluster_jwks_uri = %jwks_uri,
        "starting jwksproxy"
    );

    let state = AppState {
        config: Arc::new(config),
        client,
        jwks_cache: Arc::new(ArcSwap::from_pointee(jwks_cache)),
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/openid-configuration", get(openid_config))
        .route("/jwks.json", get(keys))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn openid_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.config.issuer(),
        "jwks_uri": state.config.jwks_uri(),
    }))
}

async fn keys(State(state): State<AppState>) -> Result<Response, AppError> {
    let cache = state.jwks_cache.load_full();
    let jwks_uri = cache.jwks_uri.clone();
    let should_refresh = cache.fetched_at.elapsed() >= state.config.max_key_age;

    if should_refresh {
        debug!(cluster_jwks_uri = %jwks_uri, "refreshing cached cluster JWKS");
        match fetch_jwks(&state.client, &jwks_uri).await {
            Ok(refreshed_cache) => {
                state.jwks_cache.store(Arc::new(refreshed_cache));
            }
            Err(error) => {
                warn!(error = %error, cluster_jwks_uri = %jwks_uri, "failed to refresh cluster JWKS; returning stale cache");
            }
        }
    }

    let cache = state.jwks_cache.load_full();
    cached_jwks_response(&cache)
}

async fn discover_cluster_jwks_uri(
    client: &reqwest::Client,
    endpoint: &str,
) -> anyhow::Result<String> {
    let discovery: ClusterOpenidConfig = client
        .get(endpoint)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if discovery.jwks_uri.is_empty() {
        anyhow::bail!("cluster OpenID configuration did not include jwks_uri");
    }
    reqwest::Url::parse(&discovery.jwks_uri).with_context(|| {
        format!(
            "cluster jwks_uri must be an absolute URL: '{}'",
            discovery.jwks_uri
        )
    })?;
    Ok(discovery.jwks_uri)
}

async fn fetch_jwks(client: &reqwest::Client, jwks_uri: &str) -> anyhow::Result<CachedJwks> {
    let upstream_response = client.get(jwks_uri).send().await?;
    let status = upstream_response.status();
    if status != reqwest::StatusCode::OK {
        anyhow::bail!("cluster JWKS endpoint returned HTTP {}", status.as_u16());
    }
    let upstream_body = upstream_response.bytes().await?;

    Ok(CachedJwks {
        jwks_uri: jwks_uri.to_string(),
        body: upstream_body,
        fetched_at: Instant::now(),
    })
}

fn cached_jwks_response(cache: &CachedJwks) -> Result<Response, AppError> {
    Response::builder()
        .body(Body::from(cache.body.clone()))
        .map_err(|error| AppError::Internal(format!("failed to build JWKS response: {error}")))
}
