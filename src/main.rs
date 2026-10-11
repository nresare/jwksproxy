// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The jwksproxy contributors

mod certificates;
mod config;
mod error;
mod kubernetes;
mod tls;

use crate::config::Config;
use crate::error::AppError;
use anyhow::Context;
use arc_swap::ArcSwap;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CLAIMS_SUPPORTED: &[&str] = &["aud", "exp", "iat", "iss", "jti", "nbf", "sub"];
const ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED: &[&str] =
    &["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"];
const RESPONSE_TYPES_SUPPORTED: &[&str] = &["id_token"];
const SUBJECT_TYPES_SUPPORTED: &[&str] = &["public"];

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
    certificates: Arc<certificates::Certificates>,
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

#[derive(Serialize)]
struct OpenidConfig {
    issuer: String,
    jwks_uri: String,
    claims_supported: &'static [&'static str],
    id_token_signing_alg_values_supported: &'static [&'static str],
    response_types_supported: &'static [&'static str],
    subject_types_supported: &'static [&'static str],
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
    let bind_address: SocketAddr = config.bind_address().parse()?;
    let tls = tls::load(&config, Path::new(&cli.config_path)).await?;
    let client = kubernetes::configure_in_cluster_client(reqwest::Client::builder())?.build()?;

    let certificates = Arc::new(certificates::Certificates::new(config.emit_x5c)?);
    let cluster_openid_config_endpoint = config.cluster_openid_config_endpoint();
    let jwks_uri = discover_cluster_jwks_uri(&client, &cluster_openid_config_endpoint)
        .await
        .with_context(|| {
            format!("failed to discover cluster JWKS URI from '{cluster_openid_config_endpoint}'")
        })?;
    let jwks_cache = fetch_jwks(&client, &jwks_uri, &certificates)
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
        certificates,
        jwks_cache: Arc::new(ArcSwap::from_pointee(jwks_cache)),
    };
    let app = build_router(state);
    let listener = TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");
    serve(listener, app, tls).await
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/openid-configuration", get(openid_config))
        .route("/jwks.json", get(keys))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Option<RustlsConfig>,
) -> anyhow::Result<()> {
    if let Some(tls) = tls {
        axum_server::from_tcp_rustls(listener.into_std()?, tls)?
            .serve(app.into_make_service())
            .await?;
    } else {
        axum::serve(listener, app).await?;
    }
    Ok(())
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn openid_config(State(state): State<AppState>) -> Json<OpenidConfig> {
    Json(openid_config_document(&state.config))
}

fn openid_config_document(config: &Config) -> OpenidConfig {
    OpenidConfig {
        issuer: config.issuer(),
        jwks_uri: config.jwks_uri(),
        claims_supported: CLAIMS_SUPPORTED,
        id_token_signing_alg_values_supported: ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
        response_types_supported: RESPONSE_TYPES_SUPPORTED,
        subject_types_supported: SUBJECT_TYPES_SUPPORTED,
    }
}

async fn keys(State(state): State<AppState>) -> Result<Response, AppError> {
    let cache = state.jwks_cache.load_full();
    let jwks_uri = cache.jwks_uri.clone();
    let should_refresh = cache.fetched_at.elapsed() >= state.config.max_key_age;

    if should_refresh {
        debug!(cluster_jwks_uri = %jwks_uri, "refreshing cached cluster JWKS");
        match fetch_jwks(&state.client, &jwks_uri, &state.certificates).await {
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

async fn fetch_jwks(
    client: &reqwest::Client,
    jwks_uri: &str,
    certificates: &certificates::Certificates,
) -> anyhow::Result<CachedJwks> {
    let upstream_response = client.get(jwks_uri).send().await?;
    let status = upstream_response.status();
    if status != reqwest::StatusCode::OK {
        anyhow::bail!("cluster JWKS endpoint returned HTTP {}", status.as_u16());
    }
    let upstream_body = upstream_response.bytes().await?;

    Ok(CachedJwks {
        jwks_uri: jwks_uri.to_string(),
        body: certificates.transform(&upstream_body)?.into(),
        fetched_at: Instant::now(),
    })
}

fn cached_jwks_response(cache: &CachedJwks) -> Result<Response, AppError> {
    Response::builder()
        .body(Body::from(cache.body.clone()))
        .map_err(|error| AppError::Internal(format!("failed to build JWKS response: {error}")))
}

#[cfg(test)]
mod tests {
    use super::{Config, openid_config_document};
    use serde_json::json;

    #[test]
    fn openid_config_includes_aws_oidc_prerequisite_fields() {
        let config = Config {
            emit_x5c: false,
            bind_address: Some("0.0.0.0:8080".to_string()),
            tls_cert_path: None,
            tls_key_path: None,
            origin: "issuer.example.com".to_string(),
            kubernetes_api_endpoint: "kubernetes.default.svc".to_string(),
            max_key_age: std::time::Duration::from_secs(3600),
        };

        let document = serde_json::to_value(openid_config_document(&config)).unwrap();

        assert_eq!(
            document,
            json!({
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/jwks.json",
                "claims_supported": ["aud", "exp", "iat", "iss", "jti", "nbf", "sub"],
                "id_token_signing_alg_values_supported": [
                    "RS256",
                    "RS384",
                    "RS512",
                    "ES256",
                    "ES384",
                    "ES512"
                ],
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"]
            })
        );
    }

    #[tokio::test]
    async fn serves_oidc_and_jwks_over_http_and_https() {
        use super::*;
        use rustls::pki_types::{CertificateDer, pem::PemObject};

        for enabled in [false, true] {
            let settings = if enabled {
                "tls_cert_path = 'cert.pem'\ntls_key_path = 'test-only-key.pem'"
            } else {
                ""
            };
            let config: Config =
                toml::from_str(&format!("{settings}\norigin = 'issuer.example.com'\n")).unwrap();
            let tls = tls::load(
                &config,
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls/config.toml"),
            )
            .await
            .unwrap();
            if let Some(tls) = &tls {
                assert_eq!(
                    tls.get_inner().alpn_protocols,
                    [b"h2".to_vec(), b"http/1.1".to_vec()]
                );
            }
            let state = AppState {
                config: Arc::new(config),
                client: reqwest::Client::new(),
                certificates: Arc::new(certificates::Certificates::new(false).unwrap()),
                jwks_cache: Arc::new(ArcSwap::from_pointee(CachedJwks {
                    jwks_uri: "https://kubernetes.default.svc/openid/v1/jwks".into(),
                    body: Bytes::from_static(b"{\"keys\":[]}"),
                    fetched_at: Instant::now(),
                })),
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(serve(listener, build_router(state), tls));
            for http2 in [false, true] {
                if http2 && !enabled {
                    continue;
                }
                let mut client = reqwest::Client::builder()
                    .no_proxy()
                    .resolve("localhost", address)
                    .timeout(std::time::Duration::from_secs(5));
                if enabled {
                    let mut roots = rustls::RootCertStore::empty();
                    roots
                        .add(
                            CertificateDer::from_pem_slice(include_bytes!("../tests/tls/cert.pem"))
                                .unwrap(),
                        )
                        .unwrap();
                    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                    tls.alpn_protocols = if http2 {
                        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                    } else {
                        vec![b"http/1.1".to_vec()]
                    };
                    client = client.tls_backend_preconfigured(tls);
                }
                let client = if http2 {
                    client.http2_prior_knowledge()
                } else {
                    client.http1_only()
                }
                .build()
                .unwrap();
                let scheme = if enabled { "https" } else { "http" };
                for path in [
                    "/healthz",
                    "/.well-known/openid-configuration",
                    "/jwks.json",
                ] {
                    let response = client
                        .get(format!("{scheme}://localhost:{}{path}", address.port()))
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), reqwest::StatusCode::OK);
                    assert_eq!(
                        response.version(),
                        if http2 {
                            reqwest::Version::HTTP_2
                        } else {
                            reqwest::Version::HTTP_11
                        }
                    );
                    let body: Value = response.json().await.unwrap();
                    match path {
                        "/healthz" => assert_eq!(body, json!({"status":"ok"})),
                        "/jwks.json" => assert_eq!(body, json!({"keys":[]})),
                        _ => {
                            assert_eq!(body["issuer"], "https://issuer.example.com");
                            assert_eq!(body["jwks_uri"], "https://issuer.example.com/jwks.json");
                        }
                    }
                }
            }
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    }
}
