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
use authzoo_server::shutdown;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
        "jwksproxy=debug,authzoo_server=info,tower_http=info,axum::rejection=trace"
    } else {
        "jwksproxy=info,authzoo_server=info,tower_http=info,axum::rejection=info"
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
    let signals = shutdown::Signals::new().context("could not register shutdown signals")?;
    let signal = signals.wait();
    tokio::pin!(signal);
    let (listener, app, tls) = tokio::select! {
        result = prepare(cli) => result?,
        () = &mut signal => return Ok(()),
    };
    serve(listener, app, tls, signal, shutdown::GRACE_PERIOD).await
}

async fn prepare(cli: Cli) -> anyhow::Result<(TcpListener, Router, Option<RustlsConfig>)> {
    tls::install_crypto_provider();
    let config = Config::load(&cli.config_path)?;
    config.validate()?;
    let bind_address: SocketAddr = config.bind_address().parse()?;
    let tls = tls::load(&config, Path::new(&cli.config_path)).await?;
    let client = kubernetes::configure_in_cluster_client(reqwest::Client::builder())?.build()?;

    let cluster_openid_config_endpoint = config.cluster_openid_config_endpoint();
    let jwks_uri = discover_cluster_jwks_uri(&client, &cluster_openid_config_endpoint)
        .await
        .with_context(|| {
            format!("failed to discover cluster JWKS URI from '{cluster_openid_config_endpoint}'")
        })?;
    let jwks_cache = fetch_jwks(&client, &jwks_uri, config.emit_x5c)
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
    let app = build_router(state);
    let listener = TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");
    Ok((listener, app, tls))
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
    signal: impl Future<Output = ()>,
    grace_period: Duration,
) -> anyhow::Result<()> {
    if let Some(tls) = tls {
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(listener.into_std()?, tls)?
            .handle(handle.clone())
            .serve(app.into_make_service());
        shutdown::drain(
            server,
            signal,
            || handle.graceful_shutdown(None),
            grace_period,
        )
        .await?;
    } else {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = rx.await;
        });
        shutdown::drain(
            server.into_future(),
            signal,
            || {
                let _ = tx.send(());
            },
            grace_period,
        )
        .await?;
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
        match fetch_jwks(&state.client, &jwks_uri, state.config.emit_x5c).await {
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
    emit_x5c: bool,
) -> anyhow::Result<CachedJwks> {
    let upstream_response = client.get(jwks_uri).send().await?;
    let status = upstream_response.status();
    if status != reqwest::StatusCode::OK {
        anyhow::bail!("cluster JWKS endpoint returned HTTP {}", status.as_u16());
    }
    let upstream_body = upstream_response.bytes().await?;
    let body = if emit_x5c {
        certificates::add_x5c(&upstream_body)?.into()
    } else {
        upstream_body
    };

    Ok(CachedJwks {
        jwks_uri: jwks_uri.to_string(),
        body,
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

    async fn exercise_shutdown(tls_enabled: bool, finish_request: bool) -> anyhow::Result<()> {
        use super::*;
        use tokio::sync::{Notify, oneshot};

        tls::install_crypto_provider();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/",
            get({
                let entered = entered.clone();
                let release = release.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "finished"
                    }
                }
            }),
        );
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls");
        let tls = if tls_enabled {
            Some(
                authzoo_server::tls::load(
                    &fixtures.join("cert.pem"),
                    &fixtures.join("test-only-key.pem"),
                )
                .await?,
            )
        } else {
            None
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (signal_tx, signal_rx) = oneshot::channel();
        let grace = if finish_request {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(100)
        };
        let server = tokio::spawn(serve(
            listener,
            app,
            tls,
            async {
                signal_rx.await.unwrap();
            },
            grace,
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
                "../tests/tls/cert.pem"
            ))?])
            .build()?;
        let scheme = if tls_enabled { "https" } else { "http" };
        let mut request = tokio::spawn(async move {
            client
                .get(format!("{scheme}://localhost:{}/", address.port()))
                .send()
                .await?
                .text()
                .await
        });
        tokio::select! {
            () = entered.notified() => {},
            result = &mut request => anyhow::bail!("request ended before entering handler: {result:?}"),
        }
        let started = Instant::now();
        signal_tx.send(()).unwrap();
        if finish_request {
            // The server must keep running until the active request finishes.
            let mut server = server;
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut server)
                    .await
                    .is_err()
            );
            release.notify_one();
            assert_eq!((&mut request).await??, "finished");
            server.await??;
        } else {
            server.await??;
            assert!(started.elapsed() >= grace);
            request.abort();
            let _ = request.await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn http_and_https_drain_requests_and_bound_shutdown() -> anyhow::Result<()> {
        use anyhow::Context;
        for tls_enabled in [false, true] {
            for finish_request in [false, true] {
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    exercise_shutdown(tls_enabled, finish_request),
                )
                .await
                .with_context(|| {
                    format!(
                        "shutdown timed out: tls={tls_enabled}, finish_request={finish_request}"
                    )
                })??;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn fetch_jwks_adds_x5c_only_when_enabled() -> anyhow::Result<()> {
        use super::*;
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[1; 32])?;
        let point = signing_key.verifying_key().to_sec1_point(false);
        let document = json!({"keys": [{
            "kty": "EC", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
        }]});
        let upstream_body = serde_json::to_vec_pretty(&document)?;
        let response_body = upstream_body.clone();
        let upstream = Router::new().route(
            "/jwks",
            get(move || {
                let body = response_body.clone();
                async move { body }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let jwks_uri = format!("http://{}/jwks", listener.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(listener, upstream).await });
        tls::install_crypto_provider();
        let client = reqwest::Client::builder().no_proxy().build()?;

        let result = async {
            let unmodified = fetch_jwks(&client, &jwks_uri, false).await?;
            assert_eq!(unmodified.body.as_ref(), upstream_body.as_slice());

            let modified = fetch_jwks(&client, &jwks_uri, true).await?;
            let mut output: Value = serde_json::from_slice(&modified.body)?;
            let x5c = output["keys"][0]
                .as_object_mut()
                .unwrap()
                .remove("x5c")
                .unwrap();
            assert_eq!(x5c.as_array().unwrap().len(), 1);
            assert!(!x5c[0].as_str().unwrap().is_empty());
            assert_eq!(output, document);
            anyhow::Ok(())
        }
        .await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        result
    }

    #[tokio::test]
    async fn serves_oidc_and_jwks_over_http_and_https() {
        use super::*;
        use rustls::pki_types::{CertificateDer, pem::PemObject};

        tls::install_crypto_provider();
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
                jwks_cache: Arc::new(ArcSwap::from_pointee(CachedJwks {
                    jwks_uri: "https://kubernetes.default.svc/openid/v1/jwks".into(),
                    body: Bytes::from_static(b"{\"keys\":[]}"),
                    fetched_at: Instant::now(),
                })),
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(serve(
                listener,
                build_router(state),
                tls,
                std::future::pending(),
                shutdown::GRACE_PERIOD,
            ));
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
                        rustls_graviola::default_provider(),
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
