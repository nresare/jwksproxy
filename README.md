# jwksproxy

`jwksproxy` is a tiny Axum service for publishing a minimal OpenID-style discovery document and proxying the Kubernetes service account JWKS from the cluster it runs in.

## API

```sh
curl http://localhost:8080/.well-known/openid-configuration
```

returns:

```json
{ "jwks_uri": "https://jwksproxy.example.com/jwks.json" }
```

At startup, `jwksproxy` reads the cluster OpenID configuration from:

```text
https://{kubernetes_api_endpoint}/.well-known/openid-configuration
```

It extracts that document's `jwks_uri`, fetches the cluster JWKS, and serves the cached key set from `/jwks.json`. Once `max_key_age` has elapsed, the next `/jwks.json` request refreshes the cache from the discovered `jwks_uri` before returning a response. If a refresh fails, `jwksproxy` logs the error and returns the last cached JWKS.

## Configuration

```toml
bind_address = "0.0.0.0:8080"
origin = "jwksproxy.example.com"
kubernetes_api_endpoint = "kubernetes.default.svc"
max_key_age = "1h"
```

`origin` is the public host name clients use to reach `jwksproxy`, without a URL scheme. The discovery document at `/.well-known/openid-configuration` returns `https://{origin}/jwks.json`.

`kubernetes_api_endpoint` is the Kubernetes API server host, without a URL scheme. It defaults to `kubernetes.default.svc`.

`max_key_age` accepts seconds as an integer or a duration string using `s`, `m`, `h`, or `d`.

## Running

```sh
cargo run -- --config-file jwksproxy.toml.example
```

Use `--debug` for request-flow logs:

```sh
cargo run -- --config-file jwksproxy.toml.example --debug
```

## Kubernetes

When running in a pod, `jwksproxy` uses the mounted service account CA bundle and bearer token when calling the Kubernetes API server. The default `/openid/v1/jwks` endpoint is normally served by Kubernetes service account issuer discovery.
