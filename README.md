# jwksproxy

The purpose of this project is to provide a dead simple mechanism for making the token signing keys from a Kubernetes
cluster available publicly. Many Kubernetes clusters have mechanisms for setting up a TLS encrypted HTTP endpoint, but
no clear way of making the signing keys available to clients, which can cause problems when integrating cluster-issued
workload identities with external services.

jwksproxy is designed to be performant and easy to set up. The only necessary option is origin, matching the hostname
that is used to connect to the service. 

## Configuration

```toml
bind_address = "0.0.0.0:8080"
origin = "jwksproxy.example.com"
kubernetes_api_endpoint = "kubernetes.default.svc"
max_key_age = "1h"
```

`origin` is the public host name clients use to reach `jwksproxy`, without a URL scheme. The discovery document at `/.well-known/openid-configuration` returns `https://{origin}` as the issuer, `https://{origin}/jwks.json` as the JWKS URI, and the OIDC metadata required by AWS IAM for an OIDC identity provider.

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

When running in a pod, `jwksproxy` uses the mounted service account CA bundle and bearer token when calling the
Kubernetes API server.
