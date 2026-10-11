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

To enable HTTPS, configure both PEM paths:

```toml
tls_cert_path = "tls/cert.pem"
tls_key_path = "tls/key.pem"
```

Relative paths resolve from the configuration file's directory. TLS negotiates
HTTP/2 and HTTP/1.1 through ALPN. The default listen address is `0.0.0.0:8443`
with TLS and `0.0.0.0:8080` otherwise; an explicit `bind_address` overrides either
one. Invalid, incomplete, or mismatched TLS settings fail startup before contacting
the Kubernetes API.

## Cluster deployment

Main-branch commits use `.buildkite/pipelinegen.toml` to test and publish a container
image, then notify relcoord. Relcoord reads `.deploy` from that same commit and
writes manifests to the configured output repository for Argo CD to reconcile.
The image comes from the build rather than a version pinned in system.

The deployment keeps production's single replica, `origin = "k8s.noa.re"`, and
`emit_x5c = true`. The system website plugin creates a cluster-local certificate
mounted at `/tls`, HTTPS probes, a Service on port 443 targeting port 8443, and a
BackendTLSPolicy that verifies the backend against the `cluster-local-ca` ConfigMap.
The namespace's `trust: cluster-local` label makes trust-manager install that bundle.

For the handoff from system:

1. Keep the existing `jwksproxy/` manifests in fruktsallad throughout the switchover.
   Removing `jwksproxy` from `owners/system.toml` is preparation, not confirmation
   that Argo CD has adopted the deployment.
2. Merge and deploy jwksproxy from its repository. Confirm `owners/jwksproxy.toml`
   contains `owned = "jwksproxy"`, the generated image matches the build, and Argo CD
   reports the workload synced and healthy. Verify the public discovery and JWKS
   endpoints at `https://k8s.noa.re`.
3. Only then merge the system cleanup that removes its `k8s.noa.re` website block
   and `jwksproxy/jwksproxy.toml`.

Avoid system deployments during the handoff: the old website block can reclaim
ownership before jwksproxy's first deployment, then conflicts with its new owner
until cleanup. The shared website plugin and TLS infrastructure remain in system.

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

## Experimental Ceph x5c compatibility

Set `emit_x5c = true` to attach a certificate to each upstream JWK that has
no `x5c`. This defaults to false. The proxy generates an ephemeral EC P-256
issuer private key at startup and keeps it only in memory. Each certificate
contains the original Kubernetes public key; tokens and existing JWK fields
are unchanged. RSA and EC P-256/P-384/P-521 public keys are supported.

Certificates are signed by the ephemeral issuer, valid for 365 days, and
regenerated when the JWKS cache refreshes. Existing `x5c` fields are preserved.
Malformed or unsupported keys fail the fetch; a failed refresh retains the
previous cache, as with upstream fetch failures.

This is a feasibility experiment, not a trusted certificate chain. It targets
Ceph RGW's certificate-based token verification with
`rgw_enable_jwks_url_verification = true` and a correctly registered JWKS
HTTPS endpoint thumbprint. In that mode the examined Ceph implementation
authenticates the JWKS endpoint but does not verify the issuer signature of
the embedded certificate. With URL verification disabled, Ceph checks the
embedded certificate against registered thumbprints instead; ephemeral
certificates are unsuitable for that configuration.
