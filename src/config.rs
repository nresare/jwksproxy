// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The jwksproxy contributors

use anyhow::Context;
use std::time::Duration;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_origin")]
    pub origin: String,
    #[serde(
        default = "default_kubernetes_api_endpoint",
        alias = "kubernets_api_endpoint"
    )]
    pub kubernetes_api_endpoint: String,
    #[serde(
        default = "default_max_key_age",
        deserialize_with = "deserialize_duration"
    )]
    pub max_key_age: Duration,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file '{path}'"))?;
        toml::from_str(&content)
            .map_err(|error| anyhow::anyhow!("Could not parse config file '{path}': {error}"))
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.bind_address.is_empty() {
            anyhow::bail!("bind_address must not be empty");
        }
        if self.origin.is_empty() {
            anyhow::bail!("origin must not be empty");
        }
        if self.origin.contains("://")
            || self.origin.contains('/')
            || self.origin.contains('?')
            || self.origin.contains('#')
        {
            anyhow::bail!("origin must be a host name, optionally with a port");
        }
        if self.kubernetes_api_endpoint.is_empty() {
            anyhow::bail!("kubernetes_api_endpoint must not be empty");
        }
        if self.max_key_age.is_zero() {
            anyhow::bail!("max_key_age must be greater than zero");
        }
        validate_host_like("kubernetes_api_endpoint", &self.kubernetes_api_endpoint)?;
        Ok(())
    }

    pub fn jwks_uri(&self) -> String {
        format!("https://{}/jwks.json", self.origin)
    }

    pub fn issuer(&self) -> String {
        format!("https://{}", self.origin)
    }

    pub fn cluster_openid_config_endpoint(&self) -> String {
        format!(
            "https://{}/.well-known/openid-configuration",
            self.kubernetes_api_endpoint
        )
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_origin() -> String {
    "localhost:8080".to_string()
}

fn default_kubernetes_api_endpoint() -> String {
    "kubernetes.default.svc".to_string()
}

fn default_max_key_age() -> Duration {
    Duration::from_secs(3600)
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct DurationVisitor;

    impl serde::de::Visitor<'_> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a duration string like '60s', '15m', '1h', or '1d'")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Duration::from_secs(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_duration(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    let value = value.trim();
    let digits = value.trim_end_matches(|character: char| character.is_ascii_alphabetic());
    let unit = &value[digits.len()..];
    let amount: u64 = digits
        .parse()
        .with_context(|| format!("invalid duration '{value}'"))?;
    let multiplier = match unit {
        "s" | "" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => anyhow::bail!("unsupported duration unit '{unit}' in '{value}'"),
    };

    amount
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .with_context(|| format!("duration '{value}' is too large"))
}

fn validate_host_like(name: &str, value: &str) -> anyhow::Result<()> {
    if value.contains("://") || value.contains('/') || value.contains('?') || value.contains('#') {
        anyhow::bail!("{name} must be a host name, optionally with a port");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::time::Duration;

    #[test]
    fn parses_minimal_config() {
        let config: Config = toml::from_str("").unwrap();

        config.validate().unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.origin, "localhost:8080");
        assert_eq!(config.issuer(), "https://localhost:8080");
        assert_eq!(config.jwks_uri(), "https://localhost:8080/jwks.json");
        assert_eq!(config.kubernetes_api_endpoint, "kubernetes.default.svc");
        assert_eq!(
            config.cluster_openid_config_endpoint(),
            "https://kubernetes.default.svc/.well-known/openid-configuration"
        );
        assert_eq!(config.max_key_age, Duration::from_secs(3600));
    }

    #[test]
    fn derives_cluster_openid_config_endpoint_from_kubernetes_api_endpoint() {
        let config: Config = toml::from_str(
            r#"
kubernetes_api_endpoint = "api.example.com:6443"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.cluster_openid_config_endpoint(),
            "https://api.example.com:6443/.well-known/openid-configuration"
        );
    }

    #[test]
    fn rejects_kubernetes_api_endpoint_with_scheme() {
        let config: Config = toml::from_str(
            r#"
kubernetes_api_endpoint = "https://api.example.com:6443"
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "kubernetes_api_endpoint must be a host name, optionally with a port"
        );
    }

    #[test]
    fn derives_jwks_uri_from_origin() {
        let config: Config = toml::from_str(
            r#"
origin = "issuer.example.com"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.jwks_uri(), "https://issuer.example.com/jwks.json");
    }

    #[test]
    fn derives_issuer_from_origin() {
        let config: Config = toml::from_str(
            r#"
origin = "issuer.example.com"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.issuer(), "https://issuer.example.com");
    }

    #[test]
    fn rejects_origin_with_scheme() {
        let config: Config = toml::from_str(
            r#"
origin = "https://issuer.example.com"
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "origin must be a host name, optionally with a port"
        );
    }

    #[test]
    fn parses_max_key_age_duration() {
        let config: Config = toml::from_str(
            r#"
max_key_age = "15m"
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.max_key_age, Duration::from_secs(15 * 60));
    }

    #[test]
    fn rejects_zero_max_key_age() {
        let config: Config = toml::from_str(
            r#"
max_key_age = "0s"
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert_eq!(error.to_string(), "max_key_age must be greater than zero");
    }
}
