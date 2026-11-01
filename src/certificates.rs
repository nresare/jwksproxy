// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The jwksproxy contributors

use anyhow::{Context, Error, Result, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::elliptic_curve::Generate;
use p256::{
    ecdsa::{DerSignature, SigningKey},
    pkcs8::EncodePublicKey,
};
use rand::TryRng;
use rand::rngs::SysRng;
use rsa::{BoxedUint, RsaPublicKey};
use serde_json::{Value, json};
use std::time::Duration;
use x509_cert::builder::profile;
use x509_cert::{
    Certificate,
    builder::{Builder, CertificateBuilder},
    der::{Decode, Encode},
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

pub fn add_x5c(buf: &[u8]) -> Result<Vec<u8>> {
    let mut document: Value = serde_json::from_slice(buf)?;
    let keys = document
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .context("JWKS must contain a keys array")?;
    let issuer = SigningKey::try_generate_from_rng(&mut SysRng)?;
    for key in keys {
        if key.get("x5c").is_some() {
            continue;
        }
        let public_key = public_key(key).context("could not construct JWK public key")?;
        let cert = create_certificate(public_key, &issuer)?;
        key.as_object_mut()
            .context("JWK must be an object")?
            .insert("x5c".into(), json!([STANDARD.encode(cert.to_der()?)]));
    }
    Ok(serde_json::to_vec(&document)?)
}

fn create_certificate(
    public_key: SubjectPublicKeyInfoOwned,
    issuer: &SigningKey,
) -> Result<Certificate> {
    let profile = profile::cabf::Root::new(
        false,
        "CN=jwksproxy issuer,O=something,C=something".parse()?,
    )?;
    let mut serial = [0u8; 16];
    SysRng.try_fill_bytes(&mut serial)?;
    // Keep the serial positive and nonzero.
    serial[0] = (serial[0] & 0x7f) | 1;
    Ok(CertificateBuilder::new(
        profile,
        SerialNumber::new(&serial)?,
        Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60))?,
        public_key,
    )?
    .build::<_, DerSignature>(issuer)?)
}

fn field<'a>(key: &'a Value, name: &str) -> Result<&'a str> {
    key.get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing JWK string field {name}"))
}

fn decode_field(key: &Value, name: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(field(key, name)?)?)
}

fn decode_boxed_uint(fields: &Value, name: &str) -> Result<BoxedUint, Error> {
    let buf: &[u8] = &decode_field(fields, name)?;
    let bits = buf.len() as u32 * 8;
    Ok(BoxedUint::from_be_slice(buf, bits)?)
}

fn public_key(key: &Value) -> anyhow::Result<SubjectPublicKeyInfoOwned> {
    let encoded = match field(key, "kty")? {
        "RSA" => RsaPublicKey::new(decode_boxed_uint(key, "n")?, decode_boxed_uint(key, "e")?)?
            .to_public_key_der()?,
        "EC" => {
            let curve = field(key, "crv")?;
            let size = match curve {
                "P-256" => 32,
                "P-384" => 48,
                "P-521" => 66,
                other => bail!("unsupported JWK curve {other}"),
            };
            let x = decode_field(key, "x")?;
            let y = decode_field(key, "y")?;
            if x.len() != size || y.len() != size {
                bail!("invalid coordinate length for {curve}");
            }
            let mut point = Vec::with_capacity(1 + 2 * size);
            point.push(4); // SEC1 uncompressed point.
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            match curve {
                "P-256" => p256::PublicKey::from_sec1_bytes(&point)?.to_public_key_der()?,
                "P-384" => p384::PublicKey::from_sec1_bytes(&point)?.to_public_key_der()?,
                "P-521" => p521::PublicKey::from_sec1_bytes(&point)?.to_public_key_der()?,
                _ => unreachable!(),
            }
        }
        other => bail!("unsupported JWK key type {other}"),
    };
    Ok(SubjectPublicKeyInfoOwned::from_der(encoded.as_bytes())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{
            Signature, VerifyingKey,
            signature::{Signer, Verifier},
        },
        elliptic_curve::sec1::ToSec1Point,
        pkcs8::DecodePublicKey,
    };
    use rsa::traits::PublicKeyParts;

    fn transform_certificate(document: &Value) -> anyhow::Result<(Value, Certificate)> {
        let output: Value = serde_json::from_slice(&add_x5c(&serde_json::to_vec(document)?)?)?;
        let cert = Certificate::from_der(
            &STANDARD.decode(output["keys"][0]["x5c"][0].as_str().unwrap())?,
        )?;
        Ok((output, cert))
    }

    #[test]
    fn certificate_verifies_original_ec_token_signature() -> anyhow::Result<()> {
        let original = SigningKey::try_generate_from_rng(&mut SysRng)?;
        let point = original.verifying_key().to_sec1_point(false);
        let document = json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": "original-key", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
        }], "extra": true});
        let (output, cert) = transform_certificate(&document)?;
        let certified = VerifyingKey::from_public_key_der(
            &cert.tbs_certificate().subject_public_key_info().to_der()?,
        )?;
        assert_eq!(&certified, original.verifying_key());
        let signature: Signature = original.sign(b"header.payload");
        certified.verify(b"header.payload", &signature)?;
        assert!(certified.verify(b"modified.payload", &signature).is_err());
        let mut restored = output;
        restored["keys"][0].as_object_mut().unwrap().remove("x5c");
        assert_eq!(restored, document);
        Ok(())
    }

    #[test]
    fn certificate_is_signed_by_issuer() -> anyhow::Result<()> {
        let issuer = SigningKey::try_generate_from_rng(&mut SysRng)?;
        let original = SigningKey::try_generate_from_rng(&mut SysRng)?;
        let cert = create_certificate(
            SubjectPublicKeyInfoOwned::from_key(original.verifying_key())?,
            &issuer,
        )?;
        let signature = DerSignature::from_bytes(cert.signature().as_bytes().unwrap())?;
        let tbs = cert.tbs_certificate().to_der()?;
        issuer.verifying_key().verify(&tbs, &signature)?;
        assert!(original.verifying_key().verify(&tbs, &signature).is_err());
        Ok(())
    }

    #[test]
    fn preserves_existing_certificates() -> anyhow::Result<()> {
        let body = br#"{"keys": [{"x5c": ["existing"]}], "extra": 1}"#;
        let output: Value = serde_json::from_slice(&add_x5c(body)?)?;
        assert_eq!(output, serde_json::from_slice::<Value>(body)?);
        assert!(add_x5c(br#"{"keys":[{"kty":"EC"}]}"#).is_err());
        Ok(())
    }

    #[test]
    fn supports_rsa_public_keys() -> anyhow::Result<()> {
        // Fixed public key: this test exercises encoding, not RSA key generation.
        let public = RsaPublicKey::from_public_key_pem(
            "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSR+XY9rMsRgj7yrz847
j5drDUKH5G7FrY5gXj9gUerAw4uUE00Zco901P12t5JMDB+J9jqNF/UtMP/sDf86
wBMV0qaEK3hR65ISP1H9lfeHQN/gHlKQrmOsnhRPd+sJ0ro+CPmX8TCMdTA3/jWT
MFImNh7FM0H7g+jSgkUjSg50+pNACKGXMGIHLFiNiLncSbBLww2Or79BwKSq+8tT
K4kTawX4BNn3oy+G1XNIFjOdcBd8BAS9IUMc9WMf/p5OsIMKosoz/ZbGyu3RdTu1
Zb34vge2J5VZONLvqHJIkgqmGPenj921fSPYWvncQJsE/lyg+icPFpVnVwIS6SMK
LQIDAQAB
-----END PUBLIC KEY-----
",
        )?;
        let document = json!({"keys": [{
            "kty": "RSA", "n": URL_SAFE_NO_PAD.encode(public.n().to_be_bytes_trimmed_vartime()),
            "e": URL_SAFE_NO_PAD.encode(public.e().to_be_bytes_trimmed_vartime())
        }]});
        let (_, cert) = transform_certificate(&document)?;
        let certified = RsaPublicKey::from_public_key_der(
            &cert.tbs_certificate().subject_public_key_info().to_der()?,
        )?;
        assert_eq!(certified, public);
        Ok(())
    }

    #[test]
    fn supports_larger_ec_curves() -> anyhow::Result<()> {
        let p384 = p384::SecretKey::try_generate_from_rng(&mut SysRng)?.public_key();
        let p521 = p521::SecretKey::try_generate_from_rng(&mut SysRng)?.public_key();
        for (curve, point, expected) in [
            (
                "P-384",
                p384.to_sec1_point(false).as_bytes().to_vec(),
                p384.to_public_key_der()?,
            ),
            (
                "P-521",
                p521.to_sec1_point(false).as_bytes().to_vec(),
                p521.to_public_key_der()?,
            ),
        ] {
            let size = (point.len() - 1) / 2;
            let document = json!({"keys": [{
                "kty": "EC", "crv": curve,
                "x": URL_SAFE_NO_PAD.encode(&point[1..1 + size]),
                "y": URL_SAFE_NO_PAD.encode(&point[1 + size..])
            }]});
            let (_, cert) = transform_certificate(&document)?;
            assert_eq!(
                cert.tbs_certificate().subject_public_key_info().to_der()?,
                expected.as_bytes()
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_ec_points() {
        for size in [31, 32] {
            let document = json!({"keys": [{
                "kty": "EC", "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(vec![0; size]),
                "y": URL_SAFE_NO_PAD.encode(vec![0; size])
            }]});
            assert!(transform_certificate(&document).is_err());
        }
    }
}
