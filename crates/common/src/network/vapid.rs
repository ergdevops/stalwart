/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! VAPID (RFC 8292) key management for WebDAV-Push (and Web Push) delivery.
//!
//! A single P-256 (ES256) keypair is generated on first use and persisted in
//! the shared data store, so it is stable across restarts and identical on
//! every cluster node. Clients fetch the public key via the WebDAV-Push
//! `transports` PROPFIND property and use it to create restricted Web Push
//! subscriptions; the server then proves its identity by signing a JWT for
//! each push message.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use store::{
    Deserialize, SUBSPACE_PROPERTY,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};
use trc::AddContext;

use crate::Server;

/// Well-known key under [`SUBSPACE_PROPERTY`] that stores the PKCS#8 DER bytes
/// of the server-wide VAPID private key. Multi-byte to avoid colliding with the
/// single-byte schema-version key.
const VAPID_STORE_KEY: &[u8] = b"vapid-p256";

/// Default lifetime of a signed VAPID JWT.
pub const VAPID_TOKEN_TTL_SECS: u64 = 12 * 60 * 60;

pub struct VapidKeyPair {
    key_pair: EcdsaKeyPair,
    /// Base64url-encoded uncompressed (SEC1) public key, as required by both the
    /// `vapid-public-key` property and the VAPID `Authorization` header `k`
    /// parameter.
    public_key: String,
}

struct RawBytes(Vec<u8>);

impl Deserialize for RawBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawBytes(bytes.to_vec()))
    }
}

impl VapidKeyPair {
    fn from_pkcs8(der: &[u8]) -> trc::Result<Self> {
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new())
                .map_err(|err| {
                    trc::StoreEvent::DataCorruption
                        .into_err()
                        .details("Failed to parse VAPID PKCS#8 key")
                        .ctx(trc::Key::Reason, err.to_string())
                })?;
        let public_key = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
        Ok(VapidKeyPair {
            key_pair,
            public_key,
        })
    }

    /// Base64url-encoded uncompressed public key.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Builds a VAPID `Authorization` header value (RFC 8292 section 4.2) for a
    /// push message sent to the given endpoint.
    ///
    /// `audience` MUST be the origin (scheme + host[:port]) of the push
    /// resource; `subject` is a contact URI (`mailto:` or `https:`).
    pub fn authorization_header(
        &self,
        audience: &str,
        subject: &str,
        expires_at: u64,
    ) -> trc::Result<String> {
        let jwt = self.sign_jwt(audience, subject, expires_at)?;
        Ok(format!("vapid t={jwt}, k={}", self.public_key))
    }

    /// Signs an ES256 JWT with the VAPID claims.
    pub fn sign_jwt(&self, audience: &str, subject: &str, expires_at: u64) -> trc::Result<String> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = format!(
            "{{\"aud\":{},\"exp\":{},\"sub\":{}}}",
            json_string(audience),
            expires_at,
            json_string(subject),
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let signature = self
            .key_pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .into_err()
                    .details("Failed to sign VAPID token")
                    .ctx(trc::Key::Reason, err.to_string())
            })?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

impl Server {
    /// Returns the server-wide VAPID keypair, generating and persisting it on
    /// first use. The key is cached in memory after the first load.
    pub async fn vapid_keypair(&self) -> trc::Result<Arc<VapidKeyPair>> {
        if let Some(key) = self.inner.data.vapid_keys.lock().clone() {
            return Ok(key);
        }

        let der = match self.load_vapid_pkcs8().await? {
            Some(der) => der,
            None => self.generate_vapid_pkcs8().await?,
        };

        let key = Arc::new(VapidKeyPair::from_pkcs8(&der)?);
        *self.inner.data.vapid_keys.lock() = Some(key.clone());
        Ok(key)
    }

    async fn load_vapid_pkcs8(&self) -> trc::Result<Option<Vec<u8>>> {
        Ok(self
            .store()
            .get_value::<RawBytes>(AnyKey {
                subspace: SUBSPACE_PROPERTY,
                key: VAPID_STORE_KEY.to_vec(),
            })
            .await
            .caused_by(trc::location!())?
            .map(|raw| raw.0))
    }

    async fn generate_vapid_pkcs8(&self) -> trc::Result<Vec<u8>> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|err| {
                    trc::EventType::Server(trc::ServerEvent::ThreadError)
                        .into_err()
                        .details("Failed to generate VAPID key")
                        .ctx(trc::Key::Reason, err.to_string())
                })?;
        let der = document.as_ref().to_vec();

        // Persist with a compare-and-set so that, in a cluster, only the first
        // node to write wins; the others fall back to re-reading the value.
        let class = ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: VAPID_STORE_KEY.to_vec(),
        });
        let mut batch = BatchBuilder::new();
        batch.assert_value(class.clone(), ()).set(class, der.clone());

        match self.store().write(batch.build_all()).await {
            Ok(_) => Ok(der),
            Err(_) => self.load_vapid_pkcs8().await?.ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Failed to persist VAPID key")
            }),
        }
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
