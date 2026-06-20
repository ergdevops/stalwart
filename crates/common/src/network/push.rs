/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! WebDAV-Push (<https://bitfire.at/webdav-push>) subscription storage and
//! delivery, shared between the DAV request handlers (which advertise topics
//! and register/unregister subscriptions) and the change-notification path in
//! [`crate::Server::commit_batch`] (which delivers encrypted Web Push messages).
//!
//! Delivery is always triggered from the node that performed the write, so no
//! cluster-wide de-duplication is required. Every delivery runs in a detached
//! task and never propagates errors back into the write path.

use std::time::Duration;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use reqwest::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

use crate::{Server, network::vapid::VAPID_TOKEN_TTL_SECS};

/// Default subscription lifetime when the client does not supply (or supplies an
/// unparsable) `<P:expires>` value.
const DEFAULT_SUBSCRIPTION_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// Hard cap on a subscription lifetime, regardless of the requested expiry.
const MAX_SUBSCRIPTION_TTL_SECS: u64 = 90 * 24 * 60 * 60;
/// Timeout for an individual push delivery request.
const PUSH_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Default, Debug, Clone, PartialEq, Eq,
)]
pub struct DavPushSubscriptions {
    pub subscriptions: Vec<DavPushSubscription>,
    pub next_id: u32,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DavPushSubscription {
    /// Server-assigned id, used to build the (DELETE-able) registration URL.
    pub id: u32,
    /// [`SyncCollection`] of the subscribed collection, encoded as `u8`.
    pub sync_collection: u8,
    /// Document id of the subscribed collection.
    pub document_id: u32,
    /// Opaque topic advertised for this collection (see [`push_topic`]).
    pub topic: String,
    /// Web Push endpoint (the `push-resource`).
    pub push_resource: String,
    /// Decoded subscription public key (uncompressed SEC1, 65 bytes).
    pub p256dh: Vec<u8>,
    /// Decoded auth secret (16 bytes).
    pub auth: Vec<u8>,
    /// Whether the client requested content-update triggers.
    pub content_update: bool,
    /// Whether the client requested property-update triggers.
    pub property_update: bool,
    /// Expiry, as a unix timestamp in seconds.
    pub expires: u64,
}

/// Computes a stable, server-wide-unique opaque WebDAV-Push topic for a
/// resource, identified by its account id, sync collection and document id.
///
/// The encoding is deterministic so that both the advertising side (PROPFIND)
/// and the delivery side (push message) derive the same value for a given
/// resource.
pub fn push_topic(account_id: u32, sync_collection: u8, document_id: u32) -> String {
    let mut buf = [0u8; 9];
    buf[..4].copy_from_slice(&account_id.to_be_bytes());
    buf[4] = sync_collection;
    buf[5..].copy_from_slice(&document_id.to_be_bytes());
    URL_SAFE_NO_PAD.encode(buf)
}

/// Decodes a base64 value that may be supplied in any of the common
/// (url-safe/standard, padded/unpadded) alphabets.
pub fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .ok()
}

/// Parses a WebDAV-Push `<P:expires>` HTTP-date into a unix timestamp, clamped
/// to a sane range. Falls back to a default lifetime when absent/unparsable.
pub fn parse_expires(value: Option<&str>) -> u64 {
    let current_time = now();
    let requested = value
        .and_then(|v| chrono::DateTime::parse_from_rfc2822(v.trim()).ok())
        .map(|dt| dt.timestamp().max(0) as u64)
        .filter(|&ts| ts > current_time)
        .unwrap_or(current_time + DEFAULT_SUBSCRIPTION_TTL_SECS);

    requested.min(current_time + MAX_SUBSCRIPTION_TTL_SECS)
}

fn subscriptions_key(account_id: u32) -> ValueKey<store::write::ValueClass> {
    ValueKey::property(
        account_id,
        Collection::Principal,
        0,
        PrincipalField::DavPushSubscriptions,
    )
}

impl Server {
    /// Loads the WebDAV-Push subscriptions for an account.
    pub async fn dav_push_subscriptions(
        &self,
        account_id: u32,
    ) -> trc::Result<DavPushSubscriptions> {
        match self
            .store()
            .get_value::<Archive<AlignedBytes>>(subscriptions_key(account_id))
            .await
            .caused_by(trc::location!())?
        {
            Some(archive) => archive
                .deserialize::<DavPushSubscriptions>()
                .caused_by(trc::location!()),
            None => Ok(DavPushSubscriptions::default()),
        }
    }

    /// Registers (or, when a matching collection/endpoint already exists,
    /// updates) a WebDAV-Push subscription and returns its server-assigned id.
    pub async fn dav_push_register(
        &self,
        account_id: u32,
        mut subscription: DavPushSubscription,
    ) -> trc::Result<u32> {
        for _ in 0..4 {
            let archive = self
                .store()
                .get_value::<Archive<AlignedBytes>>(subscriptions_key(account_id))
                .await
                .caused_by(trc::location!())?;
            let mut subs = match &archive {
                Some(archive) => archive
                    .deserialize::<DavPushSubscriptions>()
                    .caused_by(trc::location!())?,
                None => DavPushSubscriptions::default(),
            };

            // Drop expired entries so they do not accumulate.
            let current_time = now();
            subs.subscriptions.retain(|s| s.expires > current_time);

            // A subscription is uniquely identified by its endpoint for a given
            // collection: update in place if it already exists.
            let assigned_id = if let Some(existing) = subs.subscriptions.iter_mut().find(|s| {
                s.sync_collection == subscription.sync_collection
                    && s.document_id == subscription.document_id
                    && s.push_resource == subscription.push_resource
            }) {
                let id = existing.id;
                subscription.id = id;
                *existing = subscription.clone();
                id
            } else {
                subs.next_id = subs.next_id.checked_add(1).unwrap_or(1).max(1);
                let id = subs.next_id;
                subscription.id = id;
                subs.subscriptions.push(subscription.clone());
                id
            };

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);
            if let Some(archive) = &archive {
                batch.assert_value(PrincipalField::DavPushSubscriptions, archive);
            } else {
                batch.assert_value(PrincipalField::DavPushSubscriptions, ());
            }
            batch.set(
                PrincipalField::DavPushSubscriptions,
                Archiver::new(subs)
                    .serialize()
                    .caused_by(trc::location!())?,
            );

            match self.commit_batch(batch).await {
                Ok(_) => return Ok(assigned_id),
                Err(err) if err.is_assertion_failure() => continue,
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }

        Err(trc::StoreEvent::AssertValueFailed
            .into_err()
            .details("Failed to register WebDAV-Push subscription after multiple attempts"))
    }

    /// Removes a WebDAV-Push subscription by id. Returns `true` when a matching
    /// subscription existed.
    pub async fn dav_push_unregister(&self, account_id: u32, id: u32) -> trc::Result<bool> {
        for _ in 0..4 {
            let Some(archive) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(subscriptions_key(account_id))
                .await
                .caused_by(trc::location!())?
            else {
                return Ok(false);
            };
            let mut subs = archive
                .deserialize::<DavPushSubscriptions>()
                .caused_by(trc::location!())?;

            let before = subs.subscriptions.len();
            subs.subscriptions.retain(|s| s.id != id);
            if subs.subscriptions.len() == before {
                return Ok(false);
            }

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(PrincipalField::DavPushSubscriptions, &archive);
            if subs.subscriptions.is_empty() {
                batch.clear(PrincipalField::DavPushSubscriptions);
            } else {
                batch.set(
                    PrincipalField::DavPushSubscriptions,
                    Archiver::new(subs)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
            }

            match self.commit_batch(batch).await {
                Ok(_) => return Ok(true),
                Err(err) if err.is_assertion_failure() => continue,
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }

        Ok(false)
    }

    /// Spawns a detached task that delivers WebDAV-Push notifications for the
    /// collections that changed in `account_id`. Never blocks or fails the
    /// caller (the write path).
    pub fn notify_webdav_push(&self, account_id: u32, collections: Vec<SyncCollection>) {
        let server = self.clone();
        tokio::spawn(async move {
            if let Err(err) = server.deliver_webdav_push(account_id, &collections).await {
                trc::error!(err.caused_by(trc::location!()));
            }
        });
    }

    async fn deliver_webdav_push(
        &self,
        account_id: u32,
        collections: &[SyncCollection],
    ) -> trc::Result<()> {
        let archive = match self
            .store()
            .get_value::<Archive<AlignedBytes>>(subscriptions_key(account_id))
            .await
            .caused_by(trc::location!())?
        {
            Some(archive) => archive,
            None => return Ok(()),
        };
        let mut subs = archive
            .deserialize::<DavPushSubscriptions>()
            .caused_by(trc::location!())?;

        // Prune expired subscriptions.
        let current_time = now();
        let before = subs.subscriptions.len();
        subs.subscriptions.retain(|s| s.expires > current_time);
        let mut changed = subs.subscriptions.len() != before;

        let wanted: Vec<u8> = collections.iter().map(|c| u8::from(*c)).collect();
        let targets: Vec<DavPushSubscription> = subs
            .subscriptions
            .iter()
            .filter(|s| s.content_update && wanted.contains(&s.sync_collection))
            .cloned()
            .collect();

        if !targets.is_empty() {
            let vapid = self.vapid_keypair().await.caused_by(trc::location!())?;
            let subject = format!("mailto:postmaster@{}", self.core.network.server_name);
            let mut gone = Vec::new();

            for target in targets {
                if matches!(
                    self.send_webdav_push(&vapid, &subject, &target).await,
                    PushOutcome::Gone
                ) {
                    gone.push(target.id);
                }
            }

            if !gone.is_empty() {
                subs.subscriptions.retain(|s| !gone.contains(&s.id));
                changed = true;
            }
        }

        if changed {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(PrincipalField::DavPushSubscriptions, &archive);
            if subs.subscriptions.is_empty() {
                batch.clear(PrincipalField::DavPushSubscriptions);
            } else {
                batch.set(
                    PrincipalField::DavPushSubscriptions,
                    Archiver::new(subs)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
            }
            // Best-effort: a concurrent registration may have updated the value.
            let _ = self.commit_batch(batch).await;
        }

        Ok(())
    }

    async fn send_webdav_push(
        &self,
        vapid: &crate::network::vapid::VapidKeyPair,
        subject: &str,
        subscription: &DavPushSubscription,
    ) -> PushOutcome {
        let body = push_message_body(&subscription.topic);
        let encrypted =
            match crate::network::ece::ece_encrypt(&subscription.p256dh, &subscription.auth, body.as_bytes()) {
                Ok(encrypted) => encrypted,
                Err(err) => {
                    trc::event!(
                        PushSubscription(trc::PushSubscriptionEvent::Error),
                        Details = "Failed to encrypt WebDAV-Push message",
                        Url = subscription.push_resource.clone(),
                        Reason = err,
                    );
                    return PushOutcome::Failed;
                }
            };

        let url = match reqwest::Url::parse(&subscription.push_resource) {
            Ok(url) => url,
            Err(err) => {
                trc::event!(
                    PushSubscription(trc::PushSubscriptionEvent::Error),
                    Details = "Invalid WebDAV-Push endpoint",
                    Url = subscription.push_resource.clone(),
                    Reason = err.to_string(),
                );
                return PushOutcome::Failed;
            }
        };
        let audience = url.origin().ascii_serialization();

        let authorization =
            match vapid.authorization_header(&audience, subject, now() + VAPID_TOKEN_TTL_SECS) {
                Ok(header) => header,
                Err(err) => {
                    trc::error!(err.caused_by(trc::location!()));
                    return PushOutcome::Failed;
                }
            };

        let client_builder = reqwest::Client::builder().timeout(PUSH_DELIVERY_TIMEOUT);
        #[cfg(feature = "test_mode")]
        let client_builder = client_builder.danger_accept_invalid_certs(true);
        let client = match client_builder.build() {
            Ok(client) => client,
            Err(err) => {
                trc::error!(
                    trc::EventType::Server(trc::ServerEvent::ThreadError)
                        .into_err()
                        .reason(err)
                        .caused_by(trc::location!())
                );
                return PushOutcome::Failed;
            }
        };

        match client
            .post(subscription.push_resource.as_str())
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_ENCODING, "aes128gcm")
            .header("TTL", "86400")
            .header("Urgency", "normal")
            .header(AUTHORIZATION, authorization)
            .body(encrypted)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    trc::event!(
                        PushSubscription(trc::PushSubscriptionEvent::Success),
                        Url = subscription.push_resource.clone(),
                    );
                    PushOutcome::Success
                } else if status == reqwest::StatusCode::NOT_FOUND
                    || status == reqwest::StatusCode::GONE
                {
                    trc::event!(
                        PushSubscription(trc::PushSubscriptionEvent::Error),
                        Details = "WebDAV-Push endpoint gone, removing subscription",
                        Url = subscription.push_resource.clone(),
                        Code = status.as_u16(),
                    );
                    PushOutcome::Gone
                } else {
                    trc::event!(
                        PushSubscription(trc::PushSubscriptionEvent::Error),
                        Details = "WebDAV-Push delivery failed",
                        Url = subscription.push_resource.clone(),
                        Code = status.as_u16(),
                    );
                    PushOutcome::Failed
                }
            }
            Err(err) => {
                trc::event!(
                    PushSubscription(trc::PushSubscriptionEvent::Error),
                    Details = "WebDAV-Push delivery failed",
                    Url = subscription.push_resource.clone(),
                    Reason = err.to_string(),
                );
                PushOutcome::Failed
            }
        }
    }
}

enum PushOutcome {
    Success,
    Failed,
    Gone,
}

fn push_message_body(topic: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<P:push-message xmlns:D=\"DAV:\" xmlns:P=\"https://bitfire.at/webdav-push\">",
            "<D:propstat><D:prop><P:topic>{}</P:topic></D:prop></D:propstat>",
            "</P:push-message>"
        ),
        topic
    )
}
