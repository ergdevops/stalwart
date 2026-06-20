/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! WebDAV-Push (<https://bitfire.at/webdav-push>) subscription management.
//!
//! Registration is a `POST` of a `<P:push-register>` document to a push-capable
//! collection (calendar or address book). The server stores the subscription
//! and returns a registration URL under `/dav/push/`, which the client may
//! later `DELETE` to unsubscribe.

use crate::{DavError, common::uri::DavUriResource};
use common::{
    Server,
    auth::AccessToken,
    network::push::{DavPushSubscription, decode_base64, parse_expires, push_topic},
};
use dav_proto::{
    RequestHeaders,
    parser::{DavParser, tokenizer::Tokenizer},
    schema::request::PushRegister,
};
use groupware::{DavResourceName, cache::GroupwareCache};
use http_proto::HttpResponse;
use hyper::StatusCode;
use trc::AddContext;
use types::collection::SyncCollection;

/// Length of an uncompressed SEC1 P-256 public key (the `p256dh` value).
const P256DH_LEN: usize = 65;

pub(crate) trait DavPushHandler: Sync + Send {
    fn handle_push_register(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        collection: SyncCollection,
        body: Vec<u8>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_push_unregister(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl DavPushHandler for Server {
    async fn handle_push_register(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        collection: SyncCollection,
        body: Vec<u8>,
    ) -> crate::Result<HttpResponse> {
        // Resolve the target collection.
        let uri = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = uri.account_id;
        let resource_path = uri
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?;

        let resources = self
            .fetch_dav_resources(access_token.account_id(), account_id, collection)
            .await
            .caused_by(trc::location!())?;
        let resource = resources
            .by_path(resource_path)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        // WebDAV-Push subscriptions are registered against collections only.
        if !resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }
        let document_id = resource.document_id();

        // Parse the registration request.
        let register = PushRegister::parse(&mut Tokenizer::new(&body))?;

        let push_resource = register
            .push_resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::BAD_REQUEST))?;
        let p256dh = register
            .subscription_public_key
            .as_deref()
            .and_then(decode_base64)
            .filter(|k| k.len() == P256DH_LEN)
            .ok_or(DavError::Code(StatusCode::BAD_REQUEST))?;
        let auth = register
            .auth_secret
            .as_deref()
            .and_then(decode_base64)
            .filter(|k| !k.is_empty())
            .ok_or(DavError::Code(StatusCode::BAD_REQUEST))?;

        // Default to a content-update subscription when no trigger is requested.
        let content_update = register.content_update.is_some() || register.property_update.is_none();
        let property_update = register.property_update.is_some();
        let expires = parse_expires(register.expires.as_deref());
        let sync_collection = u8::from(collection);

        let subscription = DavPushSubscription {
            id: 0,
            sync_collection,
            document_id,
            topic: push_topic(account_id, sync_collection, document_id),
            push_resource,
            p256dh,
            auth,
            content_update,
            property_update,
            expires,
        };

        let id = self
            .dav_push_register(account_id, subscription)
            .await
            .caused_by(trc::location!())?;

        let location = format!("{}/_{account_id}/{id}", DavResourceName::Push.base_path());

        Ok(HttpResponse::new(StatusCode::CREATED).with_location(location))
    }

    async fn handle_push_unregister(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        let uri = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = uri.account_id;

        // Only members of the account may manage its push subscriptions.
        if !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let id = uri
            .resource
            .and_then(|r| r.trim_matches('/').parse::<u32>().ok())
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        if self
            .dav_push_unregister(account_id, id)
            .await
            .caused_by(trc::location!())?
        {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT))
        } else {
            Err(DavError::Code(StatusCode::NOT_FOUND))
        }
    }
}
