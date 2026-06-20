/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Helpers for WebDAV-Push (<https://bitfire.at/webdav-push>) shared between
//! the DAV request handlers (which advertise the topic and register
//! subscriptions) and the push delivery service (which sends notifications).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

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
