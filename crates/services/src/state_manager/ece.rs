/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! The "aes128gcm" Web Push content encoding lives in the `common` crate so it
//! can be shared between JMAP push subscriptions and WebDAV-Push delivery.

pub use common::network::ece::{ece_encrypt, generate_iv};
