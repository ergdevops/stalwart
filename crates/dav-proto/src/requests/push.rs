/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{DavParser, Token, tokenizer::Tokenizer},
    schema::{
        Element, NamedElement, Namespace, property::PushDepth, request::PushRegister,
    },
};

impl DavParser for PushRegister {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut register = PushRegister::default();

        // Tolerate an empty body; the handler will reject with the appropriate
        // precondition.
        if !stream.expect_named_element_or_eof(NamedElement {
            ns: Namespace::Push,
            element: Element::PushRegister,
        })? {
            return Ok(register);
        }

        // The body nests <subscription>/<web-push-subscription> and <trigger>
        // containers. We descend into known containers (by not seeking to their
        // end) and capture the leaf values regardless of nesting.
        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Push,
                            element,
                        },
                    ..
                } => match element {
                    Element::PushResource => {
                        register.push_resource = non_empty(stream.collect_string_value()?);
                    }
                    Element::ContentEncoding => {
                        register.content_encoding = non_empty(stream.collect_string_value()?);
                    }
                    Element::SubscriptionPublicKey => {
                        register.subscription_public_key =
                            non_empty(stream.collect_string_value()?);
                    }
                    Element::AuthSecret => {
                        register.auth_secret = non_empty(stream.collect_string_value()?);
                    }
                    Element::Expires => {
                        register.expires = non_empty(stream.collect_string_value()?);
                    }
                    Element::ContentUpdate => {
                        register.content_update = Some(read_depth(stream)?);
                    }
                    Element::PropertyUpdate => {
                        register.property_update = Some(read_depth(stream)?);
                    }
                    // Containers: descend (do not consume to end).
                    Element::Subscription
                    | Element::WebPushSubscription
                    | Element::Trigger => {}
                    _ => {
                        stream.seek_element_end()?;
                    }
                },
                Token::ElementStart { .. } | Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                Token::ElementEnd => {}
                Token::Eof => break,
                _ => {}
            }
        }

        Ok(register)
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Reads the `<D:depth>` value within a trigger container, consuming the
/// container up to and including its closing tag. Defaults to depth `1` if no
/// depth element is present.
fn read_depth(stream: &mut Tokenizer<'_>) -> crate::parser::Result<PushDepth> {
    let mut depth = PushDepth::One;
    let mut nesting = 1usize;

    loop {
        match stream.token()? {
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Depth,
                    },
                ..
            } => {
                if let Some(value) = stream.collect_string_value()? {
                    depth = parse_depth(&value);
                }
            }
            Token::ElementStart { .. } | Token::UnknownElement(_) => {
                stream.seek_element_end()?;
            }
            Token::ElementEnd => {
                nesting -= 1;
                if nesting == 0 {
                    break;
                }
            }
            Token::Eof => break,
            _ => {}
        }
    }

    Ok(depth)
}

fn parse_depth(value: &str) -> PushDepth {
    match value.trim() {
        "0" => PushDepth::Zero,
        "infinity" => PushDepth::Infinity,
        _ => PushDepth::One,
    }
}
