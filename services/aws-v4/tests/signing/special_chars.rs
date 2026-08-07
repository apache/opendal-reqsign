// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use super::{init_signing_test, load_static_credential, send_signed_request};
use anyhow::Result;
use http::{Method, Request, StatusCode};
use log::warn;
use percent_encoding::{utf8_percent_encode, AsciiSet};
use reqsign_aws_core::constants::AWS_URI_ENCODE_SET;
use std::str::FromStr;

/// Encode set for building request paths / object keys.
///
/// AWS UriEncode leaves unreserved characters unencoded (`A-Z a-z 0-9 - . _ ~`).
/// Path builders must additionally leave `/` unencoded so nested keys stay
/// literal path separators (e.g. `a/b/c.txt` → `/a/b/c.txt`), not a single
/// segment containing `%2F`.
///
/// This is distinct from SigV4 `canonical_uri`, which splits on `/`, encodes
/// each segment with [`AWS_URI_ENCODE_SET`] (where `/` remains in the set),
/// then rejoins with `/`. Do not change `AWS_URI_ENCODE_SET` for path building.
static AWS_PATH_ENCODE_SET: AsciiSet = AWS_URI_ENCODE_SET.remove(b'/');

fn encode_object_key(key: &str) -> String {
    utf8_percent_encode(key, &AWS_PATH_ENCODE_SET).to_string()
}

#[tokio::test]
async fn test_head_object_with_special_characters() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    // Keep `/` in the key. Path encoding must leave it as a separator so the
    // wire URI is two segments (...%2C / %3F.txt), not one segment with %2F.
    let key = "!@#$%^&*()_+-=;:'><,/?.txt";

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, encode_object_key(key)))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_encoded_characters() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        encode_object_key("test file with spaces.txt")
    ))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_object_with_unicode_characters() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() =
        http::Uri::from_str(&format!("{}/{}", url, encode_object_key("文件名.txt")))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_nested_key_path() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    // Nested object keys must keep literal `/` separators on the wire.
    let key = "dir/sub/not_exist.txt";

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, encode_object_key(key)))?;

    let encoded = encode_object_key(key);
    assert!(
        encoded.contains('/'),
        "path builder must leave `/` unencoded, got {encoded}"
    );
    assert!(
        !encoded.contains("%2F") && !encoded.contains("%2f"),
        "path builder must not encode `/` as %2F, got {encoded}"
    );

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}
