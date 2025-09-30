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

use crate::constants::TENCENT_URI_ENCODE_SET;
use crate::Credential;
use async_trait::async_trait;
use http::header::{AUTHORIZATION, DATE};
use http::request::Parts;
use log::debug;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use reqsign_core::hash::{hex_hmac_sha1, hex_sha1};
use reqsign_core::time::{format_http_date, now, Timestamp};
use reqsign_core::{Context, Result, SignRequest, SigningRequest};
use std::time::Duration;

/// RequestSigner that implements Tencent COS signing.
///
/// - [Tencent COS Signature](https://cloud.tencent.com/document/product/436/7778)
#[derive(Debug, Default)]
pub struct RequestSigner {
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a new builder for Tencent COS signer.
    pub fn new() -> Self {
        Self { time: None }
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }
}

#[async_trait]
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let now = self.time.unwrap_or_else(now);
        let mut signing_req = SigningRequest::build(req)?;

        if let Some(expires) = expires_in {
            // Query signing
            let signature = build_signature(&mut signing_req, cred, now, expires);

            signing_req
                .headers
                .insert(DATE, format_http_date(now).parse()?);
            signing_req.query_append(&signature);

            if let Some(token) = &cred.security_token {
                signing_req.query_push(
                    "x-cos-security-token".to_string(),
                    utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC).to_string(),
                );
            }
        } else {
            // Header signing (default 3600s expiration)
            let signature = build_signature(&mut signing_req, cred, now, Duration::from_secs(3600));

            signing_req
                .headers
                .insert(DATE, format_http_date(now).parse()?);
            signing_req.headers.insert(AUTHORIZATION, {
                let mut value: http::HeaderValue = signature.parse()?;
                value.set_sensitive(true);
                value
            });

            if let Some(token) = &cred.security_token {
                signing_req.headers.insert("x-cos-security-token", {
                    let mut value: http::HeaderValue = token.parse()?;
                    value.set_sensitive(true);
                    value
                });
            }
        }

        signing_req.apply(req)
    }
}

fn build_signature(
    ctx: &mut SigningRequest,
    cred: &Credential,
    now: Timestamp,
    expires: Duration,
) -> String {
    let key_time = format!(
        "{};{}",
        now.as_second(),
        (now + jiff::SignedDuration::try_from(expires).unwrap()).as_second()
    );

    let sign_key = hex_hmac_sha1(cred.secret_key.as_bytes(), key_time.as_bytes());

    let mut params = ctx
        .query
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(&k.to_lowercase(), &TENCENT_URI_ENCODE_SET).to_string(),
                utf8_percent_encode(v, &TENCENT_URI_ENCODE_SET).to_string(),
            )
        })
        .collect::<Vec<_>>();
    params.sort();

    let param_list = params
        .iter()
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>()
        .join(";");
    debug!("param list: {param_list}");
    let param_string = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    debug!("param string: {param_string}");

    let mut headers = ctx
        .header_to_vec_with_prefix("")
        .iter()
        .map(|(k, v)| {
            (
                k.to_lowercase(),
                utf8_percent_encode(v, &TENCENT_URI_ENCODE_SET).to_string(),
            )
        })
        .collect::<Vec<_>>();
    headers.sort();

    let header_list = headers
        .iter()
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>()
        .join(";");
    debug!("header list: {header_list}");
    let header_string = headers
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    debug!("header string: {header_string}");

    let mut http_string = String::new();

    http_string.push_str(&ctx.method.as_str().to_ascii_lowercase());
    http_string.push('\n');
    http_string.push_str(&percent_decode_str(&ctx.path).decode_utf8_lossy());
    http_string.push('\n');
    http_string.push_str(&param_string);
    http_string.push('\n');
    http_string.push_str(&header_string);
    http_string.push('\n');
    debug!("http string: {http_string}");

    let mut string_to_sign = String::new();
    string_to_sign.push_str("sha1");
    string_to_sign.push('\n');
    string_to_sign.push_str(&key_time);
    string_to_sign.push('\n');
    string_to_sign.push_str(&hex_sha1(http_string.as_bytes()));
    string_to_sign.push('\n');
    debug!("string_to_sign: {string_to_sign}");

    let signature = hex_hmac_sha1(sign_key.as_bytes(), string_to_sign.as_bytes());

    format!("q-sign-algorithm=sha1&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}", cred.secret_id, key_time, key_time, header_list, param_list, signature)
}
