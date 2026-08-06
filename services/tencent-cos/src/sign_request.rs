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

use crate::Credential;
use crate::constants::TENCENT_URI_ENCODE_SET;
use http::Uri;
use http::header::{AUTHORIZATION, DATE};
use http::request::Parts;
use log::debug;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use reqsign_core::hash::{hex_hmac_sha1, hex_sha1};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Result, SignRequest, SigningCredential, SigningRequest};
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

    fn get_time(&self) -> Timestamp {
        self.time.unwrap_or_else(Timestamp::now)
    }

    fn required_valid_until_at(
        &self,
        signing_time: Timestamp,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        let signature_lifetime = expires_in.unwrap_or_else(|| Duration::from_secs(3600));
        signing_time + signature_lifetime
    }
}
impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        self.required_valid_until_at(self.get_time(), expires_in)
    }

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

        let now = self.get_time();
        let required_until = self.required_valid_until_at(now, expires_in);
        if !cred.is_valid_at(required_until) {
            return Err(reqsign_core::Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }

        let original_uri = req.uri.clone();
        let mut signing_req = SigningRequest::build(req)?;

        let final_uri = if let Some(expires) = expires_in {
            // Query signing
            let signature = build_signature(&signing_req, cred, now, expires);

            signing_req
                .headers
                .insert(DATE, now.format_http_date().parse()?);
            let mut authentication = signature;

            if let Some(token) = &cred.security_token {
                authentication.push_str("&x-cos-security-token=");
                authentication.push_str(
                    &utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC).to_string(),
                );
            }
            Some(append_query_fragment(&original_uri, &authentication)?)
        } else {
            // Header signing (default 3600s expiration)
            let signature = build_signature(&signing_req, cred, now, Duration::from_secs(3600));

            signing_req
                .headers
                .insert(DATE, now.format_http_date().parse()?);
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
            None
        };

        signing_req.apply(req)?;
        if let Some(uri) = final_uri {
            req.uri = uri;
        }
        Ok(())
    }
}

fn build_signature(
    ctx: &SigningRequest,
    cred: &Credential,
    now: Timestamp,
    expires: Duration,
) -> String {
    let key_time = format!("{};{}", now.as_second(), (now + expires).as_second());
    let sign_key = hex_hmac_sha1(cred.secret_key.as_bytes(), key_time.as_bytes());

    let (param_list, param_string) = canonical_query(ctx);
    debug!("param list: {param_list}");
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

    format!(
        "q-sign-algorithm=sha1&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}",
        cred.secret_id, key_time, key_time, header_list, param_list, signature
    )
}

fn canonical_query(ctx: &SigningRequest) -> (String, String) {
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
    let param_string = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    (param_list, param_string)
}

fn append_query_fragment(uri: &Uri, fragment: &str) -> Result<Uri> {
    let mut value = uri.to_string();
    if uri.query().is_none() {
        value.push('?');
    } else if !value.ends_with('?') && !value.ends_with('&') {
        value.push('&');
    }
    value.push_str(fragment);

    value.parse().map_err(|e| {
        reqsign_core::Error::request_invalid("failed to append COS signing query").with_source(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_QUERY: &str = "versionId=a%2Bb%3Dc%2525%26e&slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

    #[test]
    fn deadline_matches_actual_signature_lifetime() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new().with_time(now);
        let credential = Credential::default();

        assert_eq!(
            signer.required_valid_until(&credential, None),
            now + Duration::from_secs(3600)
        );
        assert_eq!(
            signer.required_valid_until(&credential, Some(Duration::from_secs(60))),
            now + Duration::from_secs(60)
        );
        Ok(())
    }

    #[tokio::test]
    async fn canonicalization_and_signing_preserve_wire_uri() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new().with_time(now);
        let credential = Credential {
            secret_id: "secret_id".to_string(),
            secret_key: "secret_key".to_string(),
            ..Default::default()
        };
        let original_uri = format!("https://example.com/object%2Fname?{RAW_QUERY}");

        let mut canonical_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        let signing_req = SigningRequest::build(&mut canonical_parts)?;
        let (param_list, param_string) = canonical_query(&signing_req);
        assert!(param_list.contains("literal-plus"));
        assert!(param_string.contains("literal-plus=%2B"));
        assert!(param_string.contains("double=%252F"));
        assert!(param_string.contains("versionid=a%2Bb%3Dc%2525%26e"));
        assert!(param_string.contains("flag="));

        let mut header_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        signer
            .sign_request(&Context::new(), &mut header_parts, Some(&credential), None)
            .await?;
        assert_eq!(header_parts.uri.to_string(), original_uri);

        let mut query_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        signer
            .sign_request(
                &Context::new(),
                &mut query_parts,
                Some(&credential),
                Some(Duration::from_secs(60)),
            )
            .await?;
        assert!(
            query_parts
                .uri
                .to_string()
                .starts_with(&format!("{original_uri}q-sign-algorithm="))
        );
        assert!(query_parts.uri.query().unwrap().contains("q-signature="));

        Ok(())
    }
}
