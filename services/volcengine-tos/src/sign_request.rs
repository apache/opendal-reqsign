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

use std::fmt::Write;
use std::sync::LazyLock;

use async_trait::async_trait;
use http::header::AUTHORIZATION;
use http::{HeaderName, HeaderValue, header};
use log::debug;
use percent_encoding::percent_decode_str;
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Result, SignRequest, SigningRequest};

use crate::constants::*;
use crate::credential::Credential;
use crate::uri::{percent_encode_path, percent_encode_query};

static HEADER_TOS_DATE: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-tos-date"));
static HEADER_TOS_SECURITY_TOKEN: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-tos-security-token"));

/// RequestSigner that implements Volcengine TOS signing.
///
/// - [Volcengine TOS Signature](https://www.volcengine.com/docs/6349/1747874)
#[derive(Debug)]
pub struct RequestSigner {
    region: String,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a new RequestSigner for the given region.
    pub fn new(region: &str) -> Self {
        Self {
            region: region.to_string(),
            time: None,
        }
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
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        _expires_in: Option<std::time::Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let now = self.time.unwrap_or_else(Timestamp::now);

        let mut signing_req = SigningRequest::build(req)?;

        // Insert HOST header if not present.
        if signing_req.headers.get(header::HOST).is_none() {
            signing_req.headers.insert(
                header::HOST,
                signing_req.authority.as_str().parse().map_err(|e| {
                    reqsign_core::Error::unexpected(format!(
                        "failed to parse authority as header value: {e}"
                    ))
                })?,
            );
        }

        let date_str = now.format_iso8601();
        let date_only = now.format_date();

        signing_req
            .headers
            .insert(&*HEADER_TOS_DATE, date_str.parse()?);

        if let Some(token) = &cred.session_token {
            signing_req
                .headers
                .insert(&*HEADER_TOS_SECURITY_TOKEN, token.parse()?);
        }

        canonicalize_query(&mut signing_req);
        let (canonical_request_hash, _) = canonical_request_hash(&mut signing_req)?;

        // Scope: "<date>/<region>/tos/request"
        let credential_scope = format!("{}/{}/tos/request", date_only, self.region);

        // StringToSign:
        //
        // TOS4-HMAC-SHA256
        // <iso8601_date>
        // <scope>
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut s = String::new();
            writeln!(s, "TOS4-HMAC-SHA256")?;
            writeln!(s, "{}", date_str)?;
            writeln!(s, "{}", credential_scope)?;
            s.push_str(&canonical_request_hash);
            s
        };

        debug!("string to sign: {}", &string_to_sign);

        let signed_headers_str = signing_req.header_name_to_vec_sorted().join(";");

        let signing_key = generate_signing_key(&cred.secret_access_key, &date_only, &self.region);
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        let authorization = format!(
            "TOS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            cred.access_key_id, credential_scope, signed_headers_str, signature
        );

        debug!("authorization: {}", &authorization);

        let mut auth_value: HeaderValue = authorization.parse()?;
        auth_value.set_sensitive(true);
        signing_req.headers.insert(AUTHORIZATION, auth_value);

        signing_req.apply(req)
    }
}

fn canonicalize_query(ctx: &mut SigningRequest) {
    ctx.query = ctx
        .query
        .iter()
        .map(|(k, v)| (percent_encode_query(k), percent_encode_query(v)))
        .collect();
    // Sort by param name
    ctx.query.sort();
}

fn canonical_request_hash(ctx: &mut SigningRequest) -> Result<(String, String)> {
    let mut canonical_request = String::with_capacity(256);

    // Insert method
    canonical_request.push_str(ctx.method.as_str());
    canonical_request.push('\n');

    // Insert encoded path
    let path = percent_decode_str(&ctx.path)
        .decode_utf8()
        .map_err(|e| reqsign_core::Error::unexpected(format!("failed to decode path: {e}")))?;
    let canonical_path = percent_encode_path(&path);
    canonical_request.push_str(&canonical_path);
    canonical_request.push('\n');

    // Insert encoded query
    let query_string = ctx
        .query
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    canonical_request.push_str(&query_string);
    canonical_request.push('\n');

    // Insert signed headers
    let signed_headers = ctx.header_name_to_vec_sorted();

    for header in &signed_headers {
        let value = &ctx.headers[*header];
        canonical_request.push_str(header);
        canonical_request.push(':');
        if let Ok(value_str) = value.to_str() {
            canonical_request.push_str(value_str.trim());
        }
        canonical_request.push('\n');
    }

    canonical_request.push('\n');
    canonical_request.push_str(signed_headers.join(";").as_str());
    canonical_request.push('\n');

    canonical_request.push_str(EMPTY_PAYLOAD_SHA256);

    let hash = hex_sha256(canonical_request.as_bytes());

    Ok((hash, canonical_request))
}

fn generate_signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    // Sign date
    let sign_date = hmac_sha256(secret.as_bytes(), date.as_bytes());
    // Sign region
    let sign_region = hmac_sha256(sign_date.as_slice(), region.as_bytes());
    // Sign service
    let sign_service = hmac_sha256(sign_region.as_slice(), "tos".as_bytes());
    // Sign request
    hmac_sha256(sign_service.as_slice(), "request".as_bytes())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use http::Uri;

    use super::*;
    use crate::provide_credential::StaticCredentialProvider;
    use reqsign_core::{Context, OsEnv, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    #[tokio::test]
    async fn test_sign_request() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let loader = StaticCredentialProvider::new("testAK", "testSK");
        let signer = RequestSigner::new("cn-beijing")
            .with_time(Timestamp::parse_rfc2822("Sat, 1 Jan 2022 00:00:00 GMT")?);

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);

        let signer = Signer::new(ctx, loader, signer);

        let get_req = "https://examplebucket.tos-cn-beijing.volces.com/exampleobject";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("x-tos-content-sha256")?,
            HeaderValue::from_str(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )?,
        );

        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;

        let headers = parts.headers;
        let tos_date = headers.get("x-tos-date").unwrap();
        let auth = headers.get("Authorization").unwrap();

        assert!(
            tos_date.to_str()?.starts_with("2022"),
            "x-tos-date should be in ISO8601 format"
        );
        assert_eq!(
            "TOS4-HMAC-SHA256 Credential=testAK/20220101/cn-beijing/tos/request, SignedHeaders=host;x-tos-content-sha256;x-tos-date, Signature=d40b66cf0054d1642843670d10fa095e1609c7896f25df217770b0abe717693b",
            auth.to_str()?
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_list_objects() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();
        let loader = StaticCredentialProvider::new("testAK", "testSK");

        let signer = RequestSigner::new("cn-beijing").with_time("2026-02-03T12:24:12Z".parse()?);

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, signer);

        let req = http::Request::get("https://bucket.tos-cn-beijing.volces.com?list-type=2&prefix=abc&delimiter=%2F&max-keys=5&continuation-token=whvFnl2rE5vm9cWvQSgxwpc7QXHY7dgUGQ7nxlsVxFymg2%2BK227j5IHQZ32h").body(())?;
        let (mut parts, _) = req.into_parts();

        signer.sign(&mut parts, None).await?;

        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        assert_eq!(
            "TOS4-HMAC-SHA256 Credential=testAK/20260203/cn-beijing/tos/request, SignedHeaders=host;x-tos-date, Signature=db01ee877fa24847ec042703353a76a0e11bd9b6ce68eabe5ccb2924420156b0",
            auth.to_str()?
        );
        Ok(())
    }
}
