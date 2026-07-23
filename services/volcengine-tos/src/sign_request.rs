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

use http::header::AUTHORIZATION;
use http::{HeaderName, HeaderValue, header};
use log::debug;
use percent_encoding::percent_decode_str;
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Result, SignRequest, SigningCredential, SigningRequest};
use std::fmt::Write;
use std::sync::LazyLock;
use std::time::Duration;

use crate::constants::*;
use crate::credential::Credential;
use crate::uri::percent_encode_query;

const TOS_ALGORITHM: &str = "TOS4-HMAC-SHA256";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const TOS_AUTH_QUERY_NAMES: &[&str] = &[
    "x-tos-algorithm",
    "x-tos-credential",
    "x-tos-date",
    "x-tos-expires",
    "x-tos-policy",
    "x-tos-security-token",
    "x-tos-signature",
    "x-tos-signedheaders",
];

static HEADER_TOS_DATE: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-tos-date"));
static HEADER_TOS_CONTENT_SHA256: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-tos-content-sha256"));
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

    fn get_time(&self) -> Timestamp {
        self.time.unwrap_or_else(Timestamp::now)
    }
}
impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<std::time::Duration>,
    ) -> Timestamp {
        self.get_time()
    }

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let now = self.get_time();
        if !cred.is_valid_at(now) {
            return Err(reqsign_core::Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }

        let original_uri = req.uri.clone();
        let mut signing_req = SigningRequest::build(req)?;
        validate_authentication_carriers(&signing_req)?;

        let date_str = now.format_iso8601();
        let date_only = now.format_date();

        // Scope: "<date>/<region>/tos/request"
        let credential_scope = format!("{}/{}/tos/request", date_only, self.region);

        canonicalize_header(&mut signing_req, cred, &date_str, expires_in)?;
        let signed_headers = signed_header_names(&signing_req, expires_in.is_some());
        let authentication_query = authentication_query(
            cred,
            &credential_scope,
            &date_str,
            expires_in,
            &signed_headers,
        );
        let canonical_query = canonicalize_query(&signing_req, &authentication_query);
        let payload_hash = if expires_in.is_some() {
            match signing_req.headers.get(&*HEADER_TOS_CONTENT_SHA256) {
                Some(value) => value.to_str().map_err(|e| {
                    reqsign_core::Error::unexpected(format!(
                        "invalid x-tos-content-sha256 header value: {e}"
                    ))
                })?,
                None => UNSIGNED_PAYLOAD,
            }
        } else {
            EMPTY_PAYLOAD_SHA256
        };
        let (canonical_request_hash, _) = canonical_request_hash(
            &signing_req,
            &canonical_query,
            &signed_headers,
            payload_hash,
        )?;

        // StringToSign:
        //
        // TOS4-HMAC-SHA256
        // <iso8601_date>
        // <scope>
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut s = String::new();
            writeln!(s, "{TOS_ALGORITHM}")?;
            writeln!(s, "{}", date_str)?;
            writeln!(s, "{}", credential_scope)?;
            s.push_str(&canonical_request_hash);
            s
        };

        debug!("string to sign: {}", string_to_sign);

        let signing_key = generate_signing_key(&cred.secret_access_key, &date_only, &self.region);
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        let final_uri = if expires_in.is_some() {
            let unsigned_uri = append_query_pairs(&original_uri, &authentication_query)?;
            Some(append_query_fragment(
                &unsigned_uri,
                &format!("X-Tos-Signature={signature}"),
            )?)
        } else {
            let signed_headers_str = signed_headers.join(";");
            let authorization = format!(
                "{TOS_ALGORITHM} Credential={}/{}, SignedHeaders={}, Signature={}",
                cred.access_key_id, credential_scope, signed_headers_str, signature
            );

            debug!("authorization: {}", authorization);

            let mut auth_value: HeaderValue = authorization.parse()?;
            auth_value.set_sensitive(true);
            signing_req.headers.insert(AUTHORIZATION, auth_value);
            None
        };

        signing_req.apply(req)?;
        if let Some(uri) = final_uri {
            req.uri = uri;
        }
        Ok(())
    }
}

fn canonicalize_header(
    ctx: &mut SigningRequest,
    cred: &Credential,
    date_str: &str,
    expires_in: Option<Duration>,
) -> Result<()> {
    // Insert HOST header if not present.
    if ctx.headers.get(header::HOST).is_none() {
        ctx.headers.insert(
            header::HOST,
            ctx.authority.as_str().parse().map_err(|e| {
                reqsign_core::Error::unexpected(format!(
                    "failed to parse authority as header value: {e}"
                ))
            })?,
        );
    }

    if expires_in.is_none() {
        ctx.headers.insert(&*HEADER_TOS_DATE, date_str.parse()?);

        if let Some(token) = &cred.session_token {
            let mut token: HeaderValue = token.parse()?;
            token.set_sensitive(true);
            ctx.headers.insert(&*HEADER_TOS_SECURITY_TOKEN, token);
        }
    }

    Ok(())
}

fn validate_authentication_carriers(ctx: &SigningRequest) -> Result<()> {
    if ctx.headers.contains_key(AUTHORIZATION) {
        return Err(reqsign_core::Error::request_invalid(
            "request already contains an authorization header",
        ));
    }

    if let Some((name, _)) = ctx.query.iter().find(|(name, _)| {
        TOS_AUTH_QUERY_NAMES
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
    }) {
        return Err(reqsign_core::Error::request_invalid(format!(
            "request query already contains TOS authentication field: {name}"
        )));
    }

    Ok(())
}

fn authentication_query(
    cred: &Credential,
    credential_scope: &str,
    date_str: &str,
    expires_in: Option<Duration>,
    signed_headers: &[&str],
) -> Vec<(String, String)> {
    let mut query = Vec::new();
    if let Some(expires) = expires_in {
        query.push(("X-Tos-Algorithm".into(), TOS_ALGORITHM.into()));
        query.push((
            "X-Tos-Credential".into(),
            format!("{}/{}", cred.access_key_id, credential_scope),
        ));
        query.push(("X-Tos-Date".into(), date_str.into()));
        query.push(("X-Tos-Expires".into(), expires.as_secs().to_string()));
        query.push(("X-Tos-SignedHeaders".into(), signed_headers.join(";")));

        if let Some(token) = &cred.session_token {
            query.push(("X-Tos-Security-Token".into(), token.into()));
        }
    }
    query
}

fn canonicalize_query(
    ctx: &SigningRequest,
    authentication_query: &[(String, String)],
) -> Vec<(String, String)> {
    let mut query = ctx
        .query
        .iter()
        .chain(authentication_query)
        .map(|(k, v)| (percent_encode_query(k), percent_encode_query(v)))
        .collect::<Vec<_>>();
    // Sort by param name
    query.sort();
    query
}

fn append_query_pairs(uri: &http::Uri, pairs: &[(String, String)]) -> Result<http::Uri> {
    let mut pairs = pairs
        .iter()
        .map(|(key, value)| (percent_encode_query(key), percent_encode_query(value)))
        .collect::<Vec<_>>();
    pairs.sort();
    let fragment = pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    append_query_fragment(uri, &fragment)
}

fn append_query_fragment(uri: &http::Uri, fragment: &str) -> Result<http::Uri> {
    if fragment.is_empty() {
        return Ok(uri.clone());
    }

    let mut value = uri.to_string();
    if uri.query().is_none() {
        value.push('?');
    } else if !value.ends_with('?') && !value.ends_with('&') {
        value.push('&');
    }
    value.push_str(fragment);

    value.parse().map_err(|e| {
        reqsign_core::Error::request_invalid("failed to append signing query").with_source(e)
    })
}

fn signed_header_names(ctx: &SigningRequest, is_presign: bool) -> Vec<&str> {
    let mut headers = ctx
        .headers
        .keys()
        .map(|k| k.as_str())
        .filter(|header| !is_presign || *header == "host" || header.starts_with("x-tos-"))
        .collect::<Vec<_>>();
    headers.sort_unstable();
    headers
}

fn canonical_request_hash(
    ctx: &SigningRequest,
    canonical_query: &[(String, String)],
    signed_headers: &[&str],
    payload_hash: &str,
) -> Result<(String, String)> {
    let mut canonical_request = String::with_capacity(256);

    // Insert method
    canonical_request.push_str(ctx.method.as_str());
    canonical_request.push('\n');

    // Insert encoded path
    let canonical_path = ctx
        .path
        .split('/')
        .map(|segment| {
            percent_decode_str(segment)
                .decode_utf8()
                .map(|segment| percent_encode_query(&segment))
                .map_err(|e| {
                    reqsign_core::Error::request_invalid("failed to decode URI path segment")
                        .with_source(e)
                })
        })
        .collect::<Result<Vec<_>>>()?
        .join("/");
    canonical_request.push_str(&canonical_path);
    canonical_request.push('\n');

    // Insert encoded query
    let query_string = canonical_query
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    canonical_request.push_str(&query_string);
    canonical_request.push('\n');

    // Insert signed headers
    for header in signed_headers {
        let mut value = ctx.headers[*header].clone();
        SigningRequest::header_value_normalize(&mut value);
        let value = value
            .to_str()
            .map_err(|e| {
                reqsign_core::Error::request_invalid(format!(
                    "invalid header value for TOS signing: {e}"
                ))
            })?
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        canonical_request.push_str(header);
        canonical_request.push(':');
        canonical_request.push_str(&value);
        canonical_request.push('\n');
    }

    canonical_request.push('\n');
    canonical_request.push_str(signed_headers.join(";").as_str());
    canonical_request.push('\n');

    canonical_request.push_str(payload_hash);

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
    use std::time::Duration;

    use http::Uri;

    use super::*;
    use crate::provide_credential::StaticCredentialProvider;
    use reqsign_core::{Context, OsEnv, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    async fn presign_request(
        req: http::Request<()>,
        credential: &Credential,
        region: &str,
        expires: Duration,
    ) -> Result<http::request::Parts> {
        let signer = RequestSigner::new(region)
            .with_time(Timestamp::parse_rfc2822("Sat, 1 Jan 2022 00:00:00 GMT")?);
        let (mut parts, _) = req.into_parts();
        signer
            .sign_request(&Context::new(), &mut parts, Some(credential), Some(expires))
            .await?;
        Ok(parts)
    }

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

        let raw_query = "list-type=2&prefix=abc&delimiter=%2F&max-keys=5&continuation-token=whvFnl2rE5vm9cWvQSgxwpc7QXHY7dgUGQ7nxlsVxFymg2%2BK227j5IHQZ32h";
        let req = http::Request::get(format!(
            "https://bucket.tos-cn-beijing.volces.com?{raw_query}"
        ))
        .body(())?;
        let (mut parts, _) = req.into_parts();

        signer.sign(&mut parts, None).await?;

        assert_eq!(parts.uri.query(), Some(raw_query));
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        assert_eq!(
            "TOS4-HMAC-SHA256 Credential=testAK/20260203/cn-beijing/tos/request, SignedHeaders=host;x-tos-date, Signature=db01ee877fa24847ec042703353a76a0e11bd9b6ce68eabe5ccb2924420156b0",
            auth.to_str()?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_presign_request() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let get_req = "https://examplebucket.tos-ap-southeast-1.bytepluses.com/exampleobject";
        let req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        let parts = presign_request(
            req,
            &Credential::new("testAK", "testSK"),
            "ap-southeast-1",
            Duration::from_secs(86400),
        )
        .await?;

        assert!(parts.headers.get("Authorization").is_none());
        assert!(parts.headers.get("x-tos-date").is_none());
        assert_eq!(
            "https://examplebucket.tos-ap-southeast-1.bytepluses.com/exampleobject?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=testAK%2F20220101%2Fap-southeast-1%2Ftos%2Frequest&X-Tos-Date=20220101T000000Z&X-Tos-Expires=86400&X-Tos-SignedHeaders=host&X-Tos-Signature=d235179a42db6eefabd0c312a8f7e33c03a939ac2deb6e7c0ac4058117fc882b",
            parts.uri.to_string()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_presign_with_session_token() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let req =
            http::Request::get("https://examplebucket.tos-cn-beijing.volces.com/object").body(())?;
        let parts = presign_request(
            req,
            &Credential::new("testAK", "testSK").with_session_token("session/token"),
            "cn-beijing",
            Duration::from_secs(3600),
        )
        .await?;

        assert!(parts.headers.get("x-tos-security-token").is_none());
        assert_eq!(
            "https://examplebucket.tos-cn-beijing.volces.com/object?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=testAK%2F20220101%2Fcn-beijing%2Ftos%2Frequest&X-Tos-Date=20220101T000000Z&X-Tos-Expires=3600&X-Tos-Security-Token=session%2Ftoken&X-Tos-SignedHeaders=host&X-Tos-Signature=7346fb25f8454f6b4c0531038ae3d8e1ba74e6bffa95513812ea1ebaec601ba2",
            parts.uri.to_string()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_presign_with_signed_headers() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = http::Request::get(
            "https://examplebucket.tos-ap-southeast-1.bytepluses.com/exampleobject",
        )
        .header("x-tos-content-sha256", EMPTY_PAYLOAD_SHA256)
        .body(())?;
        let mut metadata = HeaderValue::from_static("alpha   beta");
        metadata.set_sensitive(true);
        req.headers_mut().insert("x-tos-meta-note", metadata);
        let parts = presign_request(
            req,
            &Credential::new("testAK", "testSK"),
            "ap-southeast-1",
            Duration::from_secs(86400),
        )
        .await?;

        assert_eq!("alpha   beta", parts.headers["x-tos-meta-note"]);
        assert!(parts.headers["x-tos-meta-note"].is_sensitive());
        assert_eq!(
            "https://examplebucket.tos-ap-southeast-1.bytepluses.com/exampleobject?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=testAK%2F20220101%2Fap-southeast-1%2Ftos%2Frequest&X-Tos-Date=20220101T000000Z&X-Tos-Expires=86400&X-Tos-SignedHeaders=host%3Bx-tos-content-sha256%3Bx-tos-meta-note&X-Tos-Signature=bb27db860abc9394068d1f22c229f2dfe01e58d8f6f2a65f06f2e78114af9195",
            parts.uri.to_string(),
        );

        Ok(())
    }

    #[tokio::test]
    async fn canonicalization_and_signing_preserve_wire_uri() -> Result<()> {
        const RAW_QUERY: &str = "slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("cn-beijing").with_time(now);
        let credential = Credential::new("testAK", "testSK");
        let original_uri =
            format!("https://bucket.tos-cn-beijing.volces.com/object%2Fname?{RAW_QUERY}");
        let mut canonical_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        let mut signing_req = SigningRequest::build(&mut canonical_parts)?;
        let date_str = now.format_iso8601();
        let credential_scope = format!("{}/cn-beijing/tos/request", now.format_date());
        canonicalize_header(
            &mut signing_req,
            &credential,
            &date_str,
            Some(Duration::from_secs(60)),
        )?;
        let signed_headers = signed_header_names(&signing_req, true);
        let authentication_query = authentication_query(
            &credential,
            &credential_scope,
            &date_str,
            Some(Duration::from_secs(60)),
            &signed_headers,
        );
        let canonical_query = canonicalize_query(&signing_req, &authentication_query);
        let (_, canonical_request) = canonical_request_hash(
            &signing_req,
            &canonical_query,
            &signed_headers,
            UNSIGNED_PAYLOAD,
        )?;

        assert!(canonical_request.starts_with("GET\n/object%2Fname\n"));
        assert!(canonical_query.contains(&("literal-plus".to_string(), "%2B".to_string())));
        assert!(canonical_query.contains(&("double".to_string(), "%252F".to_string())));

        let mut header_parts = http::Request::get(&original_uri)
            .header("x-custom", "alpha   beta")
            .body(())?
            .into_parts()
            .0;
        header_parts
            .headers
            .get_mut("x-custom")
            .unwrap()
            .set_sensitive(true);
        signer
            .sign_request(&Context::new(), &mut header_parts, Some(&credential), None)
            .await?;
        assert_eq!(header_parts.uri.to_string(), original_uri);
        assert_eq!(header_parts.headers["x-custom"], "alpha   beta");
        assert!(header_parts.headers["x-custom"].is_sensitive());

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
                .starts_with(&format!("{original_uri}X-Tos-Algorithm="))
        );
        assert!(
            query_parts
                .uri
                .query()
                .unwrap()
                .contains("X-Tos-Signature=")
        );

        Ok(())
    }

    #[tokio::test]
    async fn authentication_carrier_collisions_are_atomic() -> Result<()> {
        let signer = RequestSigner::new("cn-beijing").with_time("2026-07-22T00:00:00Z".parse()?);
        let credential = Credential::new("testAK", "testSK");

        let mut query_parts = http::Request::get(
            "https://bucket.tos-cn-beijing.volces.com/object?x-tos-signature=stale&key=value",
        )
        .body(())?
        .into_parts()
        .0;
        query_parts.headers.insert(
            HeaderName::from_static("x-original"),
            HeaderValue::from_static("value"),
        );
        query_parts.extensions.insert(7_u8);
        let original_query_parts = query_parts.clone();

        signer
            .sign_request(
                &Context::new(),
                &mut query_parts,
                Some(&credential),
                Some(Duration::from_secs(60)),
            )
            .await
            .expect_err("an existing TOS signature must be rejected");
        assert_request_head_unchanged(&query_parts, &original_query_parts);

        let mut header_parts =
            http::Request::get("https://bucket.tos-cn-beijing.volces.com/object?key=value")
                .header(AUTHORIZATION, "stale")
                .body(())?
                .into_parts()
                .0;
        header_parts.extensions.insert(9_u8);
        let original_header_parts = header_parts.clone();

        signer
            .sign_request(&Context::new(), &mut header_parts, Some(&credential), None)
            .await
            .expect_err("an existing authorization header must be rejected");
        assert_request_head_unchanged(&header_parts, &original_header_parts);

        Ok(())
    }

    fn assert_request_head_unchanged(
        actual: &http::request::Parts,
        expected: &http::request::Parts,
    ) {
        assert_eq!(actual.method, expected.method);
        assert_eq!(actual.uri, expected.uri);
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.headers, expected.headers);
        assert_eq!(
            actual.extensions.get::<u8>(),
            expected.extensions.get::<u8>()
        );
    }
}
