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

//! Huawei Cloud Object Storage Service (OBS) builder
use std::collections::HashSet;
use std::fmt::Write;
use std::time::Duration;

use http::HeaderValue;
use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use log::debug;
use once_cell::sync::Lazy;
use percent_encoding::utf8_percent_encode;
use reqsign_core::Result;

use super::constants::*;
use super::credential::Credential;
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::time::format_http_date;
use reqsign_core::time::now;
use reqsign_core::{SignRequest, SigningMethod, SigningRequest};

/// RequestSigner that implement Huawei Cloud Object Storage Service Authorization.
///
/// - [User Signature Authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
#[derive(Debug)]
pub struct RequestSigner {
    bucket: String,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a builder.
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
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

#[async_trait::async_trait]
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &reqsign_core::Context,
        parts: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let k = credential
            .ok_or_else(|| reqsign_core::Error::credential_invalid("missing credential"))?;
        let now = self.time.unwrap_or_else(now);

        let method = if let Some(expires_in) = expires_in {
            SigningMethod::Query(expires_in)
        } else {
            SigningMethod::Header
        };

        let mut ctx = SigningRequest::build(parts)?;

        let string_to_sign = string_to_sign(&mut ctx, k, now, method, &self.bucket)?;
        let signature = base64_hmac_sha1(k.secret_access_key.as_bytes(), string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OBS {}:{}", k.access_key_id, signature).parse()?;
                    value.set_sensitive(true);

                    value
                });
            }
            SigningMethod::Query(expire) => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.query_push("AccessKeyId", &k.access_key_id);
                ctx.query_push(
                    "Expires",
                    (now + jiff::SignedDuration::try_from(expire).unwrap())
                        .as_second()
                        .to_string(),
                );
                ctx.query_push(
                    "Signature",
                    utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC).to_string(),
                )
            }
        }

        ctx.apply(parts)
    }
}

/// Construct string to sign
///
/// ## Format
///
/// ```text
/// VERB + "\n" +
/// Content-MD5 + "\n" +
/// Content-Type + "\n" +
/// Date + "\n" +
/// CanonicalizedHeaders +
/// CanonicalizedResource;
/// ```
///
/// ## Reference
///
/// - [User Signature Authentication (OBS)](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
fn string_to_sign(
    ctx: &mut SigningRequest,
    cred: &Credential,
    now: Timestamp,
    method: SigningMethod,
    bucket: &str,
) -> Result<String> {
    let mut s = String::new();
    s.write_str(ctx.method.as_str())?;
    s.write_str("\n")?;
    s.write_str(
        ctx.header_get_or_default(
            &CONTENT_MD5.parse().map_err(|e| {
                reqsign_core::Error::unexpected(format!("Invalid header name: {e}"))
            })?,
        )?,
    )?;
    s.write_str("\n")?;
    s.write_str(ctx.header_get_or_default(&CONTENT_TYPE)?)?;
    s.write_str("\n")?;
    match method {
        SigningMethod::Header => {
            writeln!(&mut s, "{}", format_http_date(now))?;
        }
        SigningMethod::Query(expires) => {
            writeln!(
                &mut s,
                "{}",
                (now + jiff::SignedDuration::try_from(expires).unwrap()).as_second()
            )?;
        }
    }

    {
        let headers = canonicalize_header(ctx, method, cred)?;
        if !headers.is_empty() {
            writeln!(&mut s, "{headers}",)?;
        }
    }
    write!(
        &mut s,
        "{}",
        canonicalize_resource(ctx, bucket, method, cred)
    )?;

    debug!("string to sign: {}", &s);
    Ok(s)
}

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_header(
    ctx: &mut SigningRequest,
    method: SigningMethod,
    cred: &Credential,
) -> Result<String> {
    if method == SigningMethod::Header {
        // Insert security token
        if let Some(token) = &cred.security_token {
            ctx.headers.insert("x-obs-security-token", token.parse()?);
        }
    }

    Ok(SigningRequest::header_to_string(
        ctx.header_to_vec_with_prefix("x-obs-"),
        ":",
        "\n",
    ))
}

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_resource(
    ctx: &mut SigningRequest,
    bucket: &str,
    method: SigningMethod,
    cred: &Credential,
) -> String {
    if let SigningMethod::Query(_) = method {
        // Insert security token
        if let Some(token) = &cred.security_token {
            ctx.query
                .push(("security-token".to_string(), token.to_string()));
        };
    }

    let params = ctx.query_to_vec_with_filter(is_sub_resource);

    let params_str = SigningRequest::query_to_string(params, "=", "&");

    if params_str.is_empty() {
        format!("/{bucket}{}", ctx.path)
    } else {
        format!("/{bucket}{}?{params_str}", ctx.path)
    }
}

fn is_sub_resource(param: &str) -> bool {
    SUBRESOURCES.contains(param)
}

// Please attention: the subsources are case sensitive.
static SUBRESOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "CDNNotifyConfiguration",
        "acl",
        "append",
        "attname",
        "backtosource",
        "cors",
        "customdomain",
        "delete",
        "deletebucket",
        "directcoldaccess",
        "encryption",
        "inventory",
        "length",
        "lifecycle",
        "location",
        "logging",
        "metadata",
        "modify",
        "name",
        "notification",
        "partNumber",
        "policy",
        "position",
        "quota",
        "rename",
        "replication",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "response-content-language",
        "response-content-type",
        "response-expires",
        "restore",
        "storageClass",
        "storagePolicy",
        "storageinfo",
        "tagging",
        "torrent",
        "truncate",
        "uploadId",
        "uploads",
        "versionId",
        "versioning",
        "versions",
        "website",
        "x-image-process",
        "x-image-save-bucket",
        "x-image-save-object",
        "x-obs-security-token",
    ])
});

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use http::Uri;
    use http::header::HeaderName;
    use reqsign_core::Result;
    use reqsign_core::time::parse_rfc2822;
    use reqsign_core::{Context, OsEnv, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    use super::super::provide_credential::StaticCredentialProvider;
    use super::*;

    #[tokio::test]
    async fn test_sign() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder =
            RequestSigner::new("bucket").with_time(parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, builder);

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        assert_eq!(
            "OBS access_key:9gUZ4ol2W19LyYcc92Bu3U0V09E=",
            auth.to_str()?,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_with_subresource() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder =
            RequestSigner::new("bucket").with_time(parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, builder);

        let get_req =
            "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        // CanonicalizedResource: /bucket/object.txt?name=hello
        assert_eq!(
            "OBS access_key:EaTKiO1Qh5KFUvWAVvbCNGktJUY=",
            auth.to_str()?,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_list_objects() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder =
            RequestSigner::new("bucket").with_time(parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, builder);

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        // CanonicalizedResource: /bucket/?name=hello
        assert_eq!(
            "OBS access_key:9OdOsf8PRdhGhpkp7IIbKE0kRvA=",
            auth.to_str()?,
        );

        Ok(())
    }
}
