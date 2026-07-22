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
use std::sync::LazyLock;
use std::time::Duration;

use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use http::{HeaderValue, Uri};
use log::debug;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqsign_core::Result;

use super::constants::*;
use super::credential::Credential;
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::{SignRequest, SigningMethod, SigningRequest};

static OBS_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

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
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &reqsign_core::Context,
        parts: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };
        let now = self.time.unwrap_or_else(Timestamp::now);

        let method = if let Some(expires_in) = expires_in {
            SigningMethod::Query(expires_in)
        } else {
            SigningMethod::Header
        };

        let original_uri = parts.uri.clone();
        let mut ctx = SigningRequest::build(parts)?;

        let string_to_sign = string_to_sign(&mut ctx, cred, now, method, &self.bucket)?;
        let signature =
            base64_hmac_sha1(cred.secret_access_key.as_bytes(), string_to_sign.as_bytes());

        let final_uri = match method {
            SigningMethod::Header => {
                ctx.headers.insert(DATE, now.format_http_date().parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OBS {}:{}", cred.access_key_id, signature).parse()?;
                    value.set_sensitive(true);

                    value
                });
                None
            }
            SigningMethod::Query(expire) => {
                ctx.headers.insert(DATE, now.format_http_date().parse()?);
                let mut authentication = Vec::new();
                if let Some(token) = &cred.security_token {
                    authentication.push(format!(
                        "security-token={}",
                        utf8_percent_encode(token, &OBS_QUERY_ENCODE_SET)
                    ));
                }
                authentication.push(format!(
                    "AccessKeyId={}",
                    utf8_percent_encode(&cred.access_key_id, &OBS_QUERY_ENCODE_SET)
                ));
                authentication.push(format!("Expires={}", (now + expire).as_second()));
                authentication.push(format!(
                    "Signature={}",
                    utf8_percent_encode(&signature, &OBS_QUERY_ENCODE_SET)
                ));
                Some(append_query_fragment(
                    &original_uri,
                    &authentication.join("&"),
                )?)
            }
        };

        ctx.apply(parts)?;
        if let Some(uri) = final_uri {
            parts.uri = uri;
        }
        Ok(())
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
            writeln!(&mut s, "{}", now.format_http_date())?;
        }
        SigningMethod::Query(expires) => {
            writeln!(&mut s, "{}", (now + expires).as_second())?;
        }
    }

    {
        let headers = canonicalize_header(ctx, method, cred)?;
        if !headers.is_empty() {
            writeln!(&mut s, "{headers}",)?;
        }
    }
    write!(&mut s, "{}", canonicalize_resource(ctx, bucket))?;

    debug!("string to sign: {}", s);
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
fn canonicalize_resource(ctx: &SigningRequest, bucket: &str) -> String {
    let params = ctx.query_to_vec_with_filter(is_sub_resource);

    let params_str = SigningRequest::query_to_string(params, "=", "&");

    if params_str.is_empty() {
        format!("/{bucket}{}", ctx.path)
    } else {
        format!("/{bucket}{}?{params_str}", ctx.path)
    }
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
        reqsign_core::Error::request_invalid("failed to append OBS signing query").with_source(e)
    })
}

fn is_sub_resource(param: &str) -> bool {
    SUBRESOURCES.contains(param)
}

// Please attention: the subresources are case-sensitive.
static SUBRESOURCES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
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
    use reqsign_core::{Context, OsEnv, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    use super::super::provide_credential::StaticCredentialProvider;
    use super::*;

    const RAW_QUERY: &str = "versionId=a%2Bb%3Dc%2525%26e&slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

    #[tokio::test]
    async fn test_sign() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder = RequestSigner::new("bucket")
            .with_time(Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

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
        let builder = RequestSigner::new("bucket")
            .with_time(Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

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
        let builder = RequestSigner::new("bucket")
            .with_time(Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

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

    #[tokio::test]
    async fn canonicalization_and_signing_preserve_wire_uri() -> Result<()> {
        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let original_uri =
            format!("http://bucket.obs.cn-north-4.myhuaweicloud.com/object%2Fname?{RAW_QUERY}");

        let mut canonical_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        let mut signing_req = SigningRequest::build(&mut canonical_parts)?;
        let string = string_to_sign(
            &mut signing_req,
            &credential,
            now,
            SigningMethod::Header,
            "bucket",
        )?;
        assert!(string.ends_with("/bucket/object%2Fname?versionId=a+b=c%25&e"));

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
        assert!(query_parts.uri.to_string().starts_with(&original_uri));
        assert!(query_parts.uri.query().unwrap().contains("Signature="));

        Ok(())
    }
}
