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
use crate::constants::*;
use async_trait::async_trait;
use http::request::Parts;
use http::{HeaderValue, header};
use log::debug;
use percent_encoding::percent_encode;
use reqsign_core::hash::{base64_decode, base64_hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Result, SignRequest, SigningMethod, SigningRequest};
use std::fmt::Write;
use std::sync::Mutex;
use std::time::Duration;

/// Resource kind required by SAS generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SasResourceKind {
    /// Container SAS.
    Container,
    /// Blob SAS.
    Blob,
}

/// RequestSigner that implement Azure Storage Shared Key Authorization.
///
/// - [Authorize with Shared Key](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
#[derive(Debug)]
pub struct RequestSigner {
    time: Option<Timestamp>,
    service_sas_permissions: Option<String>,
    service_sas_start: Option<Timestamp>,
    service_sas_ip: Option<String>,
    service_sas_protocol: Option<String>,
    service_sas_version: Option<String>,

    user_delegation_presign: Option<UserDelegationPresignConfig>,
    user_delegation_key_cache: Mutex<Option<crate::user_delegation::UserDelegationKey>>,
}

#[derive(Clone, Debug)]
struct UserDelegationPresignConfig {
    resource: SasResourceKind,
    permissions: String,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: Option<String>,
    version: Option<String>,
}

impl RequestSigner {
    /// Create a new builder for Azure Storage signer.
    pub fn new() -> Self {
        Self {
            time: None,
            service_sas_permissions: None,
            service_sas_start: None,
            service_sas_ip: None,
            service_sas_protocol: None,
            service_sas_version: None,

            user_delegation_presign: None,
            user_delegation_key_cache: Mutex::new(None),
        }
    }

    /// Configure Service SAS presign permissions for Shared Key query signing.
    ///
    /// This setting is required when `expires_in` is provided and credential is `SharedKey`.
    pub fn with_service_sas_permissions(mut self, permissions: &str) -> Self {
        self.service_sas_permissions = Some(permissions.to_string());
        self
    }

    /// Configure Service SAS presign start time for Shared Key query signing.
    pub fn with_service_sas_start(mut self, start: Timestamp) -> Self {
        self.service_sas_start = Some(start);
        self
    }

    /// Configure Service SAS presign allowed IP range.
    pub fn with_service_sas_ip(mut self, ip: &str) -> Self {
        self.service_sas_ip = Some(ip.to_string());
        self
    }

    /// Configure Service SAS presign allowed protocol, e.g. `https` or `https,http`.
    pub fn with_service_sas_protocol(mut self, protocol: &str) -> Self {
        self.service_sas_protocol = Some(protocol.to_string());
        self
    }

    /// Configure Service SAS presign service version.
    pub fn with_service_sas_version(mut self, version: &str) -> Self {
        self.service_sas_version = Some(version.to_string());
        self
    }

    /// Enable User Delegation SAS presign for Bearer Token query signing.
    ///
    /// This is only used when `expires_in` is provided and credential is `BearerToken`.
    pub fn with_user_delegation_presign(
        mut self,
        resource: SasResourceKind,
        permissions: &str,
    ) -> Self {
        self.user_delegation_presign = Some(UserDelegationPresignConfig {
            resource,
            permissions: permissions.to_string(),
            start: None,
            ip: None,
            protocol: None,
            version: None,
        });
        self
    }

    /// Configure User Delegation SAS presign start time.
    pub fn with_user_delegation_start(mut self, start: Timestamp) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.start = Some(start);
        }
        self
    }

    /// Configure User Delegation SAS presign allowed IP range.
    pub fn with_user_delegation_ip(mut self, ip: &str) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.ip = Some(ip.to_string());
        }
        self
    }

    /// Configure User Delegation SAS presign allowed protocol, e.g. `https` or `https,http`.
    pub fn with_user_delegation_protocol(mut self, protocol: &str) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.protocol = Some(protocol.to_string());
        }
        self
    }

    /// Configure User Delegation SAS presign service version.
    pub fn with_user_delegation_version(mut self, version: &str) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.version = Some(version.to_string());
        }
        self
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

impl Default for RequestSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        context: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let method = if let Some(expires_in) = expires_in {
            SigningMethod::Query(expires_in)
        } else {
            SigningMethod::Header
        };

        let mut sctx = SigningRequest::build(req)?;

        // Handle different credential types
        match cred {
            Credential::SasToken { token } => {
                // SAS token authentication
                sctx.query_append(token);
            }
            Credential::BearerToken { token, .. } => {
                // Bearer token authentication
                match method {
                    SigningMethod::Query(d) => {
                        let Some(cfg) = &self.user_delegation_presign else {
                            return Err(reqsign_core::Error::request_invalid(
                                "BearerToken can't be used in query string",
                            ));
                        };

                        let now_time = self.time.unwrap_or_else(Timestamp::now);
                        let expiry = now_time + d;

                        let resource =
                            crate::service_sas::ServiceSasResource::from_path_percent_decoded(
                                sctx.path_percent_decoded().as_ref(),
                            )?;
                        match (cfg.resource, &resource) {
                            (
                                SasResourceKind::Container,
                                crate::service_sas::ServiceSasResource::Container { .. },
                            ) => {}
                            (
                                SasResourceKind::Blob,
                                crate::service_sas::ServiceSasResource::Blob { .. },
                            ) => {}
                            _ => {
                                return Err(reqsign_core::Error::request_invalid(
                                    "request resource doesn't match configured SAS resource kind",
                                ));
                            }
                        }

                        let account = infer_account_name(sctx.authority.as_str())?;

                        let key = {
                            let cached = self
                                .user_delegation_key_cache
                                .lock()
                                .expect("lock poisoned")
                                .clone();
                            if let Some(cached) = cached {
                                if cached.signed_expiry > expiry + Duration::from_secs(20) {
                                    cached
                                } else {
                                    let version = cfg.version.as_deref().unwrap_or("2020-12-06");
                                    let fetched = crate::user_delegation::get_user_delegation_key(
                                        context,
                                        sctx.scheme.as_str(),
                                        sctx.authority.as_str(),
                                        token,
                                        now_time,
                                        expiry,
                                        version,
                                        now_time,
                                    )
                                    .await?;
                                    *self
                                        .user_delegation_key_cache
                                        .lock()
                                        .expect("lock poisoned") = Some(fetched.clone());
                                    fetched
                                }
                            } else {
                                let version = cfg.version.as_deref().unwrap_or("2020-12-06");
                                let fetched = crate::user_delegation::get_user_delegation_key(
                                    context,
                                    sctx.scheme.as_str(),
                                    sctx.authority.as_str(),
                                    token,
                                    now_time,
                                    expiry,
                                    version,
                                    now_time,
                                )
                                .await?;
                                *self
                                    .user_delegation_key_cache
                                    .lock()
                                    .expect("lock poisoned") = Some(fetched.clone());
                                fetched
                            }
                        };

                        let mut signer =
                            crate::user_delegation::UserDelegationSharedAccessSignature::new(
                                account,
                                key,
                                resource,
                                cfg.permissions.to_string(),
                                expiry,
                            );
                        if let Some(start) = cfg.start {
                            signer = signer.with_start(start);
                        }
                        if let Some(ip) = &cfg.ip {
                            signer = signer.with_ip(ip);
                        }
                        if let Some(protocol) = &cfg.protocol {
                            signer = signer.with_protocol(protocol);
                        }
                        if let Some(version) = &cfg.version {
                            signer = signer.with_version(version);
                        }

                        let signer_token = signer.token().map_err(|e| {
                            reqsign_core::Error::unexpected(
                                "failed to generate user delegation SAS token",
                            )
                            .with_source(e)
                        })?;
                        signer_token
                            .into_iter()
                            .for_each(|(k, v)| sctx.query_push(k, v));
                    }
                    SigningMethod::Header => {
                        sctx.headers.insert(
                            X_MS_DATE,
                            Timestamp::now().format_http_date().parse().map_err(|e| {
                                reqsign_core::Error::unexpected("failed to parse date header")
                                    .with_source(e)
                            })?,
                        );
                        sctx.headers.insert(header::AUTHORIZATION, {
                            let mut value: HeaderValue =
                                format!("Bearer {token}").parse().map_err(|e| {
                                    reqsign_core::Error::unexpected(
                                        "failed to parse authorization header",
                                    )
                                    .with_source(e)
                                })?;
                            value.set_sensitive(true);
                            value
                        });
                    }
                }
            }
            Credential::SharedKey {
                account_name,
                account_key,
            } => {
                // Shared key authentication
                match method {
                    SigningMethod::Query(d) => {
                        let now_time = self.time.unwrap_or_else(Timestamp::now);
                        let Some(permissions) = &self.service_sas_permissions else {
                            return Err(reqsign_core::Error::request_invalid(
                                "Service SAS permissions are required for presign",
                            ));
                        };

                        let resource =
                            crate::service_sas::ServiceSasResource::from_path_percent_decoded(
                                sctx.path_percent_decoded().as_ref(),
                            )?;

                        let mut signer = crate::service_sas::ServiceSharedAccessSignature::new(
                            account_name.clone(),
                            account_key.clone(),
                            resource,
                            permissions.to_string(),
                            now_time + d,
                        );
                        if let Some(start) = self.service_sas_start {
                            signer = signer.with_start(start);
                        }
                        if let Some(ip) = &self.service_sas_ip {
                            signer = signer.with_ip(ip);
                        }
                        if let Some(protocol) = &self.service_sas_protocol {
                            signer = signer.with_protocol(protocol);
                        }
                        if let Some(version) = &self.service_sas_version {
                            signer = signer.with_version(version);
                        }

                        let signer_token = signer.token().map_err(|e| {
                            reqsign_core::Error::unexpected("failed to generate service SAS token")
                                .with_source(e)
                        })?;
                        signer_token
                            .into_iter()
                            .for_each(|(k, v)| sctx.query_push(k, v));
                    }
                    SigningMethod::Header => {
                        let now_time = self.time.unwrap_or_else(Timestamp::now);
                        let string_to_sign = string_to_sign(&mut sctx, account_name, now_time)?;
                        let decode_content = base64_decode(account_key).map_err(|e| {
                            reqsign_core::Error::unexpected("failed to decode account key")
                                .with_source(e)
                        })?;
                        let signature =
                            base64_hmac_sha256(&decode_content, string_to_sign.as_bytes());

                        sctx.headers.insert(header::AUTHORIZATION, {
                            let mut value: HeaderValue =
                                format!("SharedKey {account_name}:{signature}")
                                    .parse()
                                    .map_err(|e| {
                                        reqsign_core::Error::unexpected(
                                            "failed to parse authorization header",
                                        )
                                        .with_source(e)
                                    })?;
                            value.set_sensitive(true);
                            value
                        });
                    }
                }
            }
        }

        // Apply percent encoding for query parameters
        for (_, v) in sctx.query.iter_mut() {
            *v = percent_encode(v.as_bytes(), &AZURE_QUERY_ENCODE_SET).to_string();
        }

        sctx.apply(req)
    }
}

fn infer_account_name(authority: &str) -> Result<String> {
    let host = authority.split('@').last().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    let Some((account, _)) = host.split_once('.') else {
        return Err(reqsign_core::Error::request_invalid(
            "failed to infer account name from authority",
        ));
    };
    Ok(account.to_string())
}

/// Construct string to sign
///
/// ## Format
///
/// ```text
/// VERB + "\n" +
/// Content-Encoding + "\n" +
/// Content-Language + "\n" +
/// Content-Length + "\n" +
/// Content-MD5 + "\n" +
/// Content-Type + "\n" +
/// Date + "\n" +
/// If-Modified-Since + "\n" +
/// If-Match + "\n" +
/// If-None-Match + "\n" +
/// If-Unmodified-Since + "\n" +
/// Range + "\n" +
/// CanonicalizedHeaders +
/// CanonicalizedResource;
/// ```
/// ## Note
/// For sub-requests of batch API, requests should be signed without `x-ms-version` header.
/// Set the `omit_service_version` to `ture` for such.
///
/// ## Reference
///
/// - [Blob, Queue, and File Services (Shared Key authorization)](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
fn string_to_sign(
    ctx: &mut SigningRequest,
    account_name: &str,
    now_time: Timestamp,
) -> Result<String> {
    let mut s = String::with_capacity(128);

    writeln!(&mut s, "{}", ctx.method.as_str()).map_err(|e| {
        reqsign_core::Error::unexpected("failed to write method to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::CONTENT_ENCODING)
            .map_err(|e| reqsign_core::Error::unexpected(
                "failed to get content-encoding header"
            )
            .with_source(e))?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write content-encoding to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::CONTENT_LANGUAGE)
            .map_err(|e| reqsign_core::Error::unexpected(
                "failed to get content-language header"
            )
            .with_source(e))?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write content-language to string").with_source(e)
    })?;
    writeln!(&mut s, "{}", {
        let content_length = ctx
            .header_get_or_default(&header::CONTENT_LENGTH)
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to get content-length header")
                    .with_source(e)
            })?;
        if content_length == "0" {
            ""
        } else {
            content_length
        }
    })
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write content-length to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&"content-md5".parse().map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse content-md5 header name")
                .with_source(e)
        })?)
        .map_err(
            |e| reqsign_core::Error::unexpected("failed to get content-md5 header").with_source(e)
        )?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write content-md5 to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::CONTENT_TYPE)
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get content-type header")
                    .with_source(e)
            )?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write content-type to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::DATE)
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get date header").with_source(e)
            )?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write date to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::IF_MODIFIED_SINCE)
            .map_err(|e| reqsign_core::Error::unexpected(
                "failed to get if-modified-since header"
            )
            .with_source(e))?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write if-modified-since to string")
            .with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::IF_MATCH).map_err(|e| {
            reqsign_core::Error::unexpected("failed to get if-match header").with_source(e)
        })?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write if-match to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::IF_NONE_MATCH)
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get if-none-match header")
                    .with_source(e)
            )?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write if-none-match to string").with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::IF_UNMODIFIED_SINCE)
            .map_err(|e| reqsign_core::Error::unexpected(
                "failed to get if-unmodified-since header"
            )
            .with_source(e))?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write if-unmodified-since to string")
            .with_source(e)
    })?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&header::RANGE)
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get range header").with_source(e)
            )?
    )
    .map_err(|e| {
        reqsign_core::Error::unexpected("failed to write range to string").with_source(e)
    })?;
    writeln!(&mut s, "{}", canonicalize_header(ctx, now_time)?).map_err(|e| {
        reqsign_core::Error::unexpected("failed to write canonicalized headers to string")
            .with_source(e)
    })?;
    write!(&mut s, "{}", canonicalize_resource(ctx, account_name)).map_err(|e| {
        reqsign_core::Error::unexpected("failed to write canonicalized resource to string")
            .with_source(e)
    })?;

    debug!("string to sign: {}", &s);

    Ok(s)
}

/// ## Reference
///
/// - [Constructing the canonicalized headers string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-headers-string)
fn canonicalize_header(ctx: &mut SigningRequest, now_time: Timestamp) -> Result<String> {
    ctx.headers.insert(
        X_MS_DATE,
        now_time.format_http_date().parse().map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse x-ms-date header").with_source(e)
        })?,
    );

    Ok(SigningRequest::header_to_string(
        ctx.header_to_vec_with_prefix("x-ms-"),
        ":",
        "\n",
    ))
}

/// ## Reference
///
/// - [Constructing the canonicalized resource string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn canonicalize_resource(ctx: &mut SigningRequest, account_name: &str) -> String {
    if ctx.query.is_empty() {
        return format!("/{}{}", account_name, ctx.path);
    }

    let query = ctx
        .query
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    format!(
        "/{}{}\n{}",
        account_name,
        ctx.path,
        SigningRequest::query_to_percent_decoded_string(query, ":", "\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use http::Request;
    use reqsign_core::{Context, HttpSend, OsEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::str::FromStr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_sas_token() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let cred = Credential::with_sas_token(
            "sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D",
        );

        let builder = RequestSigner::new();

        // Construct request
        let req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        // Test query signing
        assert!(
            builder
                .sign_request(&ctx, &mut parts, Some(&cred), Some(Duration::from_secs(1)))
                .await
                .is_ok()
        );
        assert_eq!(
            parts.uri,
            "https://test.blob.core.windows.net/testbucket/testblob?sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D"
        )
    }

    #[tokio::test]
    async fn test_bearer_token() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let cred = Credential::with_bearer_token(
            "token",
            Some(Timestamp::now() + Duration::from_secs(3600)),
        );
        let builder = RequestSigner::new();

        let req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        // Can effectively sign request with header method
        assert!(
            builder
                .sign_request(&ctx, &mut parts, Some(&cred), None)
                .await
                .is_ok()
        );
        let authorization = parts
            .headers
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!("Bearer token", authorization);

        // Will not sign request with query method
        let req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        assert!(
            builder
                .sign_request(&ctx, &mut parts, Some(&cred), Some(Duration::from_secs(1)))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_shared_key_presign_service_sas() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);

        let now = Timestamp::from_str("2022-03-01T08:12:34Z").unwrap();
        let key = reqsign_core::hash::base64_encode("key".as_bytes());
        let cred = Credential::with_shared_key("account", &key);

        let builder = RequestSigner::new()
            .with_time(now)
            .with_service_sas_permissions("r");

        let req = Request::builder()
            .uri("https://account.blob.core.windows.net/container/path/to/blob.txt")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        builder
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(300)),
            )
            .await
            .unwrap();

        assert_eq!(
            parts.uri.to_string(),
            "https://account.blob.core.windows.net/container/path/to/blob.txt?sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&sig=CP9a2LIrR9zeG4I4jZjqPetJSXWJ77QeUA7c3GMypyM%3D"
        );
    }

    #[derive(Debug)]
    struct MockUserDelegationHttpSend;

    #[async_trait]
    impl HttpSend for MockUserDelegationHttpSend {
        async fn http_send(
            &self,
            req: http::Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            let uri = req.uri().to_string();
            if uri
                != "https://account.blob.core.windows.net/?restype=service&comp=userdelegationkey"
            {
                return Err(
                    reqsign_core::Error::unexpected("unexpected request uri").with_context(uri)
                );
            }

            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if auth != "Bearer token" {
                return Err(
                    reqsign_core::Error::unexpected("unexpected authorization header")
                        .with_context(auth),
                );
            }

            let body = r#"
<UserDelegationKey>
  <SignedOid>oid</SignedOid>
  <SignedTid>tid</SignedTid>
  <SignedStart>2022-03-01T08:12:34Z</SignedStart>
  <SignedExpiry>2022-03-01T09:12:34Z</SignedExpiry>
  <SignedService>b</SignedService>
  <SignedVersion>2020-12-06</SignedVersion>
  <Value>a2V5</Value>
</UserDelegationKey>
"#;

            Ok(http::Response::builder()
                .status(200)
                .body(Bytes::from(body))
                .unwrap())
        }
    }

    #[tokio::test]
    async fn test_bearer_token_presign_user_delegation_sas() {
        let now = Timestamp::from_str("2022-03-01T08:12:34Z").unwrap();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(MockUserDelegationHttpSend)
            .with_env(OsEnv);

        let cred = Credential::with_bearer_token("token", None);
        let builder = RequestSigner::new()
            .with_time(now)
            .with_user_delegation_presign(SasResourceKind::Blob, "r");

        let req = Request::builder()
            .uri("https://account.blob.core.windows.net/container/path/to/blob.txt")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        builder
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(300)),
            )
            .await
            .unwrap();

        assert_eq!(
            parts.uri.to_string(),
            "https://account.blob.core.windows.net/container/path/to/blob.txt?sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&skoid=oid&sktid=tid&skt=2022-03-01T08%3A12%3A34Z&ske=2022-03-01T09%3A12%3A34Z&sks=b&skv=2020-12-06&sig=VkI3h/LWkD6qcDzshjQzCuCdMPDCFA3tMEbxM%2BED5Nc%3D"
        );
    }
}
