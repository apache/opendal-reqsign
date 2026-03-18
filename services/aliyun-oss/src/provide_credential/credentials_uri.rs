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

use crate::{Credential, constants::ALIBABA_CLOUD_CREDENTIALS_URI};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;

/// CredentialsUriCredentialProvider loads temporary credentials from a custom URI.
///
/// Configuration values can be provided directly via [`with_uri`] or through the
/// `ALIBABA_CLOUD_CREDENTIALS_URI` environment variable.
#[derive(Debug, Default, Clone)]
pub struct CredentialsUriCredentialProvider {
    uri: Option<String>,
}

impl CredentialsUriCredentialProvider {
    /// Create a new `CredentialsUriCredentialProvider` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the credentials URI directly.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_CREDENTIALS_URI`.
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    fn get_uri(&self, ctx: &Context) -> Option<String> {
        self.uri
            .clone()
            .or_else(|| ctx.env_var(ALIBABA_CLOUD_CREDENTIALS_URI))
            .filter(|uri| !uri.is_empty())
    }
}

impl ProvideCredential for CredentialsUriCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(uri) = self.get_uri(ctx) else {
            return Ok(None);
        };

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&uri)
            .body(Vec::new())
            .map_err(|e| {
                Error::request_invalid("failed to build credentials URI request")
                    .with_source(e)
                    .with_context(format!("uri: {uri}"))
            })?;

        let resp = ctx
            .http_send_as_string(req.map(Into::into))
            .await
            .map_err(|e| {
                Error::unexpected("failed to fetch credentials from credentials URI")
                    .with_source(e)
                    .with_context(format!("uri: {uri}"))
                    .set_retryable(true)
            })?;

        let status = resp.status();
        let body = resp.into_body();

        if status != http::StatusCode::OK {
            let error = match status.as_u16() {
                401 | 403 => {
                    Error::permission_denied(format!("credentials URI returned {status}: {body}"))
                }
                404 => Error::config_invalid("credentials URI not found")
                    .with_context(format!("uri: {uri}")),
                500..=599 => {
                    Error::unexpected(format!("credentials URI returned {status}: {body}"))
                        .set_retryable(true)
                }
                _ => Error::unexpected(format!("credentials URI returned {status}: {body}")),
            };

            return Err(error.with_context(format!("uri: {uri}")));
        }

        let resp: CredentialsUriResponse = serde_json::from_str(&body).map_err(|e| {
            Error::unexpected("failed to parse credentials URI response")
                .with_source(e)
                .with_context(format!("uri: {uri}"))
        })?;

        if !resp.code.is_empty() && resp.code != "Success" {
            return Err(Error::unexpected(format!(
                "credentials URI returned error code {}",
                resp.code
            ))
            .with_context(format!("uri: {uri}")));
        }

        if resp.access_key_id.is_empty()
            || resp.access_key_secret.is_empty()
            || resp.security_token.is_empty()
            || resp.expiration.is_empty()
        {
            return Err(Error::credential_invalid(
                "credentials URI response is missing required fields",
            )
            .with_context(format!("uri: {uri}")));
        }

        let expires_in: Timestamp = resp.expiration.parse().map_err(|e| {
            Error::credential_invalid("failed to parse credentials URI expiration")
                .with_source(e)
                .with_context(format!("uri: {uri}"))
        })?;

        Ok(Some(Credential {
            access_key_id: resp.access_key_id,
            access_key_secret: resp.access_key_secret,
            security_token: Some(resp.security_token),
            expires_in: Some(expires_in),
        }))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct CredentialsUriResponse {
    code: String,
    access_key_id: String,
    access_key_secret: String,
    #[serde(alias = "SessionToken")]
    security_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use reqsign_core::time::Timestamp;
    use reqsign_core::{Context, HttpSend, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Debug, Clone)]
    struct MockResponse {
        status: http::StatusCode,
        body: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapturedRequest {
        method: http::Method,
        uri: String,
    }

    #[derive(Debug, Clone)]
    struct SequenceHttpSend {
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        responses: Arc<Mutex<VecDeque<MockResponse>>>,
    }

    impl SequenceHttpSend {
        fn new(responses: Vec<MockResponse>) -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(responses.into())),
            }
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().expect("lock poisoned").clone()
        }

        fn call_count(&self) -> usize {
            self.requests.lock().expect("lock poisoned").len()
        }
    }

    impl HttpSend for SequenceHttpSend {
        async fn http_send(
            &self,
            req: http::Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            self.requests
                .lock()
                .expect("lock poisoned")
                .push(CapturedRequest {
                    method: req.method().clone(),
                    uri: req.uri().to_string(),
                });

            let resp = self
                .responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .expect("mock response must exist");

            Ok(http::Response::builder()
                .status(resp.status)
                .body(Bytes::from(resp.body))
                .expect("response must build"))
        }
    }

    fn credentials_response(expiration: String, access_key_id: &str) -> String {
        format!(
            r#"{{"Code":"Success","AccessKeyId":"{access_key_id}","AccessKeySecret":"secret","SecurityToken":"token","Expiration":"{expiration}"}}"#
        )
    }

    #[tokio::test]
    async fn test_credentials_uri_provider_without_config() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(SequenceHttpSend::new(Vec::new()))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let provider = CredentialsUriCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_credentials_uri_provider_reads_env_uri() -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![MockResponse {
            status: http::StatusCode::OK,
            body: credentials_response("2124-05-25T11:45:17Z".to_string(), "uri_access_key"),
        }]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_CREDENTIALS_URI.to_string(),
                    "http://127.0.0.1/credentials".to_string(),
                )]),
            });

        let cred = CredentialsUriCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        assert_eq!("uri_access_key", cred.access_key_id);
        assert_eq!("secret", cred.access_key_secret);
        assert_eq!(Some("token".to_string()), cred.security_token);
        assert_eq!(
            vec![CapturedRequest {
                method: http::Method::GET,
                uri: "http://127.0.0.1/credentials".to_string(),
            }],
            http_send.requests()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_credentials_uri_provider_builder_overrides_env() -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![MockResponse {
            status: http::StatusCode::OK,
            body: credentials_response("2124-05-25T11:45:17Z".to_string(), "override_access_key"),
        }]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_CREDENTIALS_URI.to_string(),
                    "http://127.0.0.1/env-credentials".to_string(),
                )]),
            });

        let cred = CredentialsUriCredentialProvider::new()
            .with_uri("http://127.0.0.1/builder-credentials")
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        assert_eq!("override_access_key", cred.access_key_id);
        assert_eq!(
            vec![CapturedRequest {
                method: http::Method::GET,
                uri: "http://127.0.0.1/builder-credentials".to_string(),
            }],
            http_send.requests()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_credentials_uri_provider_refreshes_via_signer_cache() -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![
            MockResponse {
                status: http::StatusCode::OK,
                body: credentials_response(
                    (Timestamp::now() + Duration::from_secs(60)).format_rfc3339_zulu(),
                    "first_access_key",
                ),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: credentials_response(
                    (Timestamp::now() + Duration::from_secs(600)).format_rfc3339_zulu(),
                    "second_access_key",
                ),
            },
        ]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });
        let signer = reqsign_core::Signer::new(
            ctx,
            CredentialsUriCredentialProvider::new().with_uri("http://127.0.0.1/credentials"),
            crate::RequestSigner::new("bucket"),
        );

        let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        signer.sign(&mut req, None).await?;

        let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        signer.sign(&mut req, None).await?;

        assert_eq!(2, http_send.call_count());

        Ok(())
    }

    #[tokio::test]
    async fn test_credentials_uri_provider_reuses_valid_credential_via_signer_cache()
    -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![MockResponse {
            status: http::StatusCode::OK,
            body: credentials_response(
                (Timestamp::now() + Duration::from_secs(600)).format_rfc3339_zulu(),
                "cached_access_key",
            ),
        }]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });
        let signer = reqsign_core::Signer::new(
            ctx,
            CredentialsUriCredentialProvider::new().with_uri("http://127.0.0.1/credentials"),
            crate::RequestSigner::new("bucket"),
        );

        let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        signer.sign(&mut req, None).await?;

        let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        signer.sign(&mut req, None).await?;

        assert_eq!(1, http_send.call_count());

        Ok(())
    }
}
