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
use crate::constants::{
    ALIBABA_CLOUD_ECS_METADATA, ALIBABA_CLOUD_ECS_METADATA_DISABLED,
    ALIBABA_CLOUD_ECS_METADATA_SERVICE_ENDPOINT, ALIBABA_CLOUD_IMDSV1_DISABLED,
};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;

const DEFAULT_ECS_METADATA_ENDPOINT: &str = "http://100.100.100.200";
const ECS_METADATA_TOKEN_TTL_SECONDS: u64 = 21600;

/// EcsRamRoleCredentialProvider loads temporary credentials from the ECS metadata service.
///
/// Configuration values can be provided directly via builder methods or through
/// the following environment variables:
/// - `ALIBABA_CLOUD_ECS_METADATA`: Optional ECS RAM role name
/// - `ALIBABA_CLOUD_ECS_METADATA_DISABLED`: Disable the provider when set to `true`
/// - `ALIBABA_CLOUD_IMDSV1_DISABLED`: Require IMDSv2 token requests when set to `true`
/// - `ALIBABA_CLOUD_ECS_METADATA_SERVICE_ENDPOINT`: Override the metadata endpoint
#[derive(Debug, Default, Clone)]
pub struct EcsRamRoleCredentialProvider {
    endpoint: Option<String>,
    role_name: Option<String>,
    disable_imdsv1: Option<bool>,
}

impl EcsRamRoleCredentialProvider {
    /// Create a new `EcsRamRoleCredentialProvider` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the metadata service endpoint directly.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_ECS_METADATA_SERVICE_ENDPOINT`.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the ECS RAM role name directly.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_ECS_METADATA`.
    pub fn with_role_name(mut self, role_name: impl Into<String>) -> Self {
        self.role_name = Some(role_name.into());
        self
    }

    /// Configure whether IMDSv1 fallback is disabled.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_IMDSV1_DISABLED`.
    pub fn with_disable_imdsv1(mut self, disable: bool) -> Self {
        self.disable_imdsv1 = Some(disable);
        self
    }

    fn is_disabled(&self, ctx: &Context) -> bool {
        parse_bool_env(ctx.env_var(ALIBABA_CLOUD_ECS_METADATA_DISABLED))
    }

    fn disable_imdsv1(&self, ctx: &Context) -> bool {
        self.disable_imdsv1
            .unwrap_or_else(|| parse_bool_env(ctx.env_var(ALIBABA_CLOUD_IMDSV1_DISABLED)))
    }

    fn get_endpoint(&self, ctx: &Context) -> String {
        self.endpoint
            .clone()
            .or_else(|| ctx.env_var(ALIBABA_CLOUD_ECS_METADATA_SERVICE_ENDPOINT))
            .filter(|endpoint| !endpoint.is_empty())
            .unwrap_or_else(|| DEFAULT_ECS_METADATA_ENDPOINT.to_string())
    }

    fn get_role_name(&self, ctx: &Context) -> Option<String> {
        self.role_name
            .clone()
            .or_else(|| ctx.env_var(ALIBABA_CLOUD_ECS_METADATA))
            .filter(|role_name| !role_name.is_empty())
    }

    async fn get_metadata_token(&self, ctx: &Context) -> Result<Option<String>> {
        let endpoint = self.get_endpoint(ctx);
        let url = format!("{endpoint}/latest/api/token");
        let req = http::Request::builder()
            .method(http::Method::PUT)
            .uri(&url)
            .header(
                "X-aliyun-ecs-metadata-token-ttl-seconds",
                ECS_METADATA_TOKEN_TTL_SECONDS.to_string(),
            )
            .body(Vec::new())
            .map_err(|e| {
                Error::request_invalid("failed to build ECS metadata token request")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
            })?;

        let resp = ctx.http_send_as_string(req.map(Into::into)).await;
        match resp {
            Ok(resp) if resp.status() == http::StatusCode::OK => {
                Ok(Some(resp.into_body().trim().to_string()))
            }
            Ok(resp) if self.disable_imdsv1(ctx) => Err(Error::unexpected(format!(
                "failed to fetch ECS metadata token: {}",
                resp.into_body()
            ))
            .with_context(format!("url: {url}"))),
            Ok(_) => Ok(None),
            Err(err) if self.disable_imdsv1(ctx) => {
                Err(Error::unexpected("failed to fetch ECS metadata token")
                    .with_source(err)
                    .with_context(format!("url: {url}")))
            }
            Err(_) => Ok(None),
        }
    }

    async fn load_role_name(&self, ctx: &Context, metadata_token: Option<&str>) -> Result<String> {
        let endpoint = self.get_endpoint(ctx);
        let url = format!("{endpoint}/latest/meta-data/ram/security-credentials/");
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .body(Vec::new())
            .map_err(|e| {
                Error::request_invalid("failed to build ECS role name request")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
            })?;

        if let Some(metadata_token) = metadata_token {
            req.headers_mut().insert(
                "X-aliyun-ecs-metadata-token",
                metadata_token.parse().map_err(|e| {
                    Error::config_invalid("invalid ECS metadata token")
                        .with_source(e)
                        .with_context(format!("url: {url}"))
                })?,
            );
        }

        let resp = ctx
            .http_send_as_string(req.map(Into::into))
            .await
            .map_err(|e| {
                Error::unexpected("failed to fetch ECS role name")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
                    .set_retryable(true)
            })?;

        if resp.status() != http::StatusCode::OK {
            return Err(Error::unexpected(format!(
                "failed to fetch ECS role name: {}",
                resp.into_body()
            ))
            .with_context(format!("url: {url}")));
        }

        let role_name = resp
            .into_body()
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();

        if role_name.is_empty() {
            return Err(
                Error::config_invalid("ECS metadata did not return a RAM role name")
                    .with_context(format!("url: {url}")),
            );
        }

        Ok(role_name)
    }

    async fn load_credentials(
        &self,
        ctx: &Context,
        metadata_token: Option<&str>,
        role_name: &str,
    ) -> Result<Credential> {
        let endpoint = self.get_endpoint(ctx);
        let url = format!("{endpoint}/latest/meta-data/ram/security-credentials/{role_name}");
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .body(Vec::new())
            .map_err(|e| {
                Error::request_invalid("failed to build ECS credential request")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
            })?;

        if let Some(metadata_token) = metadata_token {
            req.headers_mut().insert(
                "X-aliyun-ecs-metadata-token",
                metadata_token.parse().map_err(|e| {
                    Error::config_invalid("invalid ECS metadata token")
                        .with_source(e)
                        .with_context(format!("url: {url}"))
                })?,
            );
        }

        let resp = ctx
            .http_send_as_string(req.map(Into::into))
            .await
            .map_err(|e| {
                Error::unexpected("failed to fetch ECS RAM role credentials")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
                    .set_retryable(true)
            })?;

        let status = resp.status();
        let body = resp.into_body();
        if status != http::StatusCode::OK {
            let error = match status.as_u16() {
                401 | 403 => Error::permission_denied(format!(
                    "ECS metadata denied credential access: {body}"
                )),
                404 => Error::config_invalid("ECS RAM role credentials not found")
                    .with_context(format!("role_name: {role_name}")),
                500..=599 => Error::unexpected(format!("ECS metadata returned {status}: {body}"))
                    .set_retryable(true),
                _ => Error::unexpected(format!("ECS metadata returned {status}: {body}")),
            };
            return Err(error.with_context(format!("url: {url}")));
        }

        let resp: EcsRamRoleResponse = serde_json::from_str(&body).map_err(|e| {
            Error::unexpected("failed to parse ECS RAM role credentials")
                .with_source(e)
                .with_context(format!("url: {url}"))
        })?;

        if !resp.code.is_empty() && resp.code != "Success" {
            return Err(Error::unexpected(format!(
                "ECS metadata returned error code {}",
                resp.code
            ))
            .with_context(format!("role_name: {role_name}")));
        }

        if resp.access_key_id.is_empty()
            || resp.access_key_secret.is_empty()
            || resp.security_token.is_empty()
            || resp.expiration.is_empty()
        {
            return Err(Error::credential_invalid(
                "ECS metadata response is missing required fields",
            )
            .with_context(format!("role_name: {role_name}")));
        }

        let expires_in: Timestamp = resp.expiration.parse().map_err(|e| {
            Error::credential_invalid("failed to parse ECS credential expiration")
                .with_source(e)
                .with_context(format!("role_name: {role_name}"))
        })?;

        Ok(Credential {
            access_key_id: resp.access_key_id,
            access_key_secret: resp.access_key_secret,
            security_token: Some(resp.security_token),
            expires_in: Some(expires_in),
        })
    }
}

impl ProvideCredential for EcsRamRoleCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.is_disabled(ctx) {
            return Ok(None);
        }

        let metadata_token = self.get_metadata_token(ctx).await?;
        let role_name = match self.get_role_name(ctx) {
            Some(role_name) => role_name,
            None => self.load_role_name(ctx, metadata_token.as_deref()).await?,
        };

        let cred = self
            .load_credentials(ctx, metadata_token.as_deref(), &role_name)
            .await?;
        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct EcsRamRoleResponse {
    code: String,
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

fn parse_bool_env(value: Option<String>) -> bool {
    value
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: String,
        metadata_token: Option<String>,
        metadata_token_ttl: Option<String>,
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
            let metadata_token = req
                .headers()
                .get("X-aliyun-ecs-metadata-token")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
            let metadata_token_ttl = req
                .headers()
                .get("X-aliyun-ecs-metadata-token-ttl-seconds")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);

            self.requests
                .lock()
                .expect("lock poisoned")
                .push(CapturedRequest {
                    method: req.method().clone(),
                    uri: req.uri().to_string(),
                    metadata_token,
                    metadata_token_ttl,
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

    fn ecs_credential_response(expiration: String, access_key_id: &str) -> String {
        format!(
            r#"{{"Code":"Success","AccessKeyId":"{access_key_id}","AccessKeySecret":"secret","SecurityToken":"token","Expiration":"{expiration}"}}"#
        )
    }

    #[tokio::test]
    async fn test_ecs_ram_role_provider_disabled_by_env() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(SequenceHttpSend::new(Vec::new()))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_ECS_METADATA_DISABLED.to_string(),
                    "true".to_string(),
                )]),
            });

        let cred = EcsRamRoleCredentialProvider::new()
            .provide_credential(&ctx)
            .await?;
        assert!(cred.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_ecs_ram_role_provider_uses_imdsv2_token() -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![
            MockResponse {
                status: http::StatusCode::OK,
                body: "metadata-token".to_string(),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: ecs_credential_response("2124-05-25T11:45:17Z".to_string(), "ecs_access_key"),
            },
        ]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_ECS_METADATA.to_string(),
                    "test-role".to_string(),
                )]),
            });

        let cred = EcsRamRoleCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        assert_eq!("ecs_access_key", cred.access_key_id);
        let requests = http_send.requests();
        assert_eq!(2, requests.len());
        assert_eq!(http::Method::PUT, requests[0].method);
        assert_eq!(
            Some(ECS_METADATA_TOKEN_TTL_SECONDS.to_string()),
            requests[0].metadata_token_ttl
        );
        assert_eq!(
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/test-role",
            requests[1].uri
        );
        assert_eq!(
            Some("metadata-token".to_string()),
            requests[1].metadata_token
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_ecs_ram_role_provider_falls_back_to_imdsv1() -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![
            MockResponse {
                status: http::StatusCode::INTERNAL_SERVER_ERROR,
                body: "token failed".to_string(),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: "test-role".to_string(),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: ecs_credential_response("2124-05-25T11:45:17Z".to_string(), "ecs_access_key"),
            },
        ]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let cred = EcsRamRoleCredentialProvider::new()
            .with_endpoint("http://127.0.0.1")
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        assert_eq!("ecs_access_key", cred.access_key_id);
        let requests = http_send.requests();
        assert_eq!(3, requests.len());
        assert_eq!(None, requests[1].metadata_token);
        assert_eq!(None, requests[2].metadata_token);

        Ok(())
    }

    #[tokio::test]
    async fn test_ecs_ram_role_provider_respects_imdsv1_disable() {
        let http_send = SequenceHttpSend::new(vec![MockResponse {
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
            body: "token failed".to_string(),
        }]);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_IMDSV1_DISABLED.to_string(),
                    "true".to_string(),
                )]),
            });

        let err = EcsRamRoleCredentialProvider::new()
            .with_endpoint("http://127.0.0.1")
            .provide_credential(&ctx)
            .await
            .expect_err("provider must fail when IMDSv1 is disabled");

        assert!(
            err.to_string()
                .contains("failed to fetch ECS metadata token")
        );
    }

    #[tokio::test]
    async fn test_ecs_ram_role_provider_refreshes_via_signer_cache() -> anyhow::Result<()> {
        let http_send = SequenceHttpSend::new(vec![
            MockResponse {
                status: http::StatusCode::OK,
                body: "metadata-token".to_string(),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: ecs_credential_response(
                    (Timestamp::now() + Duration::from_secs(60)).format_rfc3339_zulu(),
                    "first_access_key",
                ),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: "metadata-token-2".to_string(),
            },
            MockResponse {
                status: http::StatusCode::OK,
                body: ecs_credential_response(
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
            EcsRamRoleCredentialProvider::new()
                .with_endpoint("http://127.0.0.1")
                .with_role_name("test-role"),
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

        assert_eq!(4, http_send.call_count());

        Ok(())
    }
}
