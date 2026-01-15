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
use async_trait::async_trait;
use http::{HeaderValue, Method, Request, StatusCode};
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;

const AWS_CONTAINER_CREDENTIALS_FULL_URI: &str = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
const AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";

/// EKS Pod Identity Credential Provider
///
/// This provider fetches IAM credentials from the EKS Pod Identity Agent endpoint.
/// It is designed to work with Amazon EKS Pod Identity associations, which provide
/// a simpler alternative to IAM Roles for Service Accounts (IRSA).
///
/// # How it works
///
/// When a pod is configured with an EKS Pod Identity association, the EKS control plane
/// automatically injects environment variables and mounts a service account token:
///
/// - `AWS_CONTAINER_CREDENTIALS_FULL_URI`: Points to the Pod Identity Agent endpoint
/// - `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`: Path to the mounted service account token
///
/// The provider reads the token from the file and uses it to authenticate with the
/// Pod Identity Agent running on the node at `http://169.254.170.23/v1/credentials`.
///
/// # Configuration
///
/// In most cases, no configuration is needed. The provider automatically detects
/// EKS Pod Identity by checking for the required environment variables.
///
/// For testing or custom setups, you can override the endpoint and token file path:
///
/// ```rust,no_run
/// use reqsign_aws_v4::EKSPodIdentityCredentialProvider;
///
/// let provider = EKSPodIdentityCredentialProvider::new()
///     .with_endpoint("http://custom-endpoint/v1/credentials")
///     .with_token_file("/custom/path/to/token");
/// ```
///
/// # Environment Variables
///
/// - `AWS_CONTAINER_CREDENTIALS_FULL_URI`: Full URI to the Pod Identity Agent endpoint
/// - `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`: Path to the service account token file
///
/// # References
///
/// - [EKS Pod Identity Documentation](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)
/// - [How EKS Pod Identity Works](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html)
#[derive(Debug, Clone)]
pub struct EKSPodIdentityCredentialProvider {
    endpoint: Option<String>,
    token_file: Option<String>,
}

impl Default for EKSPodIdentityCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EKSPodIdentityCredentialProvider {
    /// Create a new EKS Pod Identity credential provider
    pub fn new() -> Self {
        Self {
            endpoint: None,
            token_file: None,
        }
    }

    /// Set a custom endpoint for the Pod Identity Agent
    ///
    /// By default, uses the endpoint from `AWS_CONTAINER_CREDENTIALS_FULL_URI`
    /// environment variable, or falls back to `http://169.254.170.23/v1/credentials`.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set a custom path to the service account token file
    ///
    /// By default, uses the path from `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`
    /// environment variable, or falls back to the standard EKS Pod Identity token path.
    pub fn with_token_file(mut self, token_file: impl Into<String>) -> Self {
        self.token_file = Some(token_file.into());
        self
    }

    fn get_endpoint(&self, ctx: &Context) -> Option<String> {
        // Use configured endpoint if provided
        if let Some(endpoint) = &self.endpoint {
            return Some(endpoint.clone());
        }

        // Try environment variable
        if let Some(uri) = ctx.env_var(AWS_CONTAINER_CREDENTIALS_FULL_URI) {
            // Only use this if it points to the EKS Pod Identity Agent
            if uri.contains("169.254.170.23") {
                return Some(uri);
            }
        }

        None
    }

    fn get_token_file(&self, ctx: &Context) -> Option<String> {
        // Use configured token file if provided
        if let Some(token_file) = &self.token_file {
            return Some(token_file.clone());
        }

        // Try environment variable
        ctx.env_var(AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE)
    }

    async fn load_token(&self, ctx: &Context, token_file: &str) -> Result<String> {
        let token = ctx.file_read(token_file).await.map_err(|e| {
            Error::config_invalid("failed to read EKS Pod Identity token file")
                .with_source(e)
                .with_context(format!("file: {token_file}"))
        })?;
        Ok(String::from_utf8_lossy(&token).trim().to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EKSPodIdentityCredentialResponse {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
}

#[async_trait]
impl ProvideCredential for EKSPodIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Check if we have the required environment variables or configuration
        let endpoint = match self.get_endpoint(ctx) {
            Some(ep) => ep,
            None => {
                debug!(
                    "EKS Pod Identity provider: no endpoint found, not running in EKS Pod Identity environment"
                );
                return Ok(None);
            }
        };

        let token_file = match self.get_token_file(ctx) {
            Some(tf) => tf,
            None => {
                debug!(
                    "EKS Pod Identity provider: no token file found, not running in EKS Pod Identity environment"
                );
                return Ok(None);
            }
        };

        debug!("EKS Pod Identity provider: fetching credentials from {endpoint}");

        // Load the service account token
        let token = self.load_token(ctx, &token_file).await?;

        // Build the request to the Pod Identity Agent
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(&endpoint)
            .body(bytes::Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build EKS Pod Identity credentials request")
                    .with_source(e)
                    .with_context(format!("endpoint: {endpoint}"))
            })?;

        // Add the authorization token
        req.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&token).map_err(|e| {
                Error::config_invalid("invalid EKS Pod Identity token")
                    .with_source(e)
                    .with_context(format!("token_file: {token_file}"))
            })?,
        );

        let resp = ctx.http_send(req).await.map_err(|e| {
            Error::unexpected("failed to fetch EKS Pod Identity credentials")
                .with_source(e)
                .with_context(format!("endpoint: {endpoint}"))
                .with_context("hint: check if running on EKS with Pod Identity enabled")
                .set_retryable(true)
        })?;

        if resp.status() != StatusCode::OK {
            let status = resp.status();
            let body = String::from_utf8_lossy(resp.body());

            let error = match status.as_u16() {
                401 | 403 => Error::permission_denied(format!(
                    "EKS Pod not authorized to fetch credentials: {body}"
                ))
                .with_context("hint: check if Pod has proper EKS Pod Identity association"),
                404 => Error::config_invalid("EKS Pod Identity endpoint not found")
                    .with_context(format!("endpoint: {endpoint}"))
                    .with_context("hint: verify the Pod Identity Agent is running on the node"),
                500..=599 => Error::unexpected(format!("EKS Pod Identity Agent error: {body}"))
                    .set_retryable(true),
                _ => Error::unexpected(format!(
                    "EKS Pod Identity Agent returned unexpected status {status}: {body}"
                )),
            };

            return Err(error
                .with_context(format!("http_status: {status}"))
                .with_context(format!("endpoint: {endpoint}")));
        }

        let body = resp.into_body();
        let creds: EKSPodIdentityCredentialResponse =
            serde_json::from_slice(&body).map_err(|e| {
                Error::unexpected("failed to parse EKS Pod Identity credentials response")
                    .with_source(e)
                    .with_context(format!("response_length: {}", body.len()))
                    .with_context(format!("endpoint: {endpoint}"))
            })?;

        let expires_in = creds.expiration.parse().map_err(|e| {
            Error::unexpected("failed to parse EKS Pod Identity credential expiration")
                .with_source(e)
                .with_context(format!("expiration_value: {}", creds.expiration))
        })?;

        Ok(Some(Credential {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: Some(creds.token),
            expires_in: Some(expires_in),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_eks_pod_identity_provider_no_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let provider = EKSPodIdentityCredentialProvider::new();
        let result = provider.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_endpoint_from_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([(
                AWS_CONTAINER_CREDENTIALS_FULL_URI.to_string(),
                "http://169.254.170.23/v1/credentials".to_string(),
            )]),
        });

        let provider = EKSPodIdentityCredentialProvider::new();
        let endpoint = provider.get_endpoint(&ctx);
        assert_eq!(
            endpoint,
            Some("http://169.254.170.23/v1/credentials".to_string())
        );
    }

    #[tokio::test]
    async fn test_get_endpoint_ignores_non_eks_uri() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([(
                AWS_CONTAINER_CREDENTIALS_FULL_URI.to_string(),
                "http://169.254.170.2/v2/credentials".to_string(), // ECS endpoint
            )]),
        });

        let provider = EKSPodIdentityCredentialProvider::new();
        let endpoint = provider.get_endpoint(&ctx);
        assert!(
            endpoint.is_none(),
            "Should not use ECS endpoint for EKS Pod Identity"
        );
    }

    #[tokio::test]
    async fn test_configured_endpoint() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let provider = EKSPodIdentityCredentialProvider::new()
            .with_endpoint("http://custom-endpoint/v1/credentials");

        let endpoint = provider.get_endpoint(&ctx);
        assert_eq!(
            endpoint,
            Some("http://custom-endpoint/v1/credentials".to_string())
        );
    }

    #[tokio::test]
    async fn test_get_token_file_from_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([(
                AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE.to_string(),
                "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"
                    .to_string(),
            )]),
        });

        let provider = EKSPodIdentityCredentialProvider::new();
        let token_file = provider.get_token_file(&ctx);
        assert_eq!(
            token_file,
            Some(
                "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"
                    .to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_configured_token_file() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let provider =
            EKSPodIdentityCredentialProvider::new().with_token_file("/custom/token/path");

        let token_file = provider.get_token_file(&ctx);
        assert_eq!(token_file, Some("/custom/token/path".to_string()));
    }
}
