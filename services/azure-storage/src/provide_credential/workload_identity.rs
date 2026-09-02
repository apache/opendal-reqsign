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
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use std::fmt::{Debug, Formatter};
use std::time::Duration;

#[derive(Clone)]
struct LoadedSubjectToken {
    token: String,
    expires_at: Option<Timestamp>,
}

impl LoadedSubjectToken {
    fn new(token: impl Into<String>, expires_at: Option<Timestamp>) -> Self {
        Self {
            token: token.into(),
            expires_at,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.token.trim().is_empty() {
            return Err(Error::credential_invalid("subject token is empty"));
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= Timestamp::now())
        {
            return Err(Error::credential_invalid("subject token has expired"));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
enum FederatedTokenSource {
    #[default]
    Environment,
    File(String),
    Direct(LoadedSubjectToken),
}

/// Load credential from Azure Workload Identity.
///
/// This loader implements the Azure Workload Identity authentication flow,
/// which allows workloads running in Kubernetes to authenticate to Azure services
/// using a federated token.
///
/// Reference: <https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview>
#[derive(Default, Clone)]
pub struct WorkloadIdentityCredentialProvider {
    tenant_id: Option<String>,
    client_id: Option<String>,
    token_source: FederatedTokenSource,
    authority_host: Option<String>,
}

impl Debug for WorkloadIdentityCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let token_source = match &self.token_source {
            FederatedTokenSource::Environment => "environment",
            FederatedTokenSource::File(_) => "file",
            FederatedTokenSource::Direct(_) => "direct",
        };
        f.debug_struct("WorkloadIdentityCredentialProvider")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("token_source", &token_source)
            .field("authority_host", &self.authority_host)
            .finish()
    }
}

impl WorkloadIdentityCredentialProvider {
    /// Create a new workload identity loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the federated token file path.
    ///
    /// This replaces any previously configured subject-token source.
    pub fn with_federated_token_file(mut self, path: impl Into<String>) -> Self {
        self.token_source = FederatedTokenSource::File(path.into());
        self
    }

    /// Set a caller-provided subject token.
    ///
    /// This replaces any previously configured subject-token source.
    pub fn with_subject_token(mut self, subject_token: impl Into<String>) -> Self {
        self.token_source =
            FederatedTokenSource::Direct(LoadedSubjectToken::new(subject_token, None));
        self
    }

    /// Set a caller-provided subject token with its absolute source expiration.
    ///
    /// This replaces any previously configured subject-token source.
    pub fn with_subject_token_and_expiration(
        mut self,
        subject_token: impl Into<String>,
        expires_at: Timestamp,
    ) -> Self {
        self.token_source =
            FederatedTokenSource::Direct(LoadedSubjectToken::new(subject_token, Some(expires_at)));
        self
    }

    /// Set the authority host.
    pub fn with_authority_host(mut self, authority_host: impl Into<String>) -> Self {
        self.authority_host = Some(authority_host.into());
        self
    }

    async fn load_subject_token(
        &self,
        ctx: &Context,
        envs: &std::collections::HashMap<String, String>,
    ) -> Result<Option<LoadedSubjectToken>> {
        let subject_token = match &self.token_source {
            FederatedTokenSource::Environment => {
                let Some(path) = envs
                    .get("AZURE_FEDERATED_TOKEN_FILE")
                    .filter(|path| !path.is_empty())
                else {
                    return Ok(None);
                };
                load_file_subject_token(ctx, path).await?
            }
            FederatedTokenSource::File(path) => load_file_subject_token(ctx, path).await?,
            FederatedTokenSource::Direct(subject_token) => Some(subject_token.clone()),
        };

        let Some(subject_token) = subject_token else {
            return Ok(None);
        };
        subject_token.validate()?;
        Ok(Some(subject_token))
    }
}
impl ProvideCredential for WorkloadIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        // Check if all required parameters are available from environment
        let tenant_id = match self
            .tenant_id
            .as_ref()
            .or_else(|| envs.get("AZURE_TENANT_ID"))
        {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(None),
        };

        let client_id = match self
            .client_id
            .as_ref()
            .or_else(|| envs.get("AZURE_CLIENT_ID"))
        {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(None),
        };

        let authority_host = self
            .authority_host
            .as_ref()
            .or_else(|| envs.get("AZURE_AUTHORITY_HOST"))
            .filter(|h| !h.is_empty())
            .map(|s| s.as_str())
            .unwrap_or("https://login.microsoftonline.com");

        let Some(subject_token) = self.load_subject_token(ctx, &envs).await? else {
            return Ok(None);
        };
        let token_response = get_workload_identity_token(
            tenant_id,
            client_id,
            &subject_token.token,
            authority_host,
            ctx,
        )
        .await?;

        let expires_on = match token_response.expires_on {
            Some(expires_on) => expires_on.parse().map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse expires_on time").with_source(e)
            })?,
            None => Timestamp::now() + Duration::from_secs(600),
        };

        Ok(Some(Credential::with_bearer_token(
            &token_response.access_token,
            Some(expires_on),
        )))
    }
}

#[derive(serde::Deserialize)]
struct WorkloadIdentityTokenResponse {
    access_token: String,
    expires_on: Option<String>,
}

async fn get_workload_identity_token(
    tenant_id: &str,
    client_id: &str,
    federated_token: &str,
    authority_host: &str,
    ctx: &Context,
) -> Result<WorkloadIdentityTokenResponse> {
    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        authority_host.trim_end_matches('/'),
        tenant_id
    );

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("scope", "https://storage.azure.com/.default")
        .append_pair("client_id", client_id)
        .append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .append_pair("client_assertion", federated_token)
        .append_pair("grant_type", "client_credentials")
        .finish();

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(bytes::Bytes::from(body))
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to build workload identity request")
                .with_source(e)
        })?;

    let resp = ctx.http_send(req).await?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(
            reqsign_core::Error::unexpected("workload identity request failed")
                .with_context(format!("http_status: {status}")),
        );
    }

    let token: WorkloadIdentityTokenResponse =
        serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse workload identity response")
                .with_source(e)
        })?;
    Ok(token)
}

async fn load_file_subject_token(ctx: &Context, path: &str) -> Result<Option<LoadedSubjectToken>> {
    let content = match ctx.file_read(path).await {
        Ok(content) => String::from_utf8(content).map_err(|err| {
            reqsign_core::Error::unexpected("failed to parse federated token file as UTF-8")
                .with_source(err)
        })?,
        Err(_) => return Ok(None),
    };
    let token = content.trim();
    if token.is_empty() {
        return Ok(None);
    }
    Ok(Some(LoadedSubjectToken::new(token, None)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use reqsign_core::{ErrorKind, HttpSend};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct CaptureHttpSend {
        calls: Arc<AtomicUsize>,
        request_body: Arc<Mutex<Option<String>>>,
        status: http::StatusCode,
        response_body: String,
    }

    impl CaptureHttpSend {
        fn success() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                request_body: Arc::new(Mutex::new(None)),
                status: http::StatusCode::OK,
                response_body:
                    r#"{"access_token":"azure-access-token","expires_on":"2124-05-25T11:45:17Z"}"#
                        .to_string(),
            }
        }

        fn error(body: impl Into<String>) -> Self {
            Self {
                status: http::StatusCode::BAD_REQUEST,
                response_body: body.into(),
                ..Self::success()
            }
        }
    }

    impl HttpSend for CaptureHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(
                req.uri(),
                "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
            );
            *self.request_body.lock().expect("lock must succeed") =
                Some(String::from_utf8_lossy(req.body()).into_owned());
            Ok(http::Response::builder()
                .status(self.status)
                .body(Bytes::from(self.response_body.clone()))
                .expect("response must build"))
        }
    }

    #[tokio::test]
    async fn caller_provided_subject_token_builds_exchange_request() -> Result<()> {
        let http = CaptureHttpSend::success();
        let ctx = Context::new().with_http_send(http.clone());
        let provider = WorkloadIdentityCredentialProvider::new()
            .with_tenant_id("test-tenant")
            .with_client_id("test-client")
            .with_federated_token_file("/must-not-be-read")
            .with_subject_token("caller.subject+token/");

        provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must load");

        let body = http
            .request_body
            .lock()
            .expect("lock must succeed")
            .clone()
            .expect("request body must be captured");
        let fields = form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            fields.get("client_assertion").map(String::as_str),
            Some("caller.subject+token/")
        );
        assert_eq!(
            fields.get("client_id").map(String::as_str),
            Some("test-client")
        );
        assert!(!format!("{provider:?}").contains("caller.subject+token/"));
        Ok(())
    }

    #[tokio::test]
    async fn expired_subject_token_is_rejected_before_http() {
        let http = CaptureHttpSend::success();
        let ctx = Context::new().with_http_send(http.clone());
        let provider = WorkloadIdentityCredentialProvider::new()
            .with_tenant_id("test-tenant")
            .with_client_id("test-client")
            .with_subject_token_and_expiration(
                "expired.subject.token",
                Timestamp::now() - Duration::from_secs(1),
            );

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("expired token must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exchange_error_cannot_echo_subject_token() {
        let secret = "echoed.azure.subject.token";
        let http = CaptureHttpSend::error(format!(r#"{{"error_description":"{secret}"}}"#));
        let ctx = Context::new().with_http_send(http);
        let provider = WorkloadIdentityCredentialProvider::new()
            .with_tenant_id("test-tenant")
            .with_client_id("test-client")
            .with_subject_token(secret);

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("exchange error must be returned");
        assert!(!err.to_string().contains(secret));
        assert!(!format!("{err:?}").contains(secret));
    }
}
