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

use std::time::Duration;

use form_urlencoded::Serializer;
use http::header::{ACCEPT, CONTENT_TYPE};
use log::{debug, error};
use serde::{Deserialize, Serialize};

use crate::credential::{Credential, ExternalAccount, Token, external_account};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, Result};

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// STS token response.
#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

/// Impersonated token response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonatedTokenResponse {
    access_token: String,
    expire_time: String,
}

/// Impersonation request.
#[derive(Serialize)]
struct ImpersonationRequest {
    scope: Vec<String>,
    lifetime: String,
}

/// ExternalAccountCredentialProvider exchanges external account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ExternalAccountCredentialProvider {
    external_account: ExternalAccount,
    scope: Option<String>,
}

impl ExternalAccountCredentialProvider {
    /// Create a new ExternalAccountCredentialProvider.
    pub fn new(external_account: ExternalAccount) -> Self {
        Self {
            external_account,
            scope: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    fn resolve_scope(&self, ctx: &Context) -> String {
        self.scope
            .clone()
            .or_else(|| ctx.env_var(crate::constants::GOOGLE_SCOPE))
            .unwrap_or_else(|| crate::constants::DEFAULT_SCOPE.to_string())
    }

    async fn load_oidc_token(&self, ctx: &Context) -> Result<String> {
        match &self.external_account.credential_source {
            external_account::Source::File(source) => {
                self.load_file_sourced_token(ctx, source).await
            }
            external_account::Source::Url(source) => self.load_url_sourced_token(ctx, source).await,
        }
    }

    async fn load_file_sourced_token(
        &self,
        ctx: &Context,
        source: &external_account::FileSource,
    ) -> Result<String> {
        let file = resolve_template(ctx, &source.file)?;
        debug!("loading OIDC token from file: {}", file);

        let content = ctx.file_read(&file).await?;
        let token = source.format.parse(&content)?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(reqsign_core::Error::credential_invalid(
                "OIDC token loaded from file is empty",
            ));
        }

        Ok(token)
    }

    async fn load_url_sourced_token(
        &self,
        ctx: &Context,
        source: &external_account::UrlSource,
    ) -> Result<String> {
        let url = resolve_template(ctx, &source.url)?;
        debug!("loading OIDC token from URL: {}", url);

        let mut req = http::Request::get(&url);

        // Add custom headers if any
        if let Some(headers) = &source.headers {
            for (key, value) in headers {
                let value = resolve_template(ctx, value)?;
                req = req.header(key, value);
            }
        }

        let resp = ctx
            .http_send(req.body(Vec::<u8>::new().into()).map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?)
            .await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {resp:?}");
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange OIDC token failed: {body}"
            )));
        }

        let token = source.format.parse(resp.body())?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(reqsign_core::Error::credential_invalid(
                "OIDC token loaded from URL is empty",
            ));
        }

        Ok(token)
    }

    async fn exchange_sts_token(&self, ctx: &Context, oidc_token: &str) -> Result<Token> {
        debug!("exchanging OIDC token for STS access token");

        let scope = self.resolve_scope(ctx);
        let token_url = resolve_template(ctx, &self.external_account.token_url)?;
        let audience = resolve_template(ctx, &self.external_account.audience)?;
        let subject_token_type = resolve_template(ctx, &self.external_account.subject_token_type)?;

        let body = Serializer::new(String::new())
            .append_pair(
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            )
            .append_pair(
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            )
            .append_pair("audience", &audience)
            .append_pair("scope", &scope)
            .append_pair("subject_token", oidc_token)
            .append_pair("subject_token_type", &subject_token_type)
            .finish();

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(token_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {resp:?}");
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange token failed: {body}"
            )));
        }

        let token_resp: StsTokenResponse = serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse STS response").with_source(e)
        })?;

        let expires_at = token_resp
            .expires_in
            .map(|expires_in| Timestamp::now() + Duration::from_secs(expires_in));

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    async fn impersonate_service_account(
        &self,
        ctx: &Context,
        access_token: &str,
    ) -> Result<Option<Token>> {
        let Some(url) = &self.external_account.service_account_impersonation_url else {
            return Ok(None);
        };

        debug!("impersonating service account");

        let scope = self.resolve_scope(ctx);
        let lifetime = self
            .external_account
            .service_account_impersonation
            .as_ref()
            .and_then(|s| s.token_lifetime_seconds)
            .unwrap_or(MAX_LIFETIME.as_secs() as usize);

        let lifetime = if lifetime == 0 {
            return Err(reqsign_core::Error::config_invalid(
                "service_account_impersonation.token_lifetime_seconds must be positive",
            ));
        } else {
            lifetime.min(MAX_LIFETIME.as_secs() as usize)
        };

        let request = ImpersonationRequest {
            scope: vec![scope.clone()],
            lifetime: format!("{lifetime}s"),
        };

        let body = serde_json::to_vec(&request).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize request").with_source(e)
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(http::header::AUTHORIZATION, {
                let mut value: http::HeaderValue =
                    format!("Bearer {access_token}").parse().map_err(|e| {
                        reqsign_core::Error::unexpected("failed to parse header value")
                            .with_source(e)
                    })?;
                value.set_sensitive(true);
                value
            })
            .body(body.into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("impersonated token got unexpected response: {resp:?}");
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange impersonated token failed: {body}"
            )));
        }

        let token_resp: ImpersonatedTokenResponse =
            serde_json::from_slice(resp.body()).map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse impersonation response")
                    .with_source(e)
            })?;

        // Parse expire time from RFC3339 format
        Ok(Some(Token {
            access_token: token_resp.access_token,
            expires_at: token_resp.expire_time.parse().ok(),
        }))
    }
}

#[async_trait::async_trait]
impl ProvideCredential for ExternalAccountCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Load OIDC token from source
        let oidc_token = self.load_oidc_token(ctx).await?;

        // Exchange for STS token
        let sts_token = self.exchange_sts_token(ctx, &oidc_token).await?;

        // Try to impersonate service account if configured
        let final_token = if let Some(token) = self
            .impersonate_service_account(ctx, &sts_token.access_token)
            .await?
        {
            token
        } else {
            sts_token
        };

        Ok(Some(Credential::with_token(final_token)))
    }
}

fn resolve_template(ctx: &Context, input: &str) -> Result<String> {
    // Google external account credentials commonly contain `${VAR}` placeholders that must be
    // substituted using process environment variables (e.g. GitHub Actions OIDC).
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    loop {
        let Some(start) = rest.find("${") else {
            out.push_str(rest);
            return Ok(out);
        };

        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];

        let Some(end) = rest.find('}') else {
            return Err(reqsign_core::Error::config_invalid(format!(
                "invalid template syntax in value: {input}"
            )));
        };

        let var = &rest[..end];
        rest = &rest[end + 1..];

        if var.is_empty() {
            return Err(reqsign_core::Error::config_invalid(format!(
                "empty template variable in value: {input}"
            )));
        }

        let value = ctx.env_var(var).filter(|v| !v.is_empty()).ok_or_else(|| {
            reqsign_core::Error::config_invalid(format!(
                "missing environment variable {var} required by template: {input}"
            ))
        })?;
        out.push_str(&value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use bytes::Bytes;
    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use reqsign_core::{Env, FileRead, HttpSend};
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[derive(Debug, Default)]
    struct MockEnv {
        vars: HashMap<String, String>,
    }

    impl MockEnv {
        fn with_var(mut self, k: &str, v: &str) -> Self {
            self.vars.insert(k.to_string(), v.to_string());
            self
        }
    }

    impl Env for MockEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }

        fn vars(&self) -> HashMap<String, String> {
            self.vars.clone()
        }

        fn home_dir(&self) -> Option<PathBuf> {
            None
        }
    }

    #[derive(Debug, Default)]
    struct MockFileRead {
        files: HashMap<String, Vec<u8>>,
    }

    impl MockFileRead {
        fn with_file(mut self, path: &str, content: impl Into<Vec<u8>>) -> Self {
            self.files.insert(path.to_string(), content.into());
            self
        }
    }

    #[async_trait]
    impl FileRead for MockFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            self.files.get(path).cloned().ok_or_else(|| {
                reqsign_core::Error::config_invalid(format!("file not found: {path}"))
            })
        }
    }

    #[derive(Debug)]
    struct CaptureStsHttpSend {
        expected_url: String,
        expected_scope: String,
        expected_subject_token: String,
        expected_audience: String,
        expected_subject_token_type: String,
        access_token: String,
    }

    #[async_trait]
    impl HttpSend for CaptureStsHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(req.uri().to_string(), self.expected_url);
            assert_eq!(
                req.headers()
                    .get(CONTENT_TYPE)
                    .expect("content-type must exist")
                    .to_str()
                    .expect("content-type must be valid string"),
                "application/x-www-form-urlencoded"
            );

            let pairs: HashMap<String, String> = form_urlencoded::parse(req.body().as_ref())
                .into_owned()
                .collect();
            assert_eq!(
                pairs.get("grant_type").map(String::as_str),
                Some("urn:ietf:params:oauth:grant-type:token-exchange")
            );
            assert_eq!(
                pairs.get("requested_token_type").map(String::as_str),
                Some("urn:ietf:params:oauth:token-type:access_token")
            );
            assert_eq!(
                pairs.get("audience").map(String::as_str),
                Some(self.expected_audience.as_str())
            );
            assert_eq!(
                pairs.get("scope").map(String::as_str),
                Some(self.expected_scope.as_str())
            );
            assert_eq!(
                pairs.get("subject_token").map(String::as_str),
                Some(self.expected_subject_token.as_str())
            );
            assert_eq!(
                pairs.get("subject_token_type").map(String::as_str),
                Some(self.expected_subject_token_type.as_str())
            );

            let body = serde_json::json!({
                "access_token": &self.access_token,
                "expires_in": 3600
            });
            Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(serde_json::to_vec(&body).expect("json must encode").into())
                .expect("response must build"))
        }
    }

    #[derive(Debug)]
    struct UrlThenStsHttpSend {
        expected_get_url: String,
        expected_get_auth: String,
        expected_post_url: String,
        expected_subject_token: String,
    }

    #[async_trait]
    impl HttpSend for UrlThenStsHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            match *req.method() {
                http::Method::GET => {
                    assert_eq!(req.uri().to_string(), self.expected_get_url);
                    assert_eq!(
                        req.headers()
                            .get(AUTHORIZATION)
                            .expect("authorization must exist")
                            .to_str()
                            .expect("authorization must be valid string"),
                        self.expected_get_auth
                    );
                    Ok(http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(b"test-oidc-token".as_slice().into())
                        .expect("response must build"))
                }
                http::Method::POST => {
                    assert_eq!(req.uri().to_string(), self.expected_post_url);
                    let pairs: HashMap<String, String> =
                        form_urlencoded::parse(req.body().as_ref())
                            .into_owned()
                            .collect();
                    assert_eq!(
                        pairs.get("subject_token").map(String::as_str),
                        Some(self.expected_subject_token.as_str())
                    );
                    Ok(http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(
                            br#"{"access_token":"final-token","expires_in":3600}"#
                                .as_slice()
                                .into(),
                        )
                        .expect("response must build"))
                }
                _ => unreachable!("unexpected method"),
            }
        }
    }

    #[test]
    fn test_resolve_template() {
        let ctx = Context::new().with_env(MockEnv::default().with_var("FOO", "bar"));
        assert_eq!(resolve_template(&ctx, "a${FOO}c").unwrap(), "abarc");
    }

    #[tokio::test]
    async fn test_external_account_file_source_uses_form_encoded_sts() -> Result<()> {
        let external_account = ExternalAccount {
            audience: "aud".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            credential_source: external_account::Source::File(external_account::FileSource {
                file: "/var/run/token".to_string(),
                format: external_account::Format::Text,
            }),
            service_account_impersonation_url: None,
            service_account_impersonation: None,
        };

        let http = CaptureStsHttpSend {
            expected_url: "https://sts.googleapis.com/v1/token".to_string(),
            expected_scope: "scope-a".to_string(),
            expected_subject_token: "test-oidc".to_string(),
            expected_audience: "aud".to_string(),
            expected_subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            access_token: "access-token".to_string(),
        };
        let fs = MockFileRead::default().with_file("/var/run/token", b"  test-oidc \n");
        let ctx = Context::new().with_http_send(http).with_file_read(fs);

        let provider =
            ExternalAccountCredentialProvider::new(external_account).with_scope("scope-a");
        let cred = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must exist");
        assert!(cred.has_token());
        assert!(cred.has_valid_token());
        Ok(())
    }

    #[tokio::test]
    async fn test_external_account_url_source_supports_env_templates() -> Result<()> {
        let external_account = ExternalAccount {
            audience: "aud".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            credential_source: external_account::Source::Url(external_account::UrlSource {
                url: "https://example.com/${PATH}".to_string(),
                format: external_account::Format::Text,
                headers: Some(HashMap::from([(
                    "Authorization".to_string(),
                    "Bearer ${TOKEN}".to_string(),
                )])),
            }),
            service_account_impersonation_url: None,
            service_account_impersonation: None,
        };

        let http = UrlThenStsHttpSend {
            expected_get_url: "https://example.com/oidc".to_string(),
            expected_get_auth: "Bearer secret".to_string(),
            expected_post_url: "https://sts.googleapis.com/v1/token".to_string(),
            expected_subject_token: "test-oidc-token".to_string(),
        };

        let env = MockEnv::default()
            .with_var("PATH", "oidc")
            .with_var("TOKEN", "secret");

        let ctx = Context::new().with_http_send(http).with_env(env);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let cred = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must exist");
        assert!(cred.has_token());
        assert!(cred.has_valid_token());
        Ok(())
    }
}
