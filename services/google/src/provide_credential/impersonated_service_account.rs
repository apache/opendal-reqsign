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

use http::header::CONTENT_TYPE;
use log::{debug, error};
use serde::{Deserialize, Serialize};

use crate::credential::{
    Credential, ImpersonatedServiceAccount, Token, parse_service_account_impersonation_url,
};
use crate::service_account_impersonation::generate_access_token;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, Result};

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// OAuth2 refresh token request.
#[derive(Serialize)]
struct RefreshTokenRequest {
    grant_type: &'static str,
    refresh_token: String,
    client_id: String,
    client_secret: String,
}

/// OAuth2 token response.
#[derive(Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// ImpersonatedServiceAccountCredentialProvider exchanges impersonated service account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ImpersonatedServiceAccountCredentialProvider {
    impersonated_service_account: ImpersonatedServiceAccount,
    scope: Option<String>,
}

impl ImpersonatedServiceAccountCredentialProvider {
    /// Create a new ImpersonatedServiceAccountCredentialProvider.
    pub fn new(impersonated_service_account: ImpersonatedServiceAccount) -> Self {
        Self {
            impersonated_service_account,
            scope: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    async fn generate_bearer_auth_token(&self, ctx: &Context) -> Result<Token> {
        debug!("refreshing OAuth2 token for impersonated service account");

        let request = RefreshTokenRequest {
            grant_type: "refresh_token",
            refresh_token: self
                .impersonated_service_account
                .source_credentials
                .refresh_token
                .clone(),
            client_id: self
                .impersonated_service_account
                .source_credentials
                .client_id
                .clone(),
            client_secret: self
                .impersonated_service_account
                .source_credentials
                .client_secret
                .clone(),
        };

        let body = serde_json::to_vec(&request).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize request").with_source(e)
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!(
                "bearer token loader for impersonated service account got unexpected response: {resp:?}"
            );
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "bearer token loader for impersonated service account failed: {body}"
            )));
        }

        let token_resp: RefreshTokenResponse =
            serde_json::from_slice(resp.body()).map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse token response").with_source(e)
            })?;

        let expires_at = token_resp
            .expires_in
            .map(|expires_in| Timestamp::now() + Duration::from_secs(expires_in));

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    async fn generate_access_token(&self, ctx: &Context, bearer_token: &Token) -> Result<Token> {
        debug!("generating access token for impersonated service account");

        let scope = self
            .scope
            .clone()
            .or_else(|| ctx.env_var(crate::constants::GOOGLE_SCOPE))
            .unwrap_or_else(|| crate::constants::DEFAULT_SCOPE.to_string());

        generate_access_token(
            ctx,
            &self
                .impersonated_service_account
                .service_account_impersonation_url,
            &bearer_token.access_token,
            &[scope],
            Some(&self.impersonated_service_account.delegates),
            Some(MAX_LIFETIME),
        )
        .await
    }
}
impl ProvideCredential for ImpersonatedServiceAccountCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // First get bearer token using OAuth2 refresh
        let bearer_token = self.generate_bearer_auth_token(ctx).await?;

        // Then exchange for impersonated access token
        let access_token = self.generate_access_token(ctx, &bearer_token).await?;

        let credential = Credential::with_token(access_token);
        let signer_email = parse_service_account_impersonation_url(
            &self
                .impersonated_service_account
                .service_account_impersonation_url,
        )
        .ok();
        Ok(Some(match signer_email {
            Some(signer_email) => credential.with_signer_email(signer_email),
            None => credential,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use reqsign_core::HttpSend;

    #[derive(Clone, Debug)]
    struct MockHttpSend;

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            let body = match req.uri().to_string().as_str() {
                "https://oauth2.googleapis.com/token" => {
                    br#"{"access_token":"source-token","expires_in":3600}"#.as_slice()
                }
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target%40example.com:generateAccessToken" => {
                    br#"{"accessToken":"impersonated-token","expireTime":"2100-01-01T00:00:00Z"}"#
                        .as_slice()
                }
                uri => panic!("unexpected request: {uri}"),
            };

            Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(body.into())
                .expect("response must build"))
        }
    }

    #[tokio::test]
    async fn preserves_impersonated_service_account_identity() -> Result<()> {
        let provider = ImpersonatedServiceAccountCredentialProvider::new(
            ImpersonatedServiceAccount {
                service_account_impersonation_url: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target%40example.com:generateAccessToken".to_string(),
                source_credentials: crate::credential::OAuth2Credentials {
                    client_id: "client-id".to_string(),
                    client_secret: "client-secret".to_string(),
                    refresh_token: "refresh-token".to_string(),
                },
                delegates: Vec::new(),
            },
        );

        let credential = provider
            .provide_credential(&Context::new().with_http_send(MockHttpSend))
            .await?
            .expect("credential must exist");

        assert_eq!(
            credential.signer_email.as_deref(),
            Some("target@example.com")
        );
        assert_eq!(
            credential
                .token
                .as_ref()
                .expect("token must exist")
                .access_token,
            "impersonated-token"
        );
        Ok(())
    }
}
