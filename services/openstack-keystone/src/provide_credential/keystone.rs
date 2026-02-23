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

use http::header;
use log::debug;

use reqsign_core::{Context, ProvideCredential, Result, time::Timestamp};

use crate::credential::Credential;
use crate::credential::keystone_v3;

/// Credential provider that authenticates against a Keystone v3 identity service.
///
/// This provider performs a POST to `{auth_url}/auth/tokens` with password credentials
/// and extracts the token from the `X-Subject-Token` response header.
#[derive(Debug, Clone)]
pub struct KeystoneCredentialProvider {
    auth_url: String,
    username: String,
    password: String,
    user_domain_name: String,
    project_name: Option<String>,
    project_domain_name: Option<String>,
}

impl KeystoneCredentialProvider {
    /// Create a new KeystoneCredentialProvider with the Keystone identity URL.
    ///
    /// The `auth_url` should be the base Keystone v3 URL, e.g. `https://keystone.example.com/v3`.
    pub fn new(auth_url: impl Into<String>) -> Self {
        Self {
            auth_url: auth_url.into(),
            username: String::new(),
            password: String::new(),
            user_domain_name: "Default".to_string(),
            project_name: None,
            project_domain_name: None,
        }
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    /// Set the user domain name.
    pub fn with_user_domain_name(mut self, domain_name: impl Into<String>) -> Self {
        self.user_domain_name = domain_name.into();
        self
    }

    /// Set the project name for scoped tokens.
    pub fn with_project_name(mut self, project_name: impl Into<String>) -> Self {
        self.project_name = Some(project_name.into());
        self
    }

    /// Set the project domain name.
    pub fn with_project_domain_name(mut self, domain_name: impl Into<String>) -> Self {
        self.project_domain_name = Some(domain_name.into());
        self
    }

    fn build_auth_request(&self) -> keystone_v3::AuthRequest {
        let scope = self
            .project_name
            .as_ref()
            .map(|project_name| keystone_v3::Scope {
                project: keystone_v3::Project {
                    name: project_name.clone(),
                    domain: keystone_v3::Domain {
                        name: self
                            .project_domain_name
                            .clone()
                            .unwrap_or_else(|| self.user_domain_name.clone()),
                    },
                },
            });

        keystone_v3::AuthRequest {
            auth: keystone_v3::Auth {
                identity: keystone_v3::Identity {
                    methods: vec!["password".to_string()],
                    password: keystone_v3::Password {
                        user: keystone_v3::User {
                            name: self.username.clone(),
                            password: self.password.clone(),
                            domain: keystone_v3::Domain {
                                name: self.user_domain_name.clone(),
                            },
                        },
                    },
                },
                scope,
            },
        }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for KeystoneCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.username.is_empty() || self.password.is_empty() {
            debug!("username or password not set, skipping keystone credential provider");
            return Ok(None);
        }

        let auth_request = self.build_auth_request();
        let body = serde_json::to_vec(&auth_request).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize auth request").with_source(e)
        })?;

        let url = format!("{}/auth/tokens", self.auth_url.trim_end_matches('/'));

        debug!(
            "authenticating with Keystone at {url} as user {}",
            self.username
        );

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::CREATED {
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "Keystone authentication failed (status {}): {body}",
                resp.status()
            )));
        }

        let token = resp
            .headers()
            .get("x-subject-token")
            .ok_or_else(|| {
                reqsign_core::Error::unexpected("Keystone response missing X-Subject-Token header")
            })?
            .to_str()
            .map_err(|e| {
                reqsign_core::Error::unexpected("X-Subject-Token header is not valid UTF-8")
                    .with_source(e)
            })?
            .to_string();

        let token_response: keystone_v3::TokenResponse = serde_json::from_slice(resp.body())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse Keystone token response")
                    .with_source(e)
            })?;

        let expires_at: Timestamp = token_response.token.expires_at.parse().map_err(|e| {
            reqsign_core::Error::unexpected(format!(
                "failed to parse Keystone token expiry '{}' as timestamp",
                token_response.token.expires_at
            ))
            .with_source(e)
        })?;

        debug!(
            "Keystone authentication successful, token expires at {expires_at:?}, catalog has {} services",
            token_response.token.catalog.len()
        );

        Ok(Some(Credential {
            token,
            expires_at: Some(expires_at),
            service_catalog: token_response.token.catalog,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_request_unscoped() {
        let provider = KeystoneCredentialProvider::new("https://keystone.example.com/v3")
            .with_username("testuser")
            .with_password("testpass")
            .with_user_domain_name("Default");

        let req = provider.build_auth_request();
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["auth"]["identity"]["methods"][0], "password");
        assert_eq!(
            json["auth"]["identity"]["password"]["user"]["name"],
            "testuser"
        );
        assert_eq!(
            json["auth"]["identity"]["password"]["user"]["password"],
            "testpass"
        );
        assert_eq!(
            json["auth"]["identity"]["password"]["user"]["domain"]["name"],
            "Default"
        );
        assert!(json["auth"]["scope"].is_null());
    }

    #[test]
    fn test_build_auth_request_project_scoped() {
        let provider = KeystoneCredentialProvider::new("https://keystone.example.com/v3")
            .with_username("testuser")
            .with_password("testpass")
            .with_user_domain_name("Default")
            .with_project_name("myproject")
            .with_project_domain_name("Default");

        let req = provider.build_auth_request();
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["auth"]["scope"]["project"]["name"], "myproject");
        assert_eq!(
            json["auth"]["scope"]["project"]["domain"]["name"],
            "Default"
        );
    }
}
