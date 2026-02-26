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

use async_trait::async_trait;
use reqsign_core::Context;
use reqsign_core::ProvideCredential;
use reqsign_core::Result;

use super::super::credential::Credential;

/// StaticCredentialProvider provides static Volcengine credentials.
///
/// This provider is used when you have the access key ID and secret access key
/// directly and want to use them without any dynamic loading.
#[derive(Debug, Clone)]
pub struct StaticCredentialProvider {
    access_key_id: String,
    access_key_secret: String,
    security_token: Option<String>,
}

impl StaticCredentialProvider {
    /// Create a new StaticCredentialProvider with access key ID and secret access key.
    pub fn new(access_key_id: &str, access_key_secret: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            security_token: None,
        }
    }

    /// Set the security token.
    pub fn with_security_token(mut self, token: &str) -> Self {
        self.security_token = Some(token.to_string());
        self
    }
}

#[async_trait]
impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        let mut cred = Credential::new(&self.access_key_id, &self.access_key_secret);
        if let Some(token) = &self.security_token {
            cred = cred.with_session_token(token);
        }
        Ok(Some(cred))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_credential_provider() -> anyhow::Result<()> {
        let ctx = Context::new();

        let provider = StaticCredentialProvider::new("test_access_key", "test_secret_key");
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "test_access_key");
        assert_eq!(cred.secret_access_key, "test_secret_key");
        assert!(cred.session_token.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_static_credential_provider_with_security_token() -> anyhow::Result<()> {
        let ctx = Context::new();

        let provider = StaticCredentialProvider::new("test_access_key", "test_secret_key")
            .with_security_token("test_security_token");
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "test_access_key");
        assert_eq!(cred.secret_access_key, "test_secret_key");
        assert_eq!(cred.session_token, Some("test_security_token".to_string()));

        Ok(())
    }
}
