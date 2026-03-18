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
use crate::provide_credential::{
    AssumeRoleWithWebIdentityCredentialProvider, EnvCredentialProvider,
};
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default loader for Tencent COS.
///
/// This loader will try to load credentials in the following order:
/// 1. From environment variables
/// 2. From AssumeRoleWithWebIdentity
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder to configure the default credential chain.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new DefaultCredentialProvider using the default chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// This allows adding a high-priority credential source that will be tried
    /// before all other providers in the default chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_tencent_cos::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("secret_id", "secret_key"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }
}

/// Builder for `DefaultCredentialProvider`.
///
/// Use `slot(provider)` to override a default slot or `no_slot()` to remove it
/// from the chain before calling `build()`.
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    web_identity: Option<AssumeRoleWithWebIdentityCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(EnvCredentialProvider::default()),
            web_identity: Some(AssumeRoleWithWebIdentityCredentialProvider::default()),
        }
    }
}

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the environment credential provider slot.
    pub fn env(mut self, provider: EnvCredentialProvider) -> Self {
        self.env = Some(provider);
        self
    }

    /// Remove the environment credential provider slot.
    pub fn no_env(mut self) -> Self {
        self.env = None;
        self
    }

    /// Set the web identity credential provider slot.
    pub fn web_identity(mut self, provider: AssumeRoleWithWebIdentityCredentialProvider) -> Self {
        self.web_identity = Some(provider);
        self
    }

    /// Remove the web identity credential provider slot.
    pub fn no_web_identity(mut self) -> Self {
        self.web_identity = None;
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();
        if let Some(p) = self.env {
            chain = chain.push(p);
        }
        if let Some(p) = self.web_identity {
            chain = chain.push(p);
        }

        DefaultCredentialProvider::with_chain(chain)
    }
}
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use reqsign_core::{OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_default_loader_without_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_default_loader_with_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (TENCENTCLOUD_SECRET_ID.to_string(), "secret_id".to_string()),
                (
                    TENCENTCLOUD_SECRET_KEY.to_string(),
                    "secret_key".to_string(),
                ),
            ]),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("secret_id", credential.secret_id);
        assert_eq!("secret_key", credential.secret_key);
    }

    #[tokio::test]
    async fn test_default_loader_with_security_token() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (TKE_SECRET_ID.to_string(), "secret_id".to_string()),
                (TKE_SECRET_KEY.to_string(), "secret_key".to_string()),
                (TENCENTCLOUD_TOKEN.to_string(), "security_token".to_string()),
            ]),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("secret_id", credential.secret_id);
        assert_eq!("secret_key", credential.secret_key);
        assert_eq!("security_token", credential.security_token.unwrap());
    }

    #[tokio::test]
    async fn test_builder_no_env_removes_env_provider() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (TENCENTCLOUD_SECRET_ID.to_string(), "secret_id".to_string()),
                (
                    TENCENTCLOUD_SECRET_KEY.to_string(),
                    "secret_key".to_string(),
                ),
            ]),
        });

        let loader = DefaultCredentialProvider::builder().no_env().build();
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_builder_no_web_identity_removes_web_identity_provider() {
        let ctx = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (TENCENTCLOUD_REGION.to_string(), "ap-guangzhou".to_string()),
                (
                    TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE.to_string(),
                    "/tmp/token".to_string(),
                ),
                (
                    TENCENTCLOUD_ROLE_ARN.to_string(),
                    "qcs::cam::uin/123456789:roleName/test".to_string(),
                ),
                (TENCENTCLOUD_PROVIDER_ID.to_string(), "provider".to_string()),
            ]),
        });

        let loader = DefaultCredentialProvider::builder()
            .no_env()
            .no_web_identity()
            .build();
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }
}
