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
use crate::provide_credential::{AssumeRoleWithOidcCredentialProvider, EnvCredentialProvider};
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// DefaultCredentialProvider is a loader that will try to load credential via default chains.
///
/// Resolution order:
///
/// 1. Environment variables
/// 2. Assume Role with OIDC
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

    /// Create a new `DefaultCredentialProvider` instance using the default chain.
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
    /// use reqsign_aliyun_oss::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("access_key_id", "access_key_secret"));
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
/// Use `slot(provider)` to override a default provider or `no_slot()` to
/// remove it from the chain before calling `build()`.
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    oidc: Option<AssumeRoleWithOidcCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(EnvCredentialProvider::new()),
            oidc: Some(AssumeRoleWithOidcCredentialProvider::new()),
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

    /// Set the OIDC credential provider slot.
    pub fn oidc(mut self, provider: AssumeRoleWithOidcCredentialProvider) -> Self {
        self.oidc = Some(provider);
        self
    }

    /// Remove the OIDC credential provider slot.
    pub fn no_oidc(mut self) -> Self {
        self.oidc = None;
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();
        if let Some(p) = self.env {
            chain = chain.push(p);
        }
        if let Some(p) = self.oidc {
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
    use bytes::Bytes;
    use reqsign_core::{FileRead, HttpSend, OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_default_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

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
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    ALIBABA_CLOUD_ACCESS_KEY_ID.to_string(),
                    "access_key_id".to_string(),
                ),
                (
                    ALIBABA_CLOUD_ACCESS_KEY_SECRET.to_string(),
                    "secret_access_key".to_string(),
                ),
            ]),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("access_key_id", credential.access_key_id);
        assert_eq!("secret_access_key", credential.access_key_secret);
    }

    #[tokio::test]
    async fn test_default_loader_with_security_token() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    ALIBABA_CLOUD_ACCESS_KEY_ID.to_string(),
                    "access_key_id".to_string(),
                ),
                (
                    ALIBABA_CLOUD_ACCESS_KEY_SECRET.to_string(),
                    "secret_access_key".to_string(),
                ),
                (
                    ALIBABA_CLOUD_SECURITY_TOKEN.to_string(),
                    "security_token".to_string(),
                ),
            ]),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("access_key_id", credential.access_key_id);
        assert_eq!("secret_access_key", credential.access_key_secret);
        assert_eq!("security_token", credential.security_token.unwrap());
    }

    #[tokio::test]
    async fn test_builder_no_env_removes_env_provider() {
        let ctx = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    ALIBABA_CLOUD_ACCESS_KEY_ID.to_string(),
                    "access_key_id".to_string(),
                ),
                (
                    ALIBABA_CLOUD_ACCESS_KEY_SECRET.to_string(),
                    "secret_access_key".to_string(),
                ),
            ]),
        });

        let credential = DefaultCredentialProvider::builder()
            .no_oidc()
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap();
        assert!(credential.is_some());

        let credential = DefaultCredentialProvider::builder()
            .no_env()
            .no_oidc()
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap();
        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_builder_no_oidc_removes_oidc_provider() {
        #[derive(Debug)]
        struct TestFileRead;

        impl FileRead for TestFileRead {
            async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
                assert_eq!(path, "/mock/token");
                Ok(b"token".to_vec())
            }
        }

        #[derive(Debug)]
        struct TestHttpSend;

        impl HttpSend for TestHttpSend {
            async fn http_send(&self, _req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
                http::Response::builder()
                    .status(http::StatusCode::OK)
                    .body(Bytes::from_static(br#"{"Credentials":{"SecurityToken":"security_token","Expiration":"2124-05-25T11:45:17Z","AccessKeySecret":"secret_access_key","AccessKeyId":"access_key_id"}}"#))
                    .map_err(Into::into)
            }
        }

        let ctx = Context::new()
            .with_file_read(TestFileRead)
            .with_http_send(TestHttpSend)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from_iter([
                    (
                        ALIBABA_CLOUD_OIDC_TOKEN_FILE.to_string(),
                        "/mock/token".to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_ROLE_ARN.to_string(),
                        "acs:ram::123456789012:role/test-role".to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_OIDC_PROVIDER_ARN.to_string(),
                        "acs:ram::123456789012:oidc-provider/test-provider".to_string(),
                    ),
                ]),
            });

        let credential = DefaultCredentialProvider::builder()
            .no_env()
            .oidc(AssumeRoleWithOidcCredentialProvider::new())
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap();
        assert!(credential.is_some());

        let credential = DefaultCredentialProvider::builder()
            .no_env()
            .no_oidc()
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap();
        assert!(credential.is_none());
    }
}
