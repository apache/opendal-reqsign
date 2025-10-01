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

use crate::provide_credential::{
    AssumeRoleWithWebIdentityCredentialProvider, ECSCredentialProvider, EnvCredentialProvider,
    IMDSv2CredentialProvider, ProfileCredentialProvider,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::provide_credential::{ProcessCredentialProvider, SSOCredentialProvider};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// DefaultCredentialProvider is a loader that will try to load credential via default chains.
///
/// Resolution order:
///
/// 1. Environment variables
/// 2. Shared config (`~/.aws/config`, `~/.aws/credentials`)
/// 3. SSO credentials
/// 4. Web Identity Tokens
/// 5. Process credentials
/// 6. ECS (IAM Roles for Tasks) & Container credentials
/// 7. EC2 IMDSv2
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
    /// use reqsign_aws_v4::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("access_key_id", "secret_access_key"));
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
/// Use `configure_*` to customize provider behavior and `disable_*(bool)` to
/// include or exclude providers from the default chain. Call `build()` to
/// construct the provider.
#[derive(Default)]
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    profile: Option<ProfileCredentialProvider>,
    #[cfg(not(target_arch = "wasm32"))]
    sso: Option<SSOCredentialProvider>,
    assume_role: Option<AssumeRoleWithWebIdentityCredentialProvider>,
    #[cfg(not(target_arch = "wasm32"))]
    process: Option<ProcessCredentialProvider>,
    ecs: Option<ECSCredentialProvider>,
    imds: Option<IMDSv2CredentialProvider>,
}

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the environment credential provider.
    pub fn configure_env<F>(mut self, f: F) -> Self
    where
        F: FnOnce(EnvCredentialProvider) -> EnvCredentialProvider,
    {
        let p = self.env.take().unwrap_or_default();
        self.env = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the environment provider.
    pub fn disable_env(mut self, disable: bool) -> Self {
        if disable {
            self.env = None;
        } else if self.env.is_none() {
            self.env = Some(EnvCredentialProvider::new());
        }
        self
    }

    /// Configure the profile credential provider.
    pub fn configure_profile<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ProfileCredentialProvider) -> ProfileCredentialProvider,
    {
        let p = self.profile.take().unwrap_or_default();
        self.profile = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the profile provider.
    pub fn disable_profile(mut self, disable: bool) -> Self {
        if disable {
            self.profile = None;
        } else if self.profile.is_none() {
            self.profile = Some(ProfileCredentialProvider::new());
        }
        self
    }

    /// Configure the SSO credential provider.
    ///
    /// This customizes how AWS SSO (IAM Identity Center) credentials are
    /// discovered and exchanged from local SSO caches. Typical use cases
    /// include setting an alternative endpoint for testing, or overriding the
    /// profile-derived values. This method is only available for non-wasm32
    /// targets where process and filesystem access is supported.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn configure_sso<F>(mut self, f: F) -> Self
    where
        F: FnOnce(SSOCredentialProvider) -> SSOCredentialProvider,
    {
        let p = self.sso.take().unwrap_or_default();
        self.sso = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the SSO provider.
    ///
    /// Use this to explicitly remove SSO from the default credential
    /// resolution chain (disable = true) or ensure it participates (disable = false).
    /// This is useful in controlled environments (e.g., CI) or when SSO is
    /// not configured. Only available on non-wasm32 targets.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn disable_sso(mut self, disable: bool) -> Self {
        if disable {
            self.sso = None;
        } else if self.sso.is_none() {
            self.sso = Some(SSOCredentialProvider::new());
        }
        self
    }

    /// Configure the web-identity assume-role credential provider.
    pub fn configure_assume_role<F>(mut self, f: F) -> Self
    where
        F: FnOnce(
            AssumeRoleWithWebIdentityCredentialProvider,
        ) -> AssumeRoleWithWebIdentityCredentialProvider,
    {
        let p = self.assume_role.take().unwrap_or_default();
        self.assume_role = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the assume role provider.
    pub fn disable_assume_role(mut self, disable: bool) -> Self {
        if disable {
            self.assume_role = None;
        } else if self.assume_role.is_none() {
            self.assume_role = Some(AssumeRoleWithWebIdentityCredentialProvider::new());
        }
        self
    }

    /// Configure the external process credential provider.
    ///
    /// This allows overriding the profile-derived command used to obtain
    /// credentials via `credential_process`. Only available on non-wasm32
    /// targets.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn configure_process<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ProcessCredentialProvider) -> ProcessCredentialProvider,
    {
        let p = self.process.take().unwrap_or_default();
        self.process = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the process provider.
    ///
    /// Use this to explicitly remove the external process credential source
    /// (disable = true) or ensure it participates (disable = false). This is
    /// only meaningful on non-wasm32 targets.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn disable_process(mut self, disable: bool) -> Self {
        if disable {
            self.process = None;
        } else if self.process.is_none() {
            self.process = Some(ProcessCredentialProvider::new());
        }
        self
    }

    /// Configure the ECS (container/task) credential provider.
    pub fn configure_ecs<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ECSCredentialProvider) -> ECSCredentialProvider,
    {
        let p = self.ecs.take().unwrap_or_default();
        self.ecs = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the ECS provider.
    pub fn disable_ecs(mut self, disable: bool) -> Self {
        if disable {
            self.ecs = None;
        } else if self.ecs.is_none() {
            self.ecs = Some(ECSCredentialProvider::new());
        }
        self
    }

    /// Configure the EC2 IMDSv2 credential provider.
    pub fn configure_imds<F>(mut self, f: F) -> Self
    where
        F: FnOnce(IMDSv2CredentialProvider) -> IMDSv2CredentialProvider,
    {
        let p = self.imds.take().unwrap_or_default();
        self.imds = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the IMDSv2 provider.
    pub fn disable_imds(mut self, disable: bool) -> Self {
        if disable {
            self.imds = None;
        } else if self.imds.is_none() {
            self.imds = Some(IMDSv2CredentialProvider::new());
        }
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();

        if let Some(p) = self.env {
            chain = chain.push(p);
        } else {
            chain = chain.push(EnvCredentialProvider::new());
        }

        if let Some(p) = self.profile {
            chain = chain.push(p);
        } else {
            chain = chain.push(ProfileCredentialProvider::new());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(p) = self.sso {
                chain = chain.push(p);
            } else {
                chain = chain.push(SSOCredentialProvider::new());
            }
        }

        if let Some(p) = self.assume_role {
            chain = chain.push(p);
        } else {
            chain = chain.push(AssumeRoleWithWebIdentityCredentialProvider::new());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(p) = self.process {
                chain = chain.push(p);
            } else {
                chain = chain.push(ProcessCredentialProvider::new());
            }
        }

        if let Some(p) = self.ecs {
            chain = chain.push(p);
        } else {
            chain = chain.push(ECSCredentialProvider::new());
        }

        if let Some(p) = self.imds {
            chain = chain.push(p);
        } else {
            chain = chain.push(IMDSv2CredentialProvider::new());
        }

        DefaultCredentialProvider::with_chain(chain)
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        AWS_ACCESS_KEY_ID, AWS_CONFIG_FILE, AWS_SECRET_ACCESS_KEY, AWS_SHARED_CREDENTIALS_FILE,
    };
    use reqsign_core::{OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::env;

    #[tokio::test]
    async fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.expect("load must succeed");
        assert!(x.is_none());
    }

    #[tokio::test]
    async fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (AWS_ACCESS_KEY_ID.to_string(), "access_key_id".to_string()),
                (
                    AWS_SECRET_ACCESS_KEY.to_string(),
                    "secret_access_key".to_string(),
                ),
            ]),
        });

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.expect("load must succeed");

        let x = x.expect("must load succeed");
        assert_eq!("access_key_id", x.access_key_id);
        assert_eq!("secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONFIG_FILE.to_string(),
                    format!(
                        "{}/testdata/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE.to_string(),
                    format!(
                        "{}/testdata/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
            ]),
        });

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.unwrap().unwrap();
        assert_eq!("config_access_key_id", x.access_key_id);
        assert_eq!("config_secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONFIG_FILE.to_string(),
                    format!(
                        "{}/testdata/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE.to_string(),
                    format!(
                        "{}/testdata/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
            ]),
        });

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.unwrap().unwrap();
        assert_eq!("shared_access_key_id", x.access_key_id);
        assert_eq!("shared_secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_default_credential_provider_prepend() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                // Set environment variables that would normally be loaded
                (AWS_ACCESS_KEY_ID.to_string(), "env_access_key".to_string()),
                (
                    AWS_SECRET_ACCESS_KEY.to_string(),
                    "env_secret_key".to_string(),
                ),
            ]),
        });

        // Create a static provider with different credentials
        let static_provider =
            crate::StaticCredentialProvider::new("static_access_key", "static_secret_key");

        // Create default provider and push_front the static provider
        let provider = DefaultCredentialProvider::new().push_front(static_provider);

        // The static provider should take precedence over environment variables
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed")
            .expect("credential must exist");

        assert_eq!("static_access_key", cred.access_key_id);
        assert_eq!("static_secret_key", cred.secret_access_key);
    }

    #[tokio::test]
    async fn test_default_credential_provider_configure_imds() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        // Build a custom chain with IMDS disabled
        let mut chain = ProvideCredentialChain::new()
            .push(EnvCredentialProvider::new())
            .push(ProfileCredentialProvider::new());

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain.push(SSOCredentialProvider::new());
        }

        chain = chain.push(AssumeRoleWithWebIdentityCredentialProvider::new());

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain.push(ProcessCredentialProvider::new());
        }

        chain = chain.push(ECSCredentialProvider::new());

        let provider = DefaultCredentialProvider::with_chain(chain);

        // Even though IMDS is the last provider, it should return None when disabled
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        assert!(cred.is_none());
    }

    #[tokio::test]
    async fn test_default_credential_provider_configure_profile() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        // Build a custom chain with Profile provider using a custom config file
        let custom_config = format!(
            "{}/testdata/default_config",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );

        let mut chain = ProvideCredentialChain::new().push(EnvCredentialProvider::new());

        chain = chain.push(ProfileCredentialProvider::new().with_config_file(custom_config));

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain.push(SSOCredentialProvider::new());
        }

        chain = chain.push(AssumeRoleWithWebIdentityCredentialProvider::new());

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain.push(ProcessCredentialProvider::new());
        }

        chain = chain
            .push(ECSCredentialProvider::new())
            .push(IMDSv2CredentialProvider::new());

        let provider = DefaultCredentialProvider::with_chain(chain);

        // Should load from the custom config
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        // The testdata/default_config has credentials
        let cred = cred.expect("credential should exist");
        assert_eq!("config_access_key_id", cred.access_key_id);
        assert_eq!("config_secret_access_key", cred.secret_access_key);
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[tokio::test]
    async fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONFIG_FILE.to_string(),
                    format!(
                        "{}/testdata/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE.to_string(),
                    format!(
                        "{}/testdata/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
            ]),
        });

        let l = DefaultCredentialProvider::new();
        let x = l
            .provide_credential(&ctx)
            .await
            .expect("load must success")
            .unwrap();
        assert_eq!("shared_access_key_id", x.access_key_id);
        assert_eq!("shared_secret_access_key", x.secret_access_key);
    }
}
