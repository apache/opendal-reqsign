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
use crate::provide_credential::{ConfigFileCredentialProvider, EnvCredentialProvider};
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default loader for Oracle Cloud Infrastructure.
///
/// This loader will try to load credentials in the following order:
/// 1. From environment variables
/// 2. From the default Oracle config file (~/.oci/config)
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
    /// use reqsign_oracle::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("user", "tenancy", "key_file", "fingerprint"));
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
/// Use `env` / `config_file` to customize providers, `no_env` /
/// `no_config_file` to remove them from the chain, and `build()` to construct
/// the provider.
///
/// # Example
///
/// ```no_run
/// use reqsign_oracle::{
///     ConfigFileCredentialProvider, DefaultCredentialProvider, EnvCredentialProvider,
/// };
///
/// let provider = DefaultCredentialProvider::builder()
///     .env(EnvCredentialProvider::new())
///     .no_config_file()
///     .config_file(ConfigFileCredentialProvider::new())
///     .build();
/// ```
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    config_file: Option<ConfigFileCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(EnvCredentialProvider::default()),
            config_file: Some(ConfigFileCredentialProvider::default()),
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

    /// Set the config-file credential provider slot.
    pub fn config_file(mut self, provider: ConfigFileCredentialProvider) -> Self {
        self.config_file = Some(provider);
        self
    }

    /// Remove the config-file credential provider slot.
    pub fn no_config_file(mut self) -> Self {
        self.config_file = None;
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();
        if let Some(p) = self.env {
            chain = chain.push(p);
        }
        if let Some(p) = self.config_file {
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
    use crate::constants::{
        ORACLE_CONFIG_FILE, ORACLE_FINGERPRINT, ORACLE_KEY_FILE, ORACLE_TENANCY, ORACLE_USER,
    };
    use reqsign_core::{Context, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_default_matches_new() {
        let ctx = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([
                (ORACLE_USER.to_string(), "test_user".to_string()),
                (ORACLE_TENANCY.to_string(), "test_tenancy".to_string()),
                (ORACLE_KEY_FILE.to_string(), "/tmp/key.pem".to_string()),
                (
                    ORACLE_FINGERPRINT.to_string(),
                    "test_fingerprint".to_string(),
                ),
            ]),
        });

        let from_default = DefaultCredentialProvider::default()
            .provide_credential(&ctx)
            .await
            .expect("load must succeed")
            .expect("credential must exist");
        let from_new = DefaultCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect("load must succeed")
            .expect("credential must exist");

        assert_eq!(from_default.user, from_new.user);
        assert_eq!(from_default.tenancy, from_new.tenancy);
        assert_eq!(from_default.key_file, from_new.key_file);
        assert_eq!(from_default.fingerprint, from_new.fingerprint);
        assert!(from_default.expires_in.is_some());
        assert!(from_new.expires_in.is_some());
    }

    #[tokio::test]
    async fn test_builder_no_env_removes_env_provider() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: Some("/tmp".into()),
                envs: HashMap::from([
                    (ORACLE_USER.to_string(), "test_user".to_string()),
                    (ORACLE_TENANCY.to_string(), "test_tenancy".to_string()),
                    (ORACLE_KEY_FILE.to_string(), "/tmp/key.pem".to_string()),
                    (
                        ORACLE_FINGERPRINT.to_string(),
                        "test_fingerprint".to_string(),
                    ),
                ]),
            });

        let credential = DefaultCredentialProvider::builder()
            .no_env()
            .build()
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_builder_no_config_file_removes_config_file_provider() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("reqsign-oracle-default-provider-{unique}"));
        let config_dir = root.join(".oci");
        let config_path = config_dir.join("config");

        fs::create_dir_all(&config_dir).expect("create config dir must succeed");
        fs::write(
            &config_path,
            "[DEFAULT]\ntenancy=test_tenancy\nuser=test_user\nkey_file=/tmp/key.pem\nfingerprint=test_fingerprint\n",
        )
        .expect("write config file must succeed");

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: Some(root.clone()),
                envs: HashMap::from([(
                    ORACLE_CONFIG_FILE.to_string(),
                    "~/.oci/config".to_string(),
                )]),
            });

        let from_default = DefaultCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        assert!(from_default.is_some());

        let without_config_file = DefaultCredentialProvider::builder()
            .no_config_file()
            .build()
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");

        assert!(without_config_file.is_none());

        fs::remove_dir_all(&root).expect("cleanup temp dir must succeed");
    }
}
