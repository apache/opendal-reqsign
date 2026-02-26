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
use async_trait::async_trait;
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
/// Use `configure_env` / `configure_config_file` to customize providers, and
/// `disable_env(bool)` / `disable_config_file(bool)` to control participation.
/// Finish with `build()` to construct the provider.
#[derive(Default)]
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    config_file: Option<ConfigFileCredentialProvider>,
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

    /// Configure the config-file credential provider.
    pub fn configure_config_file<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ConfigFileCredentialProvider) -> ConfigFileCredentialProvider,
    {
        let p = self.config_file.take().unwrap_or_default();
        self.config_file = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the config-file provider.
    pub fn disable_config_file(mut self, disable: bool) -> Self {
        if disable {
            self.config_file = None;
        } else if self.config_file.is_none() {
            self.config_file = Some(ConfigFileCredentialProvider::new());
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
        if let Some(p) = self.config_file {
            chain = chain.push(p);
        } else {
            chain = chain.push(ConfigFileCredentialProvider::new());
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
    use crate::constants::{ORACLE_FINGERPRINT, ORACLE_KEY_FILE, ORACLE_TENANCY, ORACLE_USER};
    use reqsign_core::{Context, StaticEnv};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_default_matches_new() {
        let ctx = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([
                (ORACLE_USER.to_string(), "test_user".to_string()),
                (ORACLE_TENANCY.to_string(), "test_tenancy".to_string()),
                (ORACLE_KEY_FILE.to_string(), "/tmp/key.pem".to_string()),
                (ORACLE_FINGERPRINT.to_string(), "test_fingerprint".to_string()),
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
}
