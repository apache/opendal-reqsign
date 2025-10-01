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

use log::debug;

use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

use crate::constants::{DEFAULT_SCOPE, GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_SCOPE};
use crate::credential::{Credential, CredentialFile};

use super::{
    authorized_user::AuthorizedUserCredentialProvider,
    external_account::ExternalAccountCredentialProvider,
    impersonated_service_account::ImpersonatedServiceAccountCredentialProvider,
    vm_metadata::VmMetadataCredentialProvider,
};

/// Default credential provider for Google Cloud Storage (GCS).
///
/// Resolution order follows ADC (Application Default Credentials):
/// 1. Env var `GOOGLE_APPLICATION_CREDENTIALS`
/// 2. Well-known location (`~/.config/gcloud/application_default_credentials.json`)
/// 3. VM metadata service (GCE / Cloud Functions / App Engine)
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
    /// Create a builder to configure the default ADC chain for GCS.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new DefaultCredentialProvider with the default chain:
    /// env ADC -> well-known ADC -> VM metadata
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }

    /// Set the OAuth2 scope for ADC providers (deprecated).
    ///
    /// This helper configures the scope used by the environment and
    /// well-known ADC providers, as well as the VM metadata provider, by
    /// constructing a new chain with the provided scope. Prefer configuring
    /// scope via specific providers (e.g., `VmMetadataCredentialProvider::with_scope`)
    /// or using the `GOOGLE_SCOPE` environment variable.
    #[deprecated(
        since = "1.0.0",
        note = "Configure scope via specific providers or GOOGLE_SCOPE env var"
    )]
    pub fn with_scope(self, scope: impl Into<String>) -> Self {
        let s = scope.into();
        let chain = ProvideCredentialChain::new()
            .push(EnvAdcCredentialProvider::new().with_scope(s.clone()))
            .push(WellKnownAdcCredentialProvider::new().with_scope(s.clone()))
            .push(VmMetadataCredentialProvider::new().with_scope(s));
        Self { chain }
    }

    #[deprecated(
        since = "1.0.0",
        note = "Use DefaultCredentialProvider::builder().disable_env(skip).build() instead"
    )]
    pub fn skip_env_credentials(self, skip: bool) -> Self {
        DefaultCredentialProvider::builder()
            .disable_env(skip)
            .build()
    }

    #[deprecated(
        since = "1.0.0",
        note = "Use DefaultCredentialProvider::builder().disable_well_known(skip).build() instead"
    )]
    pub fn skip_well_known_location(self, skip: bool) -> Self {
        DefaultCredentialProvider::builder()
            .disable_well_known(skip)
            .build()
    }
}

#[async_trait::async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

#[derive(Default, Clone, Debug)]
struct EnvAdcCredentialProvider {
    disabled: Option<bool>,
    scope: Option<String>,
}

impl EnvAdcCredentialProvider {
    fn new() -> Self {
        Self::default()
    }

    /// Set the OAuth2 scope to request when exchanging ADC credentials.
    fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

#[async_trait::async_trait]
impl ProvideCredential for EnvAdcCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.disabled.unwrap_or(false) {
            return Ok(None);
        }

        let path = match ctx.env_var(GOOGLE_APPLICATION_CREDENTIALS) {
            Some(path) if !path.is_empty() => path,
            _ => return Ok(None),
        };

        debug!("trying to load credential from env GOOGLE_APPLICATION_CREDENTIALS: {path}");

        let content = ctx.file_read(&path).await?;
        parse_credential_bytes(ctx, &content, self.scope.clone()).await
    }
}

#[derive(Default, Clone, Debug)]
struct WellKnownAdcCredentialProvider {
    disabled: Option<bool>,
    scope: Option<String>,
}

impl WellKnownAdcCredentialProvider {
    fn new() -> Self {
        Self::default()
    }

    /// Set the OAuth2 scope to request when exchanging ADC credentials.
    fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

#[async_trait::async_trait]
impl ProvideCredential for WellKnownAdcCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.disabled.unwrap_or(false) {
            return Ok(None);
        }

        let config_dir = if let Some(v) = ctx.env_var("APPDATA") {
            v
        } else if let Some(v) = ctx.env_var("XDG_CONFIG_HOME") {
            v
        } else if let Some(v) = ctx.env_var("HOME") {
            format!("{v}/.config")
        } else {
            return Ok(None);
        };

        let path = format!("{config_dir}/gcloud/application_default_credentials.json");
        debug!("trying to load credential from well-known location: {path}");

        let content = match ctx.file_read(&path).await {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        match parse_credential_bytes(ctx, &content, self.scope.clone()).await {
            Ok(v) => Ok(v),
            Err(_) => Ok(None),
        }
    }
}

async fn parse_credential_bytes(
    ctx: &Context,
    content: &[u8],
    scope_override: Option<String>,
) -> Result<Option<Credential>> {
    let cred_file = CredentialFile::from_slice(content)?;

    let scope = scope_override
        .or_else(|| ctx.env_var(GOOGLE_SCOPE))
        .unwrap_or_else(|| DEFAULT_SCOPE.to_string());

    match cred_file {
        CredentialFile::ServiceAccount(sa) => {
            debug!("loaded service account credential");
            Ok(Some(Credential::with_service_account(sa)))
        }
        CredentialFile::ExternalAccount(ea) => {
            debug!("loaded external account credential, exchanging for token");
            let provider = ExternalAccountCredentialProvider::new(ea).with_scope(&scope);
            provider.provide_credential(ctx).await
        }
        CredentialFile::ImpersonatedServiceAccount(isa) => {
            debug!("loaded impersonated service account credential, exchanging for token");
            let provider =
                ImpersonatedServiceAccountCredentialProvider::new(isa).with_scope(&scope);
            provider.provide_credential(ctx).await
        }
        CredentialFile::AuthorizedUser(au) => {
            debug!("loaded authorized user credential, exchanging for token");
            let provider = AuthorizedUserCredentialProvider::new(au);
            provider.provide_credential(ctx).await
        }
    }
}

/// Builder for `DefaultCredentialProvider`.
///
/// Use `configure_vm_metadata` to customize VM metadata behavior and
/// `disable_env` / `disable_well_known` / `disable_vm_metadata` to control
/// participation. Call `build()` to construct the provider.
#[derive(Default)]
pub struct DefaultCredentialProviderBuilder {
    env_adc: Option<EnvAdcCredentialProvider>,
    well_known_adc: Option<WellKnownAdcCredentialProvider>,
    vm_metadata: Option<VmMetadataCredentialProvider>,
}

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    // No global scope configurator; configure scope on specific providers if needed.

    /// Configure the VM metadata provider.
    ///
    /// This allows setting a custom endpoint or other options for retrieving
    /// tokens when running on Google Compute Engine or compatible environments.
    pub fn configure_vm_metadata<F>(mut self, f: F) -> Self
    where
        F: FnOnce(VmMetadataCredentialProvider) -> VmMetadataCredentialProvider,
    {
        let p = self.vm_metadata.take().unwrap_or_default();
        self.vm_metadata = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the env-based ADC provider.
    pub fn disable_env(mut self, disable: bool) -> Self {
        if disable {
            self.env_adc = None;
        } else if self.env_adc.is_none() {
            self.env_adc = Some(EnvAdcCredentialProvider::new());
        }
        self
    }

    /// Disable (true) or ensure enabled (false) the well-known ADC provider.
    pub fn disable_well_known(mut self, disable: bool) -> Self {
        if disable {
            self.well_known_adc = None;
        } else if self.well_known_adc.is_none() {
            self.well_known_adc = Some(WellKnownAdcCredentialProvider::new());
        }
        self
    }

    /// Disable (true) or ensure enabled (false) the VM metadata provider.
    pub fn disable_vm_metadata(mut self, disable: bool) -> Self {
        if disable {
            self.vm_metadata = None;
        } else if self.vm_metadata.is_none() {
            self.vm_metadata = Some(VmMetadataCredentialProvider::new());
        }
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();

        if let Some(p) = self.env_adc {
            chain = chain.push(p);
        } else {
            chain = chain.push(EnvAdcCredentialProvider::new());
        }

        if let Some(p) = self.well_known_adc {
            chain = chain.push(p);
        } else {
            chain = chain.push(WellKnownAdcCredentialProvider::new());
        }

        if let Some(p) = self.vm_metadata {
            chain = chain.push(p);
        } else {
            chain = chain.push(VmMetadataCredentialProvider::new());
        }

        DefaultCredentialProvider::with_chain(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{Context, StaticEnv};
    use std::collections::HashMap;
    use std::env;

    #[tokio::test]
    async fn test_default_provider_env() {
        let envs = HashMap::from([(
            GOOGLE_APPLICATION_CREDENTIALS.to_string(),
            format!(
                "{}/testdata/test_credential.json",
                env::current_dir()
                    .expect("current_dir must exist")
                    .to_string_lossy()
            ),
        )]);

        let ctx = Context::new()
            .with_file_read(reqsign_file_read_tokio::TokioFileRead)
            .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs,
            });

        let provider = DefaultCredentialProvider::new();
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        assert!(cred.is_some());

        let cred = cred.unwrap();
        assert!(cred.has_service_account());
        let sa = cred.service_account.as_ref().unwrap();
        assert_eq!("test-234@test.iam.gserviceaccount.com", &sa.client_email);
    }

    #[tokio::test]
    async fn test_default_provider_with_scope() {
        let provider = DefaultCredentialProvider::builder().build();

        // Even without valid credentials, this should not panic
        let ctx = Context::new()
            .with_file_read(reqsign_file_read_tokio::TokioFileRead)
            .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default());
        let _ = provider.provide_credential(&ctx).await;
    }
}
