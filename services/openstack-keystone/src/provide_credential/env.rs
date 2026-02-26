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

use reqsign_core::{Context, ProvideCredential, Result};

use crate::credential::Credential;

use super::keystone::KeystoneCredentialProvider;

/// Environment variable names for OpenStack credentials.
const OPENSTACK_AUTH_URL: &str = "OPENSTACK_AUTH_URL";
const OPENSTACK_USERNAME: &str = "OPENSTACK_USERNAME";
const OPENSTACK_PASSWORD: &str = "OPENSTACK_PASSWORD";
const OPENSTACK_DOMAIN_NAME: &str = "OPENSTACK_DOMAIN_NAME";
const OPENSTACK_PROJECT_NAME: &str = "OPENSTACK_PROJECT_NAME";
const OPENSTACK_PROJECT_DOMAIN_NAME: &str = "OPENSTACK_PROJECT_DOMAIN_NAME";

/// Credential provider that reads OpenStack credentials from environment variables
/// and authenticates via Keystone v3.
///
/// Required environment variables:
/// - `OPENSTACK_AUTH_URL` — Keystone v3 identity URL (e.g. `https://keystone.example.com/v3`)
/// - `OPENSTACK_USERNAME` — OpenStack username
/// - `OPENSTACK_PASSWORD` — OpenStack password
///
/// Optional environment variables:
/// - `OPENSTACK_DOMAIN_NAME` — User domain name (defaults to "Default")
/// - `OPENSTACK_PROJECT_NAME` — Project name for scoped tokens
/// - `OPENSTACK_PROJECT_DOMAIN_NAME` — Project domain name (defaults to user domain)
#[derive(Debug, Default)]
pub struct EnvCredentialProvider;

impl EnvCredentialProvider {
    /// Create a new EnvCredentialProvider.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let auth_url = match ctx.env_var(OPENSTACK_AUTH_URL) {
            Some(v) if !v.is_empty() => v,
            _ => {
                debug!("{OPENSTACK_AUTH_URL} not set, skipping env credential provider");
                return Ok(None);
            }
        };

        let username = match ctx.env_var(OPENSTACK_USERNAME) {
            Some(v) if !v.is_empty() => v,
            _ => {
                debug!("{OPENSTACK_USERNAME} not set, skipping env credential provider");
                return Ok(None);
            }
        };

        let password = match ctx.env_var(OPENSTACK_PASSWORD) {
            Some(v) if !v.is_empty() => v,
            _ => {
                debug!("{OPENSTACK_PASSWORD} not set, skipping env credential provider");
                return Ok(None);
            }
        };

        let domain_name = ctx
            .env_var(OPENSTACK_DOMAIN_NAME)
            .unwrap_or_else(|| "Default".to_string());

        let project_domain_name = ctx
            .env_var(OPENSTACK_PROJECT_DOMAIN_NAME)
            .unwrap_or_else(|| domain_name.clone());

        debug!("loaded OpenStack credentials from environment for user: {username}");

        let mut provider = KeystoneCredentialProvider::new(&auth_url)
            .with_username(&username)
            .with_password(&password)
            .with_user_domain_name(&domain_name);

        if let Some(project_name) = ctx.env_var(OPENSTACK_PROJECT_NAME) {
            if !project_name.is_empty() {
                provider = provider
                    .with_project_name(&project_name)
                    .with_project_domain_name(&project_domain_name);
            }
        }

        provider.provide_credential(ctx).await
    }
}
