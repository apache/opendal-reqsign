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

use crate::constants::{
    ORACLE_CONFIG_FILE, ORACLE_CONFIG_PATH, ORACLE_DEFAULT_PROFILE, ORACLE_PROFILE,
};
use crate::Credential;
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential, Result};

/// ConfigFileCredentialProvider loads credentials from Oracle config file (~/.oci/config).
///
/// This provider reads credentials from the Oracle config file, typically located at `~/.oci/config`.
/// The config file path and profile name can be overridden using environment variables:
/// - `OCI_CONFIG_FILE`: Override the config file path
/// - `OCI_PROFILE`: Override the profile name (default is "DEFAULT")
#[derive(Debug, Default, Clone)]
pub struct ConfigFileCredentialProvider {}

impl ConfigFileCredentialProvider {
    /// Create a new ConfigFileCredentialProvider.
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ProvideCredential for ConfigFileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        // Determine config file path from env or use default
        let config_file = envs
            .get(ORACLE_CONFIG_FILE)
            .map(|s| s.as_str())
            .unwrap_or(ORACLE_CONFIG_PATH);

        // Expand home directory if needed
        let expanded_path = ctx
            .expand_home_dir(config_file)
            .ok_or_else(|| reqsign_core::Error::unexpected("Failed to expand home directory"))?;

        // Try to read the file - if it doesn't exist, return None
        let content = match ctx.file_read_as_string(&expanded_path).await {
            Ok(content) => content,
            Err(_) => {
                debug!("Oracle config file not found at {expanded_path:?}");
                return Ok(None);
            }
        };

        // Determine profile from env or use default
        let profile = envs
            .get(ORACLE_PROFILE)
            .map(|s| s.as_str())
            .unwrap_or(ORACLE_DEFAULT_PROFILE);

        // Parse INI content
        let ini = ini::Ini::read_from(&mut content.as_bytes()).map_err(|e| {
            reqsign_core::Error::config_invalid(format!("Failed to parse config file: {e}"))
        })?;
        let section = match ini.section(Some(profile)) {
            Some(section) => section,
            None => {
                debug!("Profile {profile} not found in config file");
                return Ok(None);
            }
        };

        // Extract values
        match (
            section.get("tenancy"),
            section.get("user"),
            section.get("key_file"),
            section.get("fingerprint"),
        ) {
            (Some(tenancy), Some(user), Some(key_file), Some(fingerprint)) => {
                debug!("loading credential from config file");

                // Expand key file path if it starts with ~
                let expanded_key_file = if key_file.starts_with('~') {
                    ctx.expand_home_dir(key_file).ok_or_else(|| {
                        reqsign_core::Error::unexpected("Failed to expand home directory")
                    })?
                } else {
                    key_file.to_string()
                };

                Ok(Some(Credential {
                    tenancy: tenancy.to_string(),
                    user: user.to_string(),
                    key_file: expanded_key_file,
                    fingerprint: fingerprint.to_string(),
                    expires_in: Some(
                        reqsign_core::time::now() + jiff::SignedDuration::from_mins(10),
                    ),
                }))
            }
            _ => {
                debug!("incomplete config in file, skipping");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_config_file_credential_provider_file_not_found() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv)
            .with_env(StaticEnv {
                home_dir: Some("/home/user".into()),
                envs: HashMap::new(),
            });

        let provider = ConfigFileCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_none());

        Ok(())
    }
}
