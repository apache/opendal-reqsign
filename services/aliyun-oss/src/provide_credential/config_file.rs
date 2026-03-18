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
#[cfg(not(target_arch = "wasm32"))]
use crate::constants::{ALIBABA_CLOUD_CONFIG_FILE, ALIBABA_CLOUD_PROFILE};
#[cfg(not(target_arch = "wasm32"))]
use log::debug;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::Error;
use reqsign_core::{Context, ProvideCredential, Result};
#[cfg(not(target_arch = "wasm32"))]
use serde::Deserialize;

/// ConfigFileCredentialProvider loads credentials from Alibaba Cloud CLI config files.
///
/// This provider reads credentials from `~/.aliyun/config.json` by default. The
/// file path can be overridden by `ALIBABA_CLOUD_CONFIG_FILE`, and the selected
/// profile can be overridden by `ALIBABA_CLOUD_PROFILE`.
#[derive(Debug, Clone)]
pub struct ConfigFileCredentialProvider {
    profile: Option<String>,
    config_file: Option<String>,
}

impl Default for ConfigFileCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigFileCredentialProvider {
    /// Create a new config file provider.
    pub fn new() -> Self {
        Self {
            profile: None,
            config_file: None,
        }
    }

    /// Set the profile name to use when `ALIBABA_CLOUD_PROFILE` is not set.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the path to the config file.
    pub fn with_config_file(mut self, path: impl Into<String>) -> Self {
        self.config_file = Some(path.into());
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_config(&self, ctx: &Context, path: &str) -> Result<Option<ConfigFile>> {
        let expanded_path = if path.starts_with("~/") {
            match ctx.expand_home_dir(path) {
                Some(expanded) => expanded,
                None => {
                    debug!("failed to expand homedir for path: {path}");
                    return Ok(None);
                }
            }
        } else {
            path.to_string()
        };

        let content = match ctx.file_read(&expanded_path).await {
            Ok(content) => content,
            Err(err) => {
                debug!("failed to read Alibaba config file {expanded_path}: {err:?}");
                return Ok(None);
            }
        };

        let config: ConfigFile = serde_json::from_slice(&content).map_err(|e| {
            Error::config_invalid("failed to parse Alibaba config file").with_source(e)
        })?;

        Ok(Some(config))
    }
}

impl ProvideCredential for ConfigFileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            Ok(None)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = self
                .config_file
                .clone()
                .or_else(|| ctx.env_var(ALIBABA_CLOUD_CONFIG_FILE))
                .unwrap_or_else(|| "~/.aliyun/config.json".to_string());

            let Some(config) = self.load_config(ctx, &path).await? else {
                return Ok(None);
            };

            let profile = ctx
                .env_var(ALIBABA_CLOUD_PROFILE)
                .or_else(|| self.profile.clone())
                .or(config.current.clone())
                .unwrap_or_else(|| "default".to_string());

            let profile = match config.profiles.iter().find(|entry| entry.name == profile) {
                Some(profile) => profile,
                None => {
                    debug!("profile not found in Alibaba config file");
                    return Ok(None);
                }
            };

            if !profile.supports_static_credential() {
                debug!(
                    "Alibaba config profile {} uses unsupported mode {:?}",
                    profile.name, profile.mode
                );
                return Ok(None);
            }

            match (&profile.access_key_id, &profile.access_key_secret) {
                (Some(ak), Some(sk)) => Ok(Some(Credential {
                    access_key_id: ak.clone(),
                    access_key_secret: sk.clone(),
                    security_token: profile
                        .security_token
                        .clone()
                        .or_else(|| profile.sts_token.clone()),
                    expires_in: None,
                })),
                _ => Ok(None),
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct ConfigFile {
    current: Option<String>,
    #[serde(default)]
    profiles: Vec<ConfigProfile>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct ConfigProfile {
    name: String,
    mode: Option<String>,
    access_key_id: Option<String>,
    access_key_secret: Option<String>,
    security_token: Option<String>,
    sts_token: Option<String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ConfigProfile {
    fn supports_static_credential(&self) -> bool {
        match self.mode.as_deref() {
            None => true,
            Some(mode) => matches!(
                mode.trim().to_ascii_lowercase().as_str(),
                "ak" | "ststoken" | "sts_token" | "sts"
            ),
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use reqsign_core::{FileRead, StaticEnv};
    use std::collections::HashMap;

    #[derive(Debug)]
    struct TestFileRead {
        files: HashMap<String, Vec<u8>>,
    }

    impl TestFileRead {
        fn new(files: HashMap<String, Vec<u8>>) -> Self {
            Self { files }
        }
    }

    impl FileRead for TestFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            self.files.get(path).cloned().ok_or_else(|| {
                reqsign_core::Error::config_invalid(format!("unexpected file path: {path}"))
            })
        }
    }

    #[tokio::test]
    async fn test_config_file_provider_uses_current_profile() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/config.json".to_string(),
                br#"{
  "current": "prod",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "default_access_key",
      "access_key_secret": "default_secret_key"
    },
    {
      "name": "prod",
      "mode": "StsToken",
      "access_key_id": "prod_access_key",
      "access_key_secret": "prod_secret_key",
      "sts_token": "prod_token"
    }
  ]
}"#
                .to_vec(),
            )])))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_CONFIG_FILE.to_string(),
                    "/mock/config.json".to_string(),
                )]),
            });

        let cred = ConfigFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .unwrap();

        assert_eq!(cred.access_key_id, "prod_access_key");
        assert_eq!(cred.access_key_secret, "prod_secret_key");
        assert_eq!(cred.security_token, Some("prod_token".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_config_file_provider_env_profile_overrides_current() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/config.json".to_string(),
                br#"{
  "current": "prod",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "default_access_key",
      "access_key_secret": "default_secret_key"
    },
    {
      "name": "prod",
      "mode": "AK",
      "access_key_id": "prod_access_key",
      "access_key_secret": "prod_secret_key"
    }
  ]
}"#
                .to_vec(),
            )])))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([
                    (
                        ALIBABA_CLOUD_CONFIG_FILE.to_string(),
                        "/mock/config.json".to_string(),
                    ),
                    (ALIBABA_CLOUD_PROFILE.to_string(), "default".to_string()),
                ]),
            });

        let cred = ConfigFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .unwrap();

        assert_eq!(cred.access_key_id, "default_access_key");
        assert_eq!(cred.access_key_secret, "default_secret_key");

        Ok(())
    }

    #[tokio::test]
    async fn test_config_file_provider_ignores_unsupported_mode() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/config.json".to_string(),
                br#"{
  "profiles": [
    {
      "name": "default",
      "mode": "RamRoleArn",
      "access_key_id": "shared_access_key",
      "access_key_secret": "shared_secret_key"
    }
  ]
}"#
                .to_vec(),
            )])))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_CONFIG_FILE.to_string(),
                    "/mock/config.json".to_string(),
                )]),
            });

        let cred = ConfigFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await?;

        assert!(cred.is_none());

        Ok(())
    }
}
