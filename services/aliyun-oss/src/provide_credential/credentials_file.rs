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
use crate::constants::{ALIBABA_CLOUD_CREDENTIALS_FILE, ALIBABA_CLOUD_PROFILE};
#[cfg(not(target_arch = "wasm32"))]
use ini::Ini;
#[cfg(not(target_arch = "wasm32"))]
use log::debug;
use reqsign_core::{Context, ProvideCredential, Result};
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::{Error, ErrorKind};

/// CredentialsFileCredentialProvider loads credentials from Alibaba Cloud shared credential files.
///
/// This provider reads credentials from `~/.alibabacloud/credentials.ini` first
/// and falls back to `~/.aliyun/credentials.ini`. The file path can be overridden
/// by `ALIBABA_CLOUD_CREDENTIALS_FILE`, and the selected profile can be overridden
/// by `ALIBABA_CLOUD_PROFILE`.
#[derive(Debug, Clone)]
pub struct CredentialsFileCredentialProvider {
    profile: Option<String>,
    credentials_file: Option<String>,
}

impl Default for CredentialsFileCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialsFileCredentialProvider {
    /// Create a new credentials file provider.
    pub fn new() -> Self {
        Self {
            profile: None,
            credentials_file: None,
        }
    }

    /// Set the profile name to use when `ALIBABA_CLOUD_PROFILE` is not set.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the path to the shared credentials file.
    pub fn with_credentials_file(mut self, path: impl Into<String>) -> Self {
        self.credentials_file = Some(path.into());
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_from_path(
        &self,
        ctx: &Context,
        path: &str,
        profile: &str,
    ) -> Result<Option<Credential>> {
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
                debug!("failed to read shared credentials file {expanded_path}: {err:?}");
                if err.kind() != ErrorKind::ConfigInvalid {
                    return Ok(None);
                }
                return Ok(None);
            }
        };

        let conf = Ini::load_from_str(&String::from_utf8_lossy(&content)).map_err(|e| {
            Error::config_invalid("failed to parse Alibaba shared credentials file").with_source(e)
        })?;

        let props = match conf.section(Some(profile)) {
            Some(props) => props,
            None => {
                debug!("profile {profile} not found in shared credentials file");
                return Ok(None);
            }
        };

        if !is_enabled(props.get("enable")) {
            debug!("profile {profile} is disabled in shared credentials file");
            return Ok(None);
        }

        match props.get("type") {
            Some(mode) if !is_supported_credentials_mode(mode) => {
                debug!("shared credentials profile {profile} uses unsupported type {mode}");
                Ok(None)
            }
            _ => parse_static_credential(props),
        }
    }
}

impl ProvideCredential for CredentialsFileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            Ok(None)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let profile = ctx
                .env_var(ALIBABA_CLOUD_PROFILE)
                .or_else(|| self.profile.clone())
                .unwrap_or_else(|| "default".to_string());

            if let Some(path) = self
                .credentials_file
                .clone()
                .or_else(|| ctx.env_var(ALIBABA_CLOUD_CREDENTIALS_FILE))
            {
                return self.load_from_path(ctx, &path, &profile).await;
            }

            for path in [
                "~/.alibabacloud/credentials.ini",
                "~/.aliyun/credentials.ini",
            ] {
                if let Some(cred) = self.load_from_path(ctx, path, &profile).await? {
                    return Ok(Some(cred));
                }
            }

            Ok(None)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn is_enabled(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn is_supported_credentials_mode(mode: &str) -> bool {
    matches!(
        mode.trim().to_ascii_lowercase().as_str(),
        "access_key" | "sts" | "sts_token"
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_static_credential(props: &ini::Properties) -> Result<Option<Credential>> {
    let access_key_id = props.get("access_key_id");
    let access_key_secret = props.get("access_key_secret");

    match (access_key_id, access_key_secret) {
        (Some(ak), Some(sk)) => Ok(Some(Credential {
            access_key_id: ak.to_string(),
            access_key_secret: sk.to_string(),
            security_token: props
                .get("security_token")
                .or_else(|| props.get("sts_token"))
                .map(ToString::to_string),
            expires_in: None,
        })),
        _ => Ok(None),
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
    async fn test_credentials_file_provider_reads_default_profile() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/credentials.ini".to_string(),
                br#"[default]
enable=true
type=access_key
access_key_id=shared_access_key
access_key_secret=shared_secret_key
"#
                .to_vec(),
            )])))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_CREDENTIALS_FILE.to_string(),
                    "/mock/credentials.ini".to_string(),
                )]),
            });

        let cred = CredentialsFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .unwrap();

        assert_eq!(cred.access_key_id, "shared_access_key");
        assert_eq!(cred.access_key_secret, "shared_secret_key");
        assert_eq!(cred.security_token, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_credentials_file_provider_env_profile_overrides_builder_profile()
    -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/credentials.ini".to_string(),
                br#"[default]
enable=true
type=access_key
access_key_id=default_access_key
access_key_secret=default_secret_key

[prod]
enable=true
type=sts_token
access_key_id=prod_access_key
access_key_secret=prod_secret_key
sts_token=prod_token
"#
                .to_vec(),
            )])))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([
                    (
                        ALIBABA_CLOUD_CREDENTIALS_FILE.to_string(),
                        "/mock/credentials.ini".to_string(),
                    ),
                    (ALIBABA_CLOUD_PROFILE.to_string(), "prod".to_string()),
                ]),
            });

        let cred = CredentialsFileCredentialProvider::new()
            .with_profile("default")
            .provide_credential(&ctx)
            .await?
            .unwrap();

        assert_eq!(cred.access_key_id, "prod_access_key");
        assert_eq!(cred.access_key_secret, "prod_secret_key");
        assert_eq!(cred.security_token, Some("prod_token".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_credentials_file_provider_ignores_unsupported_mode() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/credentials.ini".to_string(),
                br#"[default]
enable=true
type=ram_role_arn
access_key_id=shared_access_key
access_key_secret=shared_secret_key
"#
                .to_vec(),
            )])))
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    ALIBABA_CLOUD_CREDENTIALS_FILE.to_string(),
                    "/mock/credentials.ini".to_string(),
                )]),
            });

        let cred = CredentialsFileCredentialProvider::new()
            .provide_credential(&ctx)
            .await?;

        assert!(cred.is_none());

        Ok(())
    }
}
