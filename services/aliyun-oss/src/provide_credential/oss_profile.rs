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
use crate::constants::{OSS_CREDENTIAL_PROFILES_FILE, OSS_PROFILE};
#[cfg(not(target_arch = "wasm32"))]
use ini::Ini;
#[cfg(not(target_arch = "wasm32"))]
use log::debug;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::Error;
use reqsign_core::{Context, ProvideCredential, Result};

/// OssProfileCredentialProvider loads credentials from OSS profile files.
///
/// This provider loads credentials from `~/.oss/credentials` by default. The
/// file path can be overridden by `OSS_CREDENTIAL_PROFILES_FILE`, and the
/// selected profile can be overridden by `OSS_PROFILE`.
#[derive(Debug, Clone)]
pub struct OssProfileCredentialProvider {
    profile: String,
    credentials_file: Option<String>,
}

impl Default for OssProfileCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OssProfileCredentialProvider {
    /// Create a new profile provider that reads the `default` profile.
    pub fn new() -> Self {
        Self {
            profile: "default".to_string(),
            credentials_file: None,
        }
    }

    /// Set the profile name to use when `OSS_PROFILE` is not set.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Set the path to the OSS credentials file.
    pub fn with_credentials_file(mut self, path: impl Into<String>) -> Self {
        self.credentials_file = Some(path.into());
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_credentials(&self, ctx: &Context, profile: &str) -> Result<Option<Credential>> {
        let path = if let Some(path) = &self.credentials_file {
            path.clone()
        } else if let Some(path) = ctx.env_var(OSS_CREDENTIAL_PROFILES_FILE) {
            path
        } else {
            "~/.oss/credentials".to_string()
        };

        let expanded_path = if path.starts_with("~/") {
            match ctx.expand_home_dir(&path) {
                Some(expanded) => expanded,
                None => {
                    debug!("failed to expand homedir for path: {path}");
                    return Ok(None);
                }
            }
        } else {
            path.clone()
        };

        let content = match ctx.file_read(&expanded_path).await {
            Ok(content) => content,
            Err(err) => {
                debug!("failed to read OSS credentials file {expanded_path}: {err:?}");
                return Ok(None);
            }
        };

        let conf = Ini::load_from_str(&String::from_utf8_lossy(&content)).map_err(|e| {
            Error::config_invalid("failed to parse OSS credentials file").with_source(e)
        })?;

        let props = match conf.section(Some(profile)) {
            Some(props) => props,
            None => {
                debug!("profile {profile} not found in OSS credentials file");
                return Ok(None);
            }
        };

        let access_key_id =
            get_profile_value(props, &["access_key_id", "accessKeyId", "accessKeyID"]);
        let access_key_secret = get_profile_value(props, &["access_key_secret", "accessKeySecret"]);

        match (access_key_id, access_key_secret) {
            (Some(ak), Some(sk)) => Ok(Some(Credential {
                access_key_id: ak.to_string(),
                access_key_secret: sk.to_string(),
                security_token: get_profile_value(
                    props,
                    &["session_token", "security_token", "sts_token", "token"],
                )
                .map(ToString::to_string),
                expires_in: None,
            })),
            _ => Ok(None),
        }
    }
}

impl ProvideCredential for OssProfileCredentialProvider {
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
                .env_var(OSS_PROFILE)
                .unwrap_or_else(|| self.profile.clone());
            self.load_credentials(ctx, &profile).await
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn get_profile_value<'a>(props: &'a ini::Properties, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| props.get(key))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use reqsign_core::{FileRead, OsEnv, StaticEnv};
    use reqsign_http_send_reqwest::ReqwestHttpSend;
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
                reqsign_core::Error::unexpected(format!("unexpected file path: {path}"))
            })
        }
    }

    #[tokio::test]
    async fn test_profile_provider_reads_default_profile() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/credentials".to_string(),
                br#"[default]
access_key_id = profile_access_key
access_key_secret = profile_secret_key
session_token = profile_token
"#
                .to_vec(),
            )])))
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    OSS_CREDENTIAL_PROFILES_FILE.to_string(),
                    "/mock/credentials".to_string(),
                )]),
            });

        let provider = OssProfileCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;

        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "profile_access_key");
        assert_eq!(cred.access_key_secret, "profile_secret_key");
        assert_eq!(cred.security_token, Some("profile_token".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_profile_provider_selects_named_profile() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/credentials".to_string(),
                br#"[default]
access_key_id = default_access_key
access_key_secret = default_secret_key

[prod]
accessKeyID = prod_access_key
accessKeySecret = prod_secret_key
security_token = prod_token
"#
                .to_vec(),
            )])))
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([
                    (
                        OSS_CREDENTIAL_PROFILES_FILE.to_string(),
                        "/mock/credentials".to_string(),
                    ),
                    (OSS_PROFILE.to_string(), "prod".to_string()),
                ]),
            });

        let provider = OssProfileCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?.unwrap();

        assert_eq!(cred.access_key_id, "prod_access_key");
        assert_eq!(cred.access_key_secret, "prod_secret_key");
        assert_eq!(cred.security_token, Some("prod_token".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_profile_provider_returns_none_for_missing_profile() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TestFileRead::new(HashMap::from([(
                "/mock/credentials".to_string(),
                br#"[default]
access_key_id = default_access_key
access_key_secret = default_secret_key
"#
                .to_vec(),
            )])))
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([
                    (
                        OSS_CREDENTIAL_PROFILES_FILE.to_string(),
                        "/mock/credentials".to_string(),
                    ),
                    (OSS_PROFILE.to_string(), "missing".to_string()),
                ]),
            });

        let provider = OssProfileCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_none());

        Ok(())
    }
}
