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

#![allow(deprecated)]

use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, Result};
use std::sync::Arc;
use std::time::Duration;

/// Static configuration based loader.
#[derive(Debug)]
pub struct ConfigCredentialProvider {
    config: Arc<Config>,
}

impl ConfigCredentialProvider {
    /// Create a new ConfigCredentialProvider
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Merge with environment config
        let env_config = Config::from_env(ctx);
        let config = self.config.as_ref();

        // Use environment values if available, otherwise fall back to config
        let tenancy = env_config.tenancy.or_else(|| config.tenancy.clone());
        let user = env_config.user.or_else(|| config.user.clone());
        let key_file = env_config.key_file.or_else(|| config.key_file.clone());
        let fingerprint = env_config
            .fingerprint
            .or_else(|| config.fingerprint.clone());

        match (&tenancy, &user, &key_file, &fingerprint) {
            (Some(tenancy), Some(user), Some(key_file), Some(fingerprint)) => {
                debug!("loading credential from config");
                Ok(Some(Credential {
                    tenancy: tenancy.clone(),
                    user: user.clone(),
                    key_file: key_file.clone(),
                    fingerprint: fingerprint.clone(),
                    // Set expires_in to 10 minutes to enforce re-read
                    expires_in: Some(Timestamp::now() + Duration::from_secs(600)),
                }))
            }
            _ => {
                debug!("incomplete config, skipping");
                Ok(None)
            }
        }
    }
}
