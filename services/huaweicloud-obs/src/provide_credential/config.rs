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

use async_trait::async_trait;
use reqsign_core::Result;
use reqsign_core::{Context, ProvideCredential};

use crate::credential::Credential;

/// ConfigCredentialProvider will load credential from config.
///
/// # Deprecated
///
/// This provider is deprecated and will be removed in a future version.
/// Use `StaticCredentialProvider` for static credentials or `EnvCredentialProvider`
/// for environment-based credentials instead.
#[deprecated(
    since = "0.1.0",
    note = "Use StaticCredentialProvider or EnvCredentialProvider instead"
)]
#[derive(Debug)]
pub struct ConfigCredentialProvider;

#[allow(deprecated)]
impl ConfigCredentialProvider {
    /// Create a new ConfigCredentialProvider - this is a no-op and deprecated
    pub fn new(_: std::sync::Arc<()>) -> Self {
        Self
    }
}

#[async_trait]
#[allow(deprecated)]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        // Always return None since Config is removed
        Ok(None)
    }
}
