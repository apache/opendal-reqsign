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

//! Example of using ProvideCredentialChain with logging to see credential resolution

use async_trait::async_trait;
use log::{debug, info};
use reqsign_core::{Context, OsEnv, ProvideCredential, ProvideCredentialChain, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_huaweicloud_obs::{
    Credential, DefaultCredentialProvider, EnvCredentialProvider, StaticCredentialProvider,
};

/// Wrapper that logs when credentials are loaded
#[derive(Debug)]
struct LoggingProvider<P> {
    name: String,
    inner: P,
}

impl<P> LoggingProvider<P> {
    fn new(name: impl Into<String>, provider: P) -> Self {
        Self {
            name: name.into(),
            inner: provider,
        }
    }
}

#[async_trait]
impl<P> ProvideCredential for LoggingProvider<P>
where
    P: ProvideCredential<Credential = Credential> + Send + Sync,
{
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        info!("Attempting to load credentials from: {}", self.name);

        match self.inner.provide_credential(ctx).await {
            Ok(Some(cred)) => {
                info!("Successfully loaded credentials from: {}", self.name);
                debug!(
                    "Loaded credential with access_key_id: {}...",
                    &cred.access_key_id[..3.min(cred.access_key_id.len())]
                );
                if cred.security_token.is_some() {
                    debug!("Credential includes security token");
                }
                Ok(Some(cred))
            }
            Ok(None) => {
                info!("No credentials found in: {}", self.name);
                Ok(None)
            }
            Err(e) => {
                info!("Error loading credentials from {}: {:?}", self.name, e);
                Err(e)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create context
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    // Build a chain with logging
    let chain = ProvideCredentialChain::new()
        .push(LoggingProvider::new(
            "Static",
            StaticCredentialProvider::new("demo_key", "demo_secret"),
        ))
        .push(LoggingProvider::new(
            "Environment",
            EnvCredentialProvider::new(),
        ))
        .push(LoggingProvider::new(
            "Default",
            DefaultCredentialProvider::new(),
        ));

    info!("Starting credential resolution...");

    match chain.provide_credential(&ctx).await? {
        Some(cred) => {
            info!("Successfully resolved credentials!");
            println!("Access Key ID: {}...", &cred.access_key_id[..3]);
            if let Some(token) = &cred.security_token {
                println!("Security Token: {}...", &token[..10.min(token.len())]);
            }
        }
        None => {
            info!("No credentials found in any provider");
        }
    }

    Ok(())
}
