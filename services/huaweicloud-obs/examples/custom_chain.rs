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

//! Example of building a custom credential chain with specific providers

use async_trait::async_trait;
use reqsign_core::{Context, OsEnv, ProvideCredential, ProvideCredentialChain, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_huaweicloud_obs::Credential;

/// Custom provider that always returns a specific credential
#[derive(Debug)]
struct StaticCredentialProvider {
    access_key_id: String,
    secret_access_key: String,
    security_token: Option<String>,
}

impl StaticCredentialProvider {
    fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            security_token: None,
        }
    }

    fn with_security_token(mut self, token: String) -> Self {
        self.security_token = Some(token);
        self
    }
}

#[async_trait]
impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(Credential::new(
            self.access_key_id.clone(),
            self.secret_access_key.clone(),
            self.security_token.clone(),
        )))
    }
}

/// Environment-based provider (simplified example)
#[derive(Debug)]
struct EnvCredentialProvider;

#[async_trait]
impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Check for credentials in environment
        match (
            ctx.env_var("HUAWEI_CLOUD_ACCESS_KEY_ID"),
            ctx.env_var("HUAWEI_CLOUD_SECRET_ACCESS_KEY"),
        ) {
            (Some(ak), Some(sk)) => {
                let st = ctx.env_var("HUAWEI_CLOUD_SECURITY_TOKEN");
                Ok(Some(Credential::new(ak, sk, st)))
            }
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create context
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    // Build a custom chain with specific priority order
    let chain = ProvideCredentialChain::new()
        // First, try environment variables
        .push(EnvCredentialProvider)
        // Then try a static credential (for development/testing)
        .push(StaticCredentialProvider::new(
            "dev_access_key".to_string(),
            "dev_secret_key".to_string(),
        ));

    // You can also build chains dynamically based on configuration
    let mut dynamic_chain = ProvideCredentialChain::new();

    if std::env::var("USE_ENV_CREDS").is_ok() {
        dynamic_chain = dynamic_chain.push(EnvCredentialProvider);
    }

    if std::env::var("USE_TEMP_CREDS").is_ok() {
        dynamic_chain = dynamic_chain.push(
            StaticCredentialProvider::new("temp_key".to_string(), "temp_secret".to_string())
                .with_security_token("temporary_security_token".to_string()),
        );
    }

    // Example of using the dynamic chain
    println!("\nDynamic chain resolution:");
    match dynamic_chain.provide_credential(&ctx).await? {
        Some(_) => println!("Found credential in dynamic chain"),
        None => println!("No credentials in dynamic chain"),
    }

    // Resolve credentials from the main chain
    match chain.provide_credential(&ctx).await? {
        Some(cred) => {
            println!("\nFound credential!");
            println!("Access Key ID: {}", cred.access_key_id);
            if let Some(token) = &cred.security_token {
                println!("Has security token: {} chars", token.len());
            }
        }
        None => {
            println!("No credentials found");
        }
    }

    Ok(())
}
