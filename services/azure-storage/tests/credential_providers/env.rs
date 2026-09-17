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

use std::collections::HashMap;

use reqsign_azure_storage::EnvCredentialProvider;
use reqsign_core::StaticEnv;

use super::{assert_provider_reads_probe, live_context};

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_ENV").unwrap_or_default() == "on"
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

async fn assert_env_provider(envs: HashMap<String, String>) -> anyhow::Result<()> {
    let ctx = live_context().with_env(StaticEnv {
        home_dir: None,
        envs,
    });
    assert_provider_reads_probe(EnvCredentialProvider::new(), ctx).await
}

#[tokio::test]
async fn test_env_provider_shared_key() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_ENV is not enabled");
        return Ok(());
    }

    assert_env_provider(HashMap::from([
        (
            "AZURE_STORAGE_ACCOUNT_NAME".to_string(),
            required_env("REQSIGN_AZURE_STORAGE_ACCOUNT_NAME"),
        ),
        (
            "AZURE_STORAGE_ACCOUNT_KEY".to_string(),
            required_env("REQSIGN_AZURE_STORAGE_ACCOUNT_KEY"),
        ),
    ]))
    .await
}

#[tokio::test]
async fn test_env_provider_sas_token() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_ENV is not enabled");
        return Ok(());
    }

    assert_env_provider(HashMap::from([(
        "AZURE_STORAGE_SAS_TOKEN".to_string(),
        required_env("REQSIGN_AZURE_STORAGE_SAS_TOKEN")
            .trim_start_matches('?')
            .to_string(),
    )]))
    .await
}

#[tokio::test]
async fn test_env_provider_bearer_token() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_ENV is not enabled");
        return Ok(());
    }

    assert_env_provider(HashMap::from([(
        "AZURE_STORAGE_BEARER_TOKEN".to_string(),
        required_env("REQSIGN_AZURE_STORAGE_BEARER_TOKEN"),
    )]))
    .await
}
