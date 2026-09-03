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

use reqsign_azure_storage::{DefaultCredentialProvider, EnvCredentialProvider};
use reqsign_core::{Context, ProvideCredential, StaticEnv};

use super::{assert_provider_reads_probe, live_context};

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_DEFAULT").unwrap_or_default() == "on"
}

#[tokio::test]
async fn test_default_provider() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_DEFAULT is not enabled");
        return Ok(());
    }

    assert_provider_reads_probe(DefaultCredentialProvider::new(), live_context()).await
}

#[tokio::test]
async fn builder_can_remove_and_restore_environment_slot() {
    let ctx = Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([
            (
                "AZURE_STORAGE_ACCOUNT_NAME".to_string(),
                "testaccount".to_string(),
            ),
            (
                "AZURE_STORAGE_ACCOUNT_KEY".to_string(),
                "dGVzdGtleQ==".to_string(),
            ),
        ]),
    });

    let without_env = DefaultCredentialProvider::builder()
        .no_env()
        .no_client_secret()
        .no_azure_pipelines()
        .no_workload_identity()
        .no_imds();
    #[cfg(not(target_arch = "wasm32"))]
    let without_env = without_env.no_azure_cli().no_client_certificate();
    assert!(
        without_env
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap()
            .is_none()
    );

    let with_env = DefaultCredentialProvider::builder()
        .no_client_secret()
        .no_azure_pipelines()
        .no_workload_identity()
        .no_imds()
        .env(EnvCredentialProvider::new());
    #[cfg(not(target_arch = "wasm32"))]
    let with_env = with_env.no_azure_cli().no_client_certificate();
    assert!(
        with_env
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap()
            .is_some()
    );
}
