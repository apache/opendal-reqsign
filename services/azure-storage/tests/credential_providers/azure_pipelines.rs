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

use reqsign_azure_storage::AzurePipelinesCredentialProvider;

use super::{assert_provider_reads_probe, live_context};

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_PIPELINES").unwrap_or_default() == "on"
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[tokio::test]
async fn test_azure_pipelines_provider() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_PIPELINES is not enabled");
        return Ok(());
    }

    required_env("SYSTEM_OIDCREQUESTURI");
    required_env("SYSTEM_ACCESSTOKEN");
    let provider = AzurePipelinesCredentialProvider::new()
        .with_tenant_id(&required_env("AZURESUBSCRIPTION_TENANT_ID"))
        .with_client_id(&required_env("AZURESUBSCRIPTION_CLIENT_ID"))
        .with_service_connection_id(&required_env("AZURESUBSCRIPTION_SERVICE_CONNECTION_ID"));

    assert_provider_reads_probe(provider, live_context()).await
}
