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

use reqsign_azure_storage::ClientSecretCredentialProvider;

use super::{assert_provider_reads_probe, live_context};

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_CLIENT_SECRET").unwrap_or_default() == "on"
}

#[tokio::test]
async fn test_client_secret_provider() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_CLIENT_SECRET is not enabled");
        return Ok(());
    }

    let _tenant_id = std::env::var("AZURE_TENANT_ID")
        .expect("AZURE_TENANT_ID must be set for client secret test");
    let _client_id = std::env::var("AZURE_CLIENT_ID")
        .expect("AZURE_CLIENT_ID must be set for client secret test");
    let _client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .expect("AZURE_CLIENT_SECRET must be set for client secret test");

    assert_provider_reads_probe(ClientSecretCredentialProvider::new(), live_context()).await
}
