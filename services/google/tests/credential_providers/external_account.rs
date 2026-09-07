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

use super::{assert_provider_reads_probe, create_test_context_with_env};
use log::warn;
use reqsign_core::Result;
use reqsign_google::{
    DefaultCredentialProvider, ExternalAccountConfig, ExternalAccountCredentialProvider,
};
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_external_account_with_workload_identity() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_WORKLOAD_IDENTITY").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_WORKLOAD_IDENTITY is not set, skipped");
        return Ok(());
    }

    // This test is for real workload identity scenarios (e.g., GitHub Actions, Kubernetes)
    // It requires a properly configured external account credential file
    let cred_path = env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .expect("GOOGLE_APPLICATION_CREDENTIALS must be set for workload identity test");

    // Verify the file is an external account type.
    // google-github-actions/auth writes compact JSON (`"type":"external_account"`).
    let content = std::fs::read_to_string(&cred_path).expect("Failed to read credential file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("credential file must be valid JSON");
    assert_eq!(
        parsed.get("type").and_then(|v| v.as_str()),
        Some("external_account"),
        "Credential file must be external_account type for workload identity, got: {content}"
    );

    let scope = env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_only".to_string());
    let ctx = create_test_context_with_env(HashMap::from_iter([
        ("GOOGLE_APPLICATION_CREDENTIALS".to_string(), cred_path),
        ("GOOGLE_SCOPE".to_string(), scope),
    ]));

    assert_provider_reads_probe(DefaultCredentialProvider::new(), ctx).await
}

#[tokio::test]
async fn test_external_account_with_caller_subject_token_live() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_WORKLOAD_IDENTITY").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_WORKLOAD_IDENTITY is not set, skipped");
        return Ok(());
    }

    let subject_token =
        env::var("REQSIGN_GOOGLE_SUBJECT_TOKEN").expect("REQSIGN_GOOGLE_SUBJECT_TOKEN must be set");
    let audience = env::var("REQSIGN_GOOGLE_WORKLOAD_IDENTITY_AUDIENCE")
        .expect("REQSIGN_GOOGLE_WORKLOAD_IDENTITY_AUDIENCE must be set");
    let service_account =
        env::var("GOOGLE_SERVICE_ACCOUNT").expect("GOOGLE_SERVICE_ACCOUNT must be set");
    let scope = env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_only".to_string());
    let config = ExternalAccountConfig::new(
        audience,
        "urn:ietf:params:oauth:token-type:jwt",
        "https://sts.googleapis.com/v1/token",
    )
    .with_service_account_impersonation_url(format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account}:generateAccessToken"
    ));
    let provider = ExternalAccountCredentialProvider::from_subject_token(config, subject_token)
        .with_scope(scope);

    assert_provider_reads_probe(provider, super::create_test_context()).await
}
