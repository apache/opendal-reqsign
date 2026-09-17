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
use reqsign_google::DefaultCredentialProvider;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_impersonated_service_account_credential_provider() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_IMPERSONATED_SERVICE_ACCOUNT").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_IMPERSONATED_SERVICE_ACCOUNT is not set, skipped");
        return Ok(());
    }

    // This test requires a valid impersonated service account credential file
    let cred_path = env::var("REQSIGN_GOOGLE_IMPERSONATED_SERVICE_ACCOUNT_CREDENTIALS").expect(
        "REQSIGN_GOOGLE_IMPERSONATED_SERVICE_ACCOUNT_CREDENTIALS must be set for this test",
    );

    // Verify the file exists and is an impersonated_service_account type
    let content = std::fs::read_to_string(&cred_path)
        .expect("Failed to read impersonated service account credential file");
    assert!(
        content.contains(r#""type": "impersonated_service_account""#),
        "Credential file must be impersonated_service_account type"
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
async fn test_impersonated_service_account_with_real_credentials() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_IMPERSONATION_REAL").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_IMPERSONATION_REAL is not set, skipped");
        return Ok(());
    }

    // This test requires:
    // 1. A valid impersonated service account credential file
    // 2. The source credentials (OAuth2 or service account) must have impersonation permissions
    // 3. The target service account must exist

    let cred_path = env::var("REQSIGN_GOOGLE_IMPERSONATED_CREDENTIALS")
        .expect("REQSIGN_GOOGLE_IMPERSONATED_CREDENTIALS must be set for this test");

    // Verify the file is an impersonated_service_account type
    let content =
        std::fs::read_to_string(&cred_path).expect("Failed to read impersonated credential file");
    assert!(
        content.contains(r#""type": "impersonated_service_account""#),
        "Credential file must be impersonated_service_account type"
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
async fn test_impersonated_service_account_with_delegates() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_IMPERSONATION_DELEGATES").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_IMPERSONATION_DELEGATES is not set, skipped");
        return Ok(());
    }

    // This test requires a valid impersonated service account credential with delegation
    let cred_path = env::var("REQSIGN_GOOGLE_IMPERSONATED_DELEGATES_CREDENTIALS")
        .expect("REQSIGN_GOOGLE_IMPERSONATED_DELEGATES_CREDENTIALS must be set for this test");

    // Verify the file is an impersonated_service_account type with delegates
    let content = std::fs::read_to_string(&cred_path)
        .expect("Failed to read impersonated credential file with delegates");
    assert!(
        content.contains(r#""type": "impersonated_service_account""#),
        "Credential file must be impersonated_service_account type"
    );
    assert!(
        content.contains(r#""delegates""#),
        "Credential file must contain delegation chain"
    );

    let scope = env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_only".to_string());
    let ctx = create_test_context_with_env(HashMap::from_iter([
        ("GOOGLE_APPLICATION_CREDENTIALS".to_string(), cred_path),
        ("GOOGLE_SCOPE".to_string(), scope),
    ]));

    assert_provider_reads_probe(DefaultCredentialProvider::new(), ctx).await
}
