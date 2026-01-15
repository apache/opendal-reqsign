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

use super::create_test_context_with_env;
use log::info;
use reqsign_aws_v4::EKSPodIdentityCredentialProvider;
use reqsign_core::ProvideCredential;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_eks_pod_identity_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_EKS_POD_IDENTITY").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_EKS_POD_IDENTITY not set, skipping");
        return;
    }

    let mut envs = HashMap::new();

    // EKS Pod Identity uses AWS_CONTAINER_CREDENTIALS_FULL_URI pointing to 169.254.170.23
    // and AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE for the service account token
    if let Ok(full_uri) = env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
        envs.insert("AWS_CONTAINER_CREDENTIALS_FULL_URI".to_string(), full_uri);
    } else {
        panic!("AWS_CONTAINER_CREDENTIALS_FULL_URI must be set for EKS Pod Identity test");
    }

    if let Ok(token_file) = env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
        envs.insert(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE".to_string(),
            token_file,
        );
    } else {
        panic!("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE must be set for EKS Pod Identity test");
    }

    let ctx = create_test_context_with_env(envs);
    let provider = EKSPodIdentityCredentialProvider::new();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("EKSPodIdentityCredentialProvider should succeed");

    assert!(
        cred.is_some(),
        "Should load credentials from EKS Pod Identity"
    );
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
    assert!(
        cred.session_token.is_some(),
        "EKS Pod Identity should provide session token"
    );
}
