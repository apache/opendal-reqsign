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

use super::{assert_credentials_work, create_test_context};
use log::info;
use reqsign_aws_v4::{
    DefaultCredentialProvider, S3AccessGrantsConfig, S3AccessGrantsGrant, S3AccessGrantsGranter,
    S3AccessGrantsPermission, S3AccessGrantsPrivilege, S3AccessGrantsTarget,
};
use reqsign_core::{Granter, ProvideCredential};
use std::env;
use std::time::Duration;

#[tokio::test]
async fn test_s3_access_grants_granter_live() {
    if env::var("REQSIGN_AWS_V4_TEST_S3_ACCESS_GRANTS").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_S3_ACCESS_GRANTS not set, skipping");
        return;
    }

    let account_id =
        env::var("REQSIGN_AWS_V4_ACCOUNT_ID").expect("REQSIGN_AWS_V4_ACCOUNT_ID must be set");
    let region = env::var("AWS_REGION").expect("AWS_REGION must be set");
    let bucket = env::var("REQSIGN_AWS_V4_S3_ACCESS_GRANTS_BUCKET")
        .expect("REQSIGN_AWS_V4_S3_ACCESS_GRANTS_BUCKET must be set");
    let prefix = env::var("REQSIGN_AWS_V4_S3_ACCESS_GRANTS_PREFIX")
        .expect("REQSIGN_AWS_V4_S3_ACCESS_GRANTS_PREFIX must be set");

    let context = create_test_context();
    let source = DefaultCredentialProvider::new()
        .provide_credential(&context)
        .await
        .expect("source credential provider should succeed")
        .expect("source credential provider should return credentials");
    let operation = S3AccessGrantsGranter::new(
        S3AccessGrantsConfig::new(account_id, region),
        S3AccessGrantsGrant::new(
            S3AccessGrantsTarget::for_prefix(bucket, prefix),
            S3AccessGrantsPermission::ReadWrite,
            S3AccessGrantsPrivilege::Minimal,
        )
        .with_audit_context("reqsign-live-test"),
    );
    let mut source_provider = reqsign_aws_v4::StaticCredentialProvider::new(
        &source.access_key_id,
        &source.secret_access_key,
    );
    if let Some(session_token) = source.session_token.as_deref() {
        source_provider = source_provider.with_session_token(session_token);
    }
    let granter = Granter::new(context.clone(), source_provider, operation);

    let credential = granter
        .grant(Some(Duration::from_secs(900)))
        .await
        .expect("S3 Access Grants GetDataAccess should succeed");
    assert!(credential.session_token.is_some());
    assert!(credential.expires_in.is_some());
    assert_credentials_work(&context, &credential).await;
}
