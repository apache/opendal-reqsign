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
use reqsign_aws_v4::DefaultCredentialProvider;
use reqsign_core::ProvideCredential;
use std::env;

#[tokio::test]
async fn test_default_credential_provider_live() {
    if env::var("REQSIGN_AWS_V4_TEST_DEFAULT").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_DEFAULT not set, skipping");
        return;
    }

    let ctx = create_test_context();
    let credential = DefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("DefaultCredentialProvider should succeed")
        .expect("DefaultCredentialProvider should return credentials");
    assert_credentials_work(&ctx, &credential).await;
}
