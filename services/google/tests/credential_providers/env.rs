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

use log::warn;
use reqsign_core::Result;
use reqsign_google::{EnvCredentialProvider, WellKnownCredentialProvider};

use super::{assert_provider_reads_probe, create_test_context_with_env};

#[tokio::test]
async fn test_env_credential_provider_live() -> Result<()> {
    if std::env::var("REQSIGN_GOOGLE_TEST_ENV").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_ENV is not set, skipped");
        return Ok(());
    }

    let path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .expect("GOOGLE_APPLICATION_CREDENTIALS must be set");
    let ctx = create_test_context_with_env(HashMap::from([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
        path,
    )]));

    assert_provider_reads_probe(EnvCredentialProvider::new(), ctx).await
}

#[tokio::test]
async fn test_well_known_credential_provider_live() -> Result<()> {
    if std::env::var("REQSIGN_GOOGLE_TEST_WELL_KNOWN").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_WELL_KNOWN is not set, skipped");
        return Ok(());
    }

    let home = std::env::var("REQSIGN_GOOGLE_WELL_KNOWN_HOME")
        .or_else(|_| std::env::var("HOME"))
        .expect("HOME must be set");
    assert_provider_reads_probe(
        WellKnownCredentialProvider::new(),
        create_test_context_with_env(HashMap::from([("HOME".to_string(), home)])),
    )
    .await
}
