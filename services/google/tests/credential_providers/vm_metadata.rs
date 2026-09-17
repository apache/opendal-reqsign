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

use super::{assert_provider_reads_probe, create_test_context};
use log::warn;
use reqsign_core::Result;
use reqsign_google::VmMetadataCredentialProvider;
use std::env;

#[tokio::test]
async fn test_vm_metadata_credential_provider() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_VM_METADATA").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_VM_METADATA is not set, skipped");
        return Ok(());
    }

    // This test should only run on actual GCP VMs
    let ctx = create_test_context();

    assert_provider_reads_probe(VmMetadataCredentialProvider::new(), ctx).await
}

#[tokio::test]
async fn test_vm_metadata_credential_provider_with_scope() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_VM_METADATA").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_VM_METADATA is not set, skipped");
        return Ok(());
    }

    // This test allows specifying a custom scope
    let scope = env::var("REQSIGN_GOOGLE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_write".to_string());

    let ctx = create_test_context();

    assert_provider_reads_probe(VmMetadataCredentialProvider::new().with_scope(&scope), ctx).await
}
