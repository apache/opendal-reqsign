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

use std::time::Duration;

use log::warn;
use reqsign_core::{Result, Signer};
use reqsign_google::{
    RequestSigner, ServiceAccountImpersonationCredentialProvider, ServiceAccountImpersonationGrant,
    TokenCredentialProvider,
};

use super::{assert_provider_reads_probe, create_test_context};

fn live_provider() -> ServiceAccountImpersonationCredentialProvider {
    let source_token = std::env::var("REQSIGN_GOOGLE_ACCESS_TOKEN")
        .expect("REQSIGN_GOOGLE_ACCESS_TOKEN must be set");
    let target = std::env::var("REQSIGN_GOOGLE_IMPERSONATED_SERVICE_ACCOUNT")
        .expect("REQSIGN_GOOGLE_IMPERSONATED_SERVICE_ACCOUNT must be set");
    let source =
        TokenCredentialProvider::new(source_token).with_expires_in(Duration::from_secs(1800));
    // The resulting token reads the probe and calls IAM Credentials signBlob.
    let grant = ServiceAccountImpersonationGrant::new(
        target,
        ["https://www.googleapis.com/auth/cloud-platform"],
    );
    ServiceAccountImpersonationCredentialProvider::new(source, grant)
        .with_lifetime(Duration::from_secs(1800))
}

#[tokio::test]
async fn test_service_account_impersonation_provider_live() -> Result<()> {
    if std::env::var("REQSIGN_GOOGLE_TEST_SERVICE_ACCOUNT_IMPERSONATION").unwrap_or_default()
        != "on"
    {
        warn!("REQSIGN_GOOGLE_TEST_SERVICE_ACCOUNT_IMPERSONATION is not set, skipped");
        return Ok(());
    }

    assert_provider_reads_probe(live_provider(), create_test_context()).await
}

#[tokio::test]
async fn test_service_account_impersonation_sign_blob_live() -> Result<()> {
    if std::env::var("REQSIGN_GOOGLE_TEST_SERVICE_ACCOUNT_IMPERSONATION").unwrap_or_default()
        != "on"
    {
        warn!("REQSIGN_GOOGLE_TEST_SERVICE_ACCOUNT_IMPERSONATION is not set, skipped");
        return Ok(());
    }

    let url = std::env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SIGNED_PROBE_URL")
        .expect("REQSIGN_GOOGLE_CLOUD_STORAGE_SIGNED_PROBE_URL must be set");
    let ctx = create_test_context();
    let signer = Signer::new(ctx, live_provider(), RequestSigner::new("storage"));
    let request = http::Request::get(url)
        .body("")
        .expect("Google Cloud Storage signed probe request must build");
    let (mut parts, body) = request.into_parts();
    signer
        .sign(&mut parts, Some(Duration::from_secs(300)))
        .await?;

    let response = reqwest::Client::new()
        .execute(
            http::Request::from_parts(parts, body)
                .try_into()
                .map_err(|err| {
                    reqsign_core::Error::unexpected(
                        "failed to convert signBlob signed probe request",
                    )
                    .with_source(err)
                })?,
        )
        .await
        .map_err(|err| {
            reqsign_core::Error::unexpected("signBlob signed probe request failed").with_source(err)
        })?;
    let status = response.status();
    let body = response.text().await.map_err(|err| {
        reqsign_core::Error::unexpected("failed to read signBlob signed probe response")
            .with_source(err)
    })?;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "reqsign-live-google-ok\n");
    Ok(())
}
