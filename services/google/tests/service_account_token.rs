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

use std::env;

use log::warn;
use reqsign_core::{Context, Granter, Result, Signer};
use reqsign_google::{
    CredentialAccessBoundaryGrant, CredentialAccessBoundaryPermissions, RequestSigner,
    ServerSideCredentialAccessBoundaryGranter, ServiceAccountTokenCredentialProvider,
    StaticCredentialProvider, TokenCredentialProvider,
};
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::test]
async fn test_service_account_token_provider_with_server_side_cab_live_interoperability()
-> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenvy::dotenv();
    if env::var("REQSIGN_GOOGLE_TEST_SERVICE_ACCOUNT_TOKEN").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_SERVICE_ACCOUNT_TOKEN is not set, skipped");
        return Ok(());
    }

    let service_account_base64 = env::var("REQSIGN_GOOGLE_CREDENTIAL")
        .expect("REQSIGN_GOOGLE_CREDENTIAL must contain base64 service-account JSON");
    let bucket =
        env::var("REQSIGN_GOOGLE_CAB_BUCKET").expect("REQSIGN_GOOGLE_CAB_BUCKET must be set");
    let object_prefix = env::var("REQSIGN_GOOGLE_CAB_OBJECT_PREFIX")
        .expect("REQSIGN_GOOGLE_CAB_OBJECT_PREFIX must be set");

    let source = ServiceAccountTokenCredentialProvider::from_provider(
        StaticCredentialProvider::from_base64(&service_account_base64)?,
    );
    let grant = CredentialAccessBoundaryGrant::for_object_prefix(
        &bucket,
        &object_prefix,
        CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
    );
    let downscoped = Granter::new(
        Context::new().with_http_send(ReqwestHttpSend::default()),
        source,
        ServerSideCredentialAccessBoundaryGranter::new(grant),
    )
    .grant(None)
    .await?;
    let token = downscoped
        .token
        .expect("server-side CAB output must contain a token");
    let expires_at = token
        .expires_at
        .expect("server-side CAB output must have an expiration");
    let signer = Signer::new(
        Context::new(),
        TokenCredentialProvider::new(token.access_token).with_expires_at(expires_at),
        RequestSigner::new("storage"),
    );

    let mut url = reqwest::Url::parse(&format!(
        "https://storage.googleapis.com/storage/v1/b/{bucket}/o"
    ))
    .expect("Cloud Storage URL must be valid");
    url.query_pairs_mut()
        .append_pair("maxResults", "1")
        .append_pair("prefix", &object_prefix);
    let request = http::Request::get(url.as_str())
        .body("")
        .expect("Cloud Storage request must build");
    let (mut parts, body) = request.into_parts();
    signer.sign(&mut parts, None).await?;
    let response = reqwest::Client::new()
        .execute(
            http::Request::from_parts(parts, body)
                .try_into()
                .map_err(|err| {
                    reqsign_core::Error::unexpected(
                        "failed to convert service-account token live request",
                    )
                    .with_source(err)
                })?,
        )
        .await
        .map_err(|err| {
            reqsign_core::Error::unexpected("service-account token live request failed")
                .with_source(err)
        })?;
    assert!(
        response.status().is_success(),
        "server-issued CAB token was rejected with status {}",
        response.status()
    );

    let disallowed_prefix = if object_prefix.starts_with('a') {
        "b-reqsign-cab-out-of-scope/"
    } else {
        "a-reqsign-cab-out-of-scope/"
    };
    let mut url = reqwest::Url::parse(&format!(
        "https://storage.googleapis.com/storage/v1/b/{bucket}/o"
    ))
    .expect("Cloud Storage URL must be valid");
    url.query_pairs_mut()
        .append_pair("maxResults", "1")
        .append_pair("prefix", disallowed_prefix);
    let request = http::Request::get(url.as_str())
        .body("")
        .expect("Cloud Storage request must build");
    let (mut parts, body) = request.into_parts();
    signer.sign(&mut parts, None).await?;
    let response = reqwest::Client::new()
        .execute(
            http::Request::from_parts(parts, body)
                .try_into()
                .map_err(|err| {
                    reqsign_core::Error::unexpected(
                        "failed to convert out-of-scope service-account token live request",
                    )
                    .with_source(err)
                })?,
        )
        .await
        .map_err(|err| {
            reqsign_core::Error::unexpected(
                "out-of-scope service-account token live request failed",
            )
            .with_source(err)
        })?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "server-issued CAB token unexpectedly accessed an out-of-scope prefix"
    );
    Ok(())
}
