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

use bytes::Bytes;
use reqsign_azure_storage::{RequestSigner, StaticCredentialProvider};
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap_or_default() == "on"
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn load_sas_token() -> String {
    required_env("REQSIGN_AZURE_STORAGE_SAS_TOKEN")
        .trim_start_matches('?')
        .to_string()
}

#[tokio::test]
async fn test_sas_token_signing() -> anyhow::Result<()> {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return Ok(());
    }

    let url = required_env("REQSIGN_AZURE_STORAGE_URL");
    let sas_token = load_sas_token();

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_sas_token(&sas_token);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    let request = http::Request::get(&url)
        .header("x-ms-version", "2021-12-02")
        .body(Bytes::new())?;
    let (mut parts, body) = request.into_parts();

    signer.sign(&mut parts, None).await?;

    // With SAS token, no Authorization header should be added
    assert!(!parts.headers.contains_key("authorization"));

    // Decide separator from the original URL. Checking the signed URI always
    // sees '?', which incorrectly forces the '&' branch.
    let uri = parts.uri.to_string();
    if url.contains('?') {
        assert!(uri.contains(&format!("&{sas_token}")) || sas_token.is_empty());
    } else {
        assert!(uri.contains(&format!("?{sas_token}")) || sas_token.is_empty());
    }

    let response = ctx
        .http_send(http::Request::from_parts(parts, body))
        .await?;
    anyhow::ensure!(
        response.status() == http::StatusCode::OK,
        "Azure Blob probe returned HTTP {}",
        response.status()
    );
    anyhow::ensure!(
        response.body().as_ref() == b"reqsign-live-azure-ok\n",
        "Azure Blob probe returned an unexpected body"
    );
    Ok(())
}

#[tokio::test]
async fn test_sas_token_with_existing_query() {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return;
    }

    let base_url = required_env("REQSIGN_AZURE_STORAGE_URL");
    let sas_token = load_sas_token();

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_sas_token(&sas_token);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx, loader, builder);

    // Test with existing query parameters
    let url_with_query = format!("{}?comp=list&maxresults=10", base_url);

    let mut parts = http::Request::get(&url_with_query)
        .header("x-ms-version", "2021-12-02")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await.unwrap();

    // No Authorization header with SAS token
    assert!(!parts.headers.contains_key("authorization"));

    // Original query params should be preserved
    let uri = parts.uri.to_string();
    assert!(uri.contains("comp=list"));
    assert!(uri.contains("maxresults=10"));
}

#[tokio::test]
async fn test_sas_token_preserves_headers() {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return;
    }

    let url = required_env("REQSIGN_AZURE_STORAGE_URL");
    let sas_token = load_sas_token();

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_sas_token(&sas_token);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx, loader, builder);

    // Test that custom headers are preserved
    let mut parts = http::Request::get(&url)
        .header("x-ms-version", "2021-12-02")
        .header("x-ms-client-request-id", "test-123")
        .header("Custom-Header", "custom-value")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await.unwrap();

    // Headers should be preserved
    assert_eq!(
        parts.headers.get("x-ms-client-request-id").unwrap(),
        "test-123"
    );
    assert_eq!(parts.headers.get("Custom-Header").unwrap(), "custom-value");
}
