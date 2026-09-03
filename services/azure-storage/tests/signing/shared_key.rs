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

fn get_test_config() -> Option<(String, String, String, String, String)> {
    if !is_test_enabled() {
        return None;
    }

    let url = required_env("REQSIGN_AZURE_STORAGE_URL");
    let account_name = required_env("REQSIGN_AZURE_STORAGE_ACCOUNT_NAME");
    let account_key = required_env("REQSIGN_AZURE_STORAGE_ACCOUNT_KEY");
    let service =
        std::env::var("REQSIGN_AZURE_STORAGE_SERVICE").unwrap_or_else(|_| "blob".to_string());
    let container =
        std::env::var("REQSIGN_AZURE_STORAGE_CONTAINER").unwrap_or_else(|_| "test".to_string());

    Some((url, account_name, account_key, service, container))
}

#[tokio::test]
async fn test_shared_key_signing_get() -> anyhow::Result<()> {
    let Some((url, account_name, account_key, _, _)) = get_test_config() else {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return Ok(());
    };

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_shared_key(&account_name, &account_key);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    let request = http::Request::get(&url)
        .header("x-ms-version", "2021-12-02")
        .body(Bytes::new())?;
    let (mut parts, body) = request.into_parts();

    signer.sign(&mut parts, None).await?;

    // Verify required headers were added
    assert!(parts.headers.contains_key("authorization"));
    assert!(parts.headers.contains_key("x-ms-date"));

    // Authorization header should contain SharedKey
    let auth = parts
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(auth.starts_with("SharedKey"));
    assert!(auth.contains(&account_name));

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
async fn test_shared_key_signing_put_with_body() {
    let Some((url, account_name, account_key, _, container)) = get_test_config() else {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return;
    };

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_shared_key(&account_name, &account_key);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx, loader, builder);

    // Test PUT request with body
    let body = b"test content";
    let blob_url = format!("{}/{}/test.txt", url, container);

    let mut parts = http::Request::put(&blob_url)
        .header("x-ms-version", "2021-12-02")
        .header("x-ms-blob-type", "BlockBlob")
        .header("Content-Length", body.len().to_string())
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await.unwrap();

    // Verify required headers
    assert!(parts.headers.contains_key("authorization"));
    assert!(parts.headers.contains_key("x-ms-date"));

    let auth = parts
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(auth.starts_with("SharedKey"));
}

#[tokio::test]
async fn test_shared_key_signing_with_query_params() {
    let Some((url, account_name, account_key, _, _)) = get_test_config() else {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return;
    };

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_shared_key(&account_name, &account_key);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx, loader, builder);

    // Test request with query parameters
    let list_url = format!("{}?comp=list&maxresults=10", url);

    let mut parts = http::Request::get(&list_url)
        .header("x-ms-version", "2021-12-02")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await.unwrap();

    assert!(parts.headers.contains_key("authorization"));
    assert!(parts.headers.contains_key("x-ms-date"));
}

#[tokio::test]
async fn test_shared_key_signing_special_headers() {
    let Some((url, account_name, account_key, _, _)) = get_test_config() else {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return;
    };

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = StaticCredentialProvider::new_shared_key(&account_name, &account_key);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx, loader, builder);

    // Test with custom x-ms-* headers
    let mut parts = http::Request::get(&url)
        .header("x-ms-version", "2021-12-02")
        .header("x-ms-client-request-id", "test-request-123")
        .header("x-ms-meta-custom", "custom-value")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await.unwrap();

    assert!(parts.headers.contains_key("authorization"));
    // Custom headers should be preserved
    assert_eq!(
        parts.headers.get("x-ms-client-request-id").unwrap(),
        "test-request-123"
    );
    assert_eq!(
        parts.headers.get("x-ms-meta-custom").unwrap(),
        "custom-value"
    );
}
