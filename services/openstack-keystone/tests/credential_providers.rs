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

use reqsign_core::{Context, OsEnv, ProvideCredential, Signer, SigningCredential, StaticEnv};
use reqsign_openstack_keystone::{
    Credential, DefaultCredentialProvider, EnvCredentialProvider, KeystoneCredentialProvider,
    RequestSigner,
};
use std::collections::HashMap;

fn default_context() -> Context {
    Context::new()
        .with_file_read(reqsign_file_read_tokio::TokioFileRead)
        .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
        .with_env(OsEnv)
}

/// Test KeystoneCredentialProvider against a mock Keystone server.
///
/// This test requires the mock server to be running:
/// ```bash
/// python3 tests/mocks/keystone_mock_server.py 5000 &
/// ```
///
/// And the following env var:
/// - REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK=on
#[tokio::test]
async fn test_keystone_credential_provider_with_mock() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let ctx = default_context();

    let provider = KeystoneCredentialProvider::new(&mock_url)
        .with_username("testuser")
        .with_password("testpass")
        .with_user_domain_name("Default")
        .with_project_name("testproject")
        .with_project_domain_name("Default");

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!cred.token.is_empty(), "token must not be empty");
    assert!(cred.is_valid(), "credential must be valid");
    assert!(cred.expires_at.is_some(), "expires_at must be set");

    // Verify service catalog
    assert!(
        !cred.service_catalog.is_empty(),
        "service catalog must not be empty"
    );

    let swift_endpoint = cred.endpoint("object-store", "public");
    assert!(
        swift_endpoint.is_some(),
        "must find object-store public endpoint"
    );
    assert!(
        swift_endpoint.unwrap().contains("AUTH_test"),
        "endpoint must contain AUTH_test"
    );
}

/// Test KeystoneCredentialProvider rejects bad credentials.
#[tokio::test]
async fn test_keystone_credential_provider_bad_password() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let ctx = default_context();

    let provider = KeystoneCredentialProvider::new(&mock_url)
        .with_username("testuser")
        .with_password("wrong-password")
        .with_user_domain_name("Default");

    let result = provider.provide_credential(&ctx).await;
    assert!(result.is_err(), "bad password must fail");
}

/// Test EnvCredentialProvider with mock server.
#[tokio::test]
async fn test_env_credential_provider_with_mock() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let envs = HashMap::from([
        ("OPENSTACK_AUTH_URL".to_string(), mock_url),
        ("OPENSTACK_USERNAME".to_string(), "testuser".to_string()),
        ("OPENSTACK_PASSWORD".to_string(), "testpass".to_string()),
        ("OPENSTACK_DOMAIN_NAME".to_string(), "Default".to_string()),
        (
            "OPENSTACK_PROJECT_NAME".to_string(),
            "testproject".to_string(),
        ),
    ]);

    let ctx = Context::new()
        .with_file_read(reqsign_file_read_tokio::TokioFileRead)
        .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
        .with_env(StaticEnv {
            home_dir: None,
            envs,
        });

    let provider = EnvCredentialProvider::new();
    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!cred.token.is_empty());
    assert!(cred.is_valid());
}

/// Test EnvCredentialProvider returns None when vars are missing.
#[tokio::test]
async fn test_env_credential_provider_missing_vars() {
    let _ = env_logger::builder().is_test(true).try_init();

    let envs = HashMap::new();
    let ctx = Context::new()
        .with_file_read(reqsign_file_read_tokio::TokioFileRead)
        .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
        .with_env(StaticEnv {
            home_dir: None,
            envs,
        });

    let provider = EnvCredentialProvider::new();
    let result = provider
        .provide_credential(&ctx)
        .await
        .expect("should not error");

    assert!(result.is_none(), "must return None when vars are missing");
}

/// Test DefaultCredentialProvider with mock server.
#[tokio::test]
async fn test_default_credential_provider_with_mock() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let envs = HashMap::from([
        ("OPENSTACK_AUTH_URL".to_string(), mock_url),
        ("OPENSTACK_USERNAME".to_string(), "testuser".to_string()),
        ("OPENSTACK_PASSWORD".to_string(), "testpass".to_string()),
        ("OPENSTACK_DOMAIN_NAME".to_string(), "Default".to_string()),
        (
            "OPENSTACK_PROJECT_NAME".to_string(),
            "testproject".to_string(),
        ),
    ]);

    let ctx = Context::new()
        .with_file_read(reqsign_file_read_tokio::TokioFileRead)
        .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
        .with_env(StaticEnv {
            home_dir: None,
            envs,
        });

    let provider = DefaultCredentialProvider::new();
    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!cred.token.is_empty());
    assert!(cred.is_valid());
}

/// Test unscoped token (no project) — should get token but empty catalog.
#[tokio::test]
async fn test_keystone_credential_provider_unscoped() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let ctx = default_context();

    // No project_name or project_domain_name — unscoped
    let provider = KeystoneCredentialProvider::new(&mock_url)
        .with_username("testuser")
        .with_password("testpass")
        .with_user_domain_name("Default");

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!cred.token.is_empty(), "token must not be empty");
    assert!(cred.is_valid(), "credential must be valid");
    assert!(cred.expires_at.is_some(), "expires_at must be set");

    // Unscoped tokens get no catalog
    assert!(
        cred.service_catalog.is_empty(),
        "unscoped token must have empty service catalog"
    );
    assert_eq!(
        cred.endpoint("object-store", "public"),
        None,
        "unscoped token must not have endpoints"
    );
}

/// Test full Signer round-trip: provider -> cache -> sign request.
#[tokio::test]
async fn test_signer_round_trip_with_mock() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let ctx = default_context();

    let provider = KeystoneCredentialProvider::new(&mock_url)
        .with_username("testuser")
        .with_password("testpass")
        .with_user_domain_name("Default")
        .with_project_name("testproject")
        .with_project_domain_name("Default");

    let signer = Signer::new(ctx, provider, RequestSigner);

    // Build a request to sign
    let req = http::Request::builder()
        .method("GET")
        .uri("http://swift.example.com/v1/AUTH_test/container/object")
        .body(())
        .unwrap();
    let (mut parts, _body) = req.into_parts();

    // Sign it
    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must succeed");

    // Verify the X-Auth-Token header was inserted
    let token = parts
        .headers
        .get("x-auth-token")
        .expect("x-auth-token header must be present");
    assert!(!token.is_empty(), "x-auth-token header must not be empty");

    // Sign a second request — should reuse cached credential, not re-auth
    let req2 = http::Request::builder()
        .method("PUT")
        .uri("http://swift.example.com/v1/AUTH_test/container/object2")
        .body(())
        .unwrap();
    let (mut parts2, _body2) = req2.into_parts();

    signer
        .sign(&mut parts2, None)
        .await
        .expect("second signing must succeed");

    let token2 = parts2
        .headers
        .get("x-auth-token")
        .expect("x-auth-token header must be present on second request");

    // Both should have the same token (cached)
    assert_eq!(
        token.to_str().unwrap(),
        token2.to_str().unwrap(),
        "cached token must be reused"
    );
}

/// Test that connection refused / bad auth URL produces a clear error.
#[tokio::test]
async fn test_keystone_credential_provider_connection_refused() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = default_context();

    // Use a port that's (almost certainly) not listening
    let provider = KeystoneCredentialProvider::new("http://127.0.0.1:19999/v3")
        .with_username("testuser")
        .with_password("testpass")
        .with_user_domain_name("Default");

    let result = provider.provide_credential(&ctx).await;
    assert!(
        result.is_err(),
        "connection refused must return an error, not silently succeed"
    );
}

/// Test that empty username/password returns None (skip).
#[tokio::test]
async fn test_keystone_credential_provider_empty_credentials() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = default_context();

    let provider = KeystoneCredentialProvider::new("http://127.0.0.1:5000/v3");
    // No username/password set — should return None, not error

    let result = provider
        .provide_credential(&ctx)
        .await
        .expect("empty credentials must not error");

    assert!(result.is_none(), "empty credentials must return None");
}

/// Test catalog region filtering with mock server.
#[tokio::test]
async fn test_keystone_catalog_region_filtering_with_mock() {
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST_MOCK").unwrap_or_default() != "on" {
        return;
    }

    let mock_url = env::var("REQSIGN_OPENSTACK_KEYSTONE_MOCK_URL")
        .unwrap_or("http://127.0.0.1:5000/v3".into());

    let ctx = default_context();

    let provider = KeystoneCredentialProvider::new(&mock_url)
        .with_username("testuser")
        .with_password("testpass")
        .with_user_domain_name("Default")
        .with_project_name("testproject")
        .with_project_domain_name("Default");

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    // Mock server returns endpoints in "RegionOne"
    assert_eq!(
        cred.endpoint_in_region("object-store", "public", "RegionOne"),
        Some("http://127.0.0.1:8080/v1/AUTH_test"),
        "must find object-store public endpoint in RegionOne"
    );
    assert_eq!(
        cred.endpoint_in_region("object-store", "internal", "RegionOne"),
        Some("http://swift-internal:8080/v1/AUTH_test"),
        "must find object-store internal endpoint in RegionOne"
    );

    // Non-existent region
    assert_eq!(
        cred.endpoint_in_region("object-store", "public", "NonExistent"),
        None,
        "must not find endpoint in non-existent region"
    );
}

/// Integration test against a real Keystone service.
///
/// Requires:
/// - REQSIGN_OPENSTACK_KEYSTONE_TEST=on
/// - OPENSTACK_AUTH_URL
/// - OPENSTACK_USERNAME
/// - OPENSTACK_PASSWORD
/// - OPENSTACK_DOMAIN_NAME (optional, defaults to "Default")
/// - OPENSTACK_PROJECT_NAME (optional)
#[tokio::test]
async fn test_real_keystone_env_credential_provider() {
    let _ = dotenvy::dotenv();
    let _ = env_logger::builder().is_test(true).try_init();

    if env::var("REQSIGN_OPENSTACK_KEYSTONE_TEST").unwrap_or_default() != "on" {
        return;
    }

    let ctx = default_context();

    let provider = EnvCredentialProvider::new();
    let cred: Credential = provider
        .provide_credential(&ctx)
        .await
        .expect("credential loading must succeed")
        .expect("credential must be present");

    assert!(!cred.token.is_empty(), "token must not be empty");
    assert!(cred.is_valid(), "credential must be valid");
    assert!(cred.expires_at.is_some(), "expires_at must be set");

    println!("Token obtained successfully");
    println!("Expires at: {:?}", cred.expires_at);
    println!("Service catalog entries: {}", cred.service_catalog.len());

    for entry in &cred.service_catalog {
        println!("  Service: {}", entry.service_type);
        for ep in &entry.endpoints {
            println!("    {} ({:?}): {}", ep.interface, ep.region, ep.url);
        }
    }
}
