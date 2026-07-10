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

use anyhow::{Context as _, Result};
use http::{Method, Request, StatusCode};
use log::warn;
use reqsign_core::hash::hex_sha256;
use reqsign_core::{Context, SignRequest};
use reqsign_volcengine_tos::{Credential, RequestSigner};
use reqwest::Client;
use std::env;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_presigned_object_lifecycle() -> Result<()> {
    let Some(cfg) = load_integration_config()? else {
        warn!("REQSIGN_VOLCENGINE_TOS_TEST is not set, skipped");
        return Ok(());
    };

    let ctx = Context::new();
    let signer = RequestSigner::new(&cfg.region);
    let client = Client::new();
    let object_key = format!(
        "reqsign-presign-e2e-{}-{}.txt",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time must be after UNIX_EPOCH")?
            .as_nanos()
    );
    let object_url = format!("{}/{}", cfg.base_url, object_key);
    let body = format!("reqsign volcengine tos presign e2e: {object_key}");

    let put_req = signed_request(
        &ctx,
        &signer,
        &cfg.credential,
        Method::PUT,
        &object_url,
        body.clone(),
    )
    .await?;
    let put_resp = client
        .execute(put_req.try_into()?)
        .await
        .map_err(reqwest::Error::without_url)?;
    assert!(
        put_resp.status().is_success(),
        "presigned PUT should succeed, got {}",
        put_resp.status()
    );

    let get_req = signed_request(
        &ctx,
        &signer,
        &cfg.credential,
        Method::GET,
        &object_url,
        String::new(),
    )
    .await?;
    let get_resp = client
        .execute(get_req.try_into()?)
        .await
        .map_err(reqwest::Error::without_url)?;
    assert_eq!(StatusCode::OK, get_resp.status());
    let got = get_resp.text().await?;
    assert_eq!(body, got);

    let delete_req = signed_request(
        &ctx,
        &signer,
        &cfg.credential,
        Method::DELETE,
        &object_url,
        String::new(),
    )
    .await?;
    let delete_resp = client
        .execute(delete_req.try_into()?)
        .await
        .map_err(reqwest::Error::without_url)?;
    assert!(
        delete_resp.status().is_success(),
        "presigned DELETE should succeed, got {}",
        delete_resp.status()
    );

    let get_deleted_req = signed_request(
        &ctx,
        &signer,
        &cfg.credential,
        Method::GET,
        &object_url,
        String::new(),
    )
    .await?;
    let get_deleted_resp = client
        .execute(get_deleted_req.try_into()?)
        .await
        .map_err(reqwest::Error::without_url)?;
    assert_eq!(StatusCode::NOT_FOUND, get_deleted_resp.status());

    Ok(())
}

async fn signed_request(
    ctx: &Context,
    signer: &RequestSigner,
    credential: &Credential,
    method: Method,
    url: &str,
    body: String,
) -> Result<Request<String>> {
    let mut req = Request::new(body);
    *req.method_mut() = method;
    *req.uri_mut() = http::Uri::from_str(url)?;
    if !req.body().is_empty() {
        let content_sha256 = hex_sha256(req.body().as_bytes());
        req.headers_mut()
            .insert("x-tos-content-sha256", content_sha256.parse()?);
    }

    let (mut parts, body) = req.into_parts();
    signer
        .sign_request(
            ctx,
            &mut parts,
            Some(credential),
            Some(Duration::from_secs(300)),
        )
        .await?;

    Ok(Request::from_parts(parts, body))
}

struct IntegrationConfig {
    credential: Credential,
    region: String,
    base_url: String,
}

fn load_integration_config() -> Result<Option<IntegrationConfig>> {
    if !env_enabled("REQSIGN_VOLCENGINE_TOS_TEST") {
        return Ok(None);
    }

    let access_key_id = env::var("REQSIGN_VOLCENGINE_TOS_ACCESS_KEY")
        .context("REQSIGN_VOLCENGINE_TOS_ACCESS_KEY must be set")?;
    let secret_access_key = env::var("REQSIGN_VOLCENGINE_TOS_SECRET_KEY")
        .context("REQSIGN_VOLCENGINE_TOS_SECRET_KEY must be set")?;
    let bucket = env::var("REQSIGN_VOLCENGINE_TOS_BUCKET")
        .context("REQSIGN_VOLCENGINE_TOS_BUCKET must be set")?;
    let endpoint = env::var("REQSIGN_VOLCENGINE_TOS_ENDPOINT")
        .context("REQSIGN_VOLCENGINE_TOS_ENDPOINT must be set")?;
    let region = env::var("REQSIGN_VOLCENGINE_TOS_REGION")
        .ok()
        .or_else(|| region_from_endpoint(&endpoint))
        .context(
            "REQSIGN_VOLCENGINE_TOS_REGION must be set when region cannot be derived from endpoint",
        )?;

    let mut credential = Credential::new(&access_key_id, &secret_access_key);
    if let Ok(token) = env::var("REQSIGN_VOLCENGINE_TOS_SECURITY_TOKEN") {
        credential = credential.with_session_token(&token);
    }

    Ok(Some(IntegrationConfig {
        credential,
        region,
        base_url: base_url(&endpoint, &bucket),
    }))
}

fn env_enabled(key: &str) -> bool {
    matches!(
        env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("on") | Some("ON")
    )
}

fn base_url(endpoint: &str, bucket: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.contains(&format!("{bucket}.")) {
        endpoint.to_string()
    } else if let Some(rest) = endpoint.strip_prefix("https://") {
        format!("https://{bucket}.{rest}")
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        format!("http://{bucket}.{rest}")
    } else {
        format!("https://{bucket}.{endpoint}")
    }
}

fn region_from_endpoint(endpoint: &str) -> Option<String> {
    let host = endpoint
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| endpoint.trim_end_matches('/').strip_prefix("http://"))
        .unwrap_or(endpoint);

    host.strip_prefix("tos-")
        .and_then(|v| v.split('.').next())
        .map(str::to_string)
        .filter(|v| !v.is_empty())
}
