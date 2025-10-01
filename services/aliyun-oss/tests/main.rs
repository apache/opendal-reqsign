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
use std::str::FromStr;
use std::time::Duration;

use http::header::CONTENT_LENGTH;
use http::Request;
use http::StatusCode;
use log::{debug, warn};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqsign_aliyun_oss::{RequestSigner, StaticCredentialProvider};
use reqsign_core::Result;
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;

async fn init_signer() -> Option<(Context, Signer<reqsign_aliyun_oss::Credential>)> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
        || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
    {
        return None;
    }

    let context = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let access_key_id = env::var("REQSIGN_ALIYUN_OSS_ACCESS_KEY")
        .expect("env REQSIGN_ALIYUN_OSS_ACCESS_KEY must set");
    let access_key_secret = env::var("REQSIGN_ALIYUN_OSS_SECRET_KEY")
        .expect("env REQSIGN_ALIYUN_OSS_SECRET_KEY must set");

    let bucket =
        env::var("REQSIGN_ALIYUN_OSS_BUCKET").expect("env REQSIGN_ALIYUN_OSS_BUCKET must set");

    let loader = StaticCredentialProvider::new(&access_key_id, &access_key_secret);
    let builder = RequestSigner::new(&bucket);
    let signer = Signer::new(context.clone(), loader, builder);

    Some((context, signer))
}

#[tokio::test]
async fn test_get_object() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    debug!("got response: {resp:?}");
    debug!(
        "got response content: {}",
        resp.text()
            .await
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get response text")
                    .with_source(anyhow::Error::new(e))
            )?
    );
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_delete_objects() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new(
        r#"<Delete>
<Object>
 <Key>sample1.txt</Key>
 </Object>
 <Object>
   <Key>sample2.txt</Key>
 </Object>
 </Delete>"#,
    );
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = http::Uri::from_str(&format!("{url}/?delete"))?;
    req.headers_mut()
        .insert("CONTENT-MD5", "WOctCY1SS662e7ziElh4cw==".parse().unwrap());

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    debug!("got response: {resp:?}");
    debug!(
        "got response content: {}",
        resp.text()
            .await
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get response text")
                    .with_source(anyhow::Error::new(e))
            )?
    );
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_get_object_with_query_sign() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, Some(Duration::from_secs(3600)))
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    debug!("got response: {resp:?}");
    debug!(
        "got response content: {}",
        resp.text()
            .await
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get response text")
                    .with_source(anyhow::Error::new(e))
            )?
    );
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_special_characters() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("not-exist-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    debug!("got response: {resp:?}");
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_put_object_with_special_characters() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::PUT;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("put-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;
    req.headers_mut()
        .insert(CONTENT_LENGTH, 0.to_string().parse()?);

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    debug!("got response: {resp:?}");
    debug!(
        "got response content: {:?}",
        resp.text()
            .await
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get response text")
                    .with_source(anyhow::Error::new(e))
            )?
    );
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_list_bucket() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() =
        http::Uri::from_str(&format!("{url}?list-type=2&delimiter=/&encoding-type=url"))?;

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    debug!("got response: {resp:?}");
    debug!(
        "got response content: {}",
        resp.text()
            .await
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get response text")
                    .with_source(anyhow::Error::new(e))
            )?
    );
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_list_bucket_with_invalid_token() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let (_context, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}?list-type=2&delimiter=/&encoding-type=url&continuation-token={}",
        url,
        utf8_percent_encode("hello.txt", NON_ALPHANUMERIC)
    ))?;

    let req = {
        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {req:?}");

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    debug!("got response: {resp:?}");
    debug!(
        "got response content: {}",
        resp.text()
            .await
            .map_err(
                |e| reqsign_core::Error::unexpected("failed to get response text")
                    .with_source(anyhow::Error::new(e))
            )?
    );
    assert_eq!(StatusCode::BAD_REQUEST, status);
    Ok(())
}
