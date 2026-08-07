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

mod assume_role;
mod assume_role_with_web_identity;
mod cognito;
mod default;
mod ecs;
mod env;
mod imds;
#[cfg(not(target_arch = "wasm32"))]
mod process;
mod profile;
mod s3_access_grants;
mod s3_express;
#[cfg(not(target_arch = "wasm32"))]
mod sso;
mod r#static;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use reqsign_aws_v4::{Credential, EMPTY_STRING_SHA256, RequestSigner};
#[cfg(not(target_arch = "wasm32"))]
use reqsign_command_execute_tokio::TokioCommandExecute;
use reqsign_core::{Context, OsEnv, SignRequest, StaticEnv};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::collections::HashMap;

pub fn create_test_context() -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenvy::dotenv();

    let mut ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    #[cfg(not(target_arch = "wasm32"))]
    {
        ctx = ctx.with_command_execute(TokioCommandExecute);
    }

    ctx
}

pub fn create_test_context_with_env(envs: HashMap<String, String>) -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenvy::dotenv();

    // Get home directory from HOME environment variable if set
    let home_dir = std::env::var("HOME").ok().map(std::path::PathBuf::from);

    let mut ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    #[cfg(not(target_arch = "wasm32"))]
    {
        ctx = ctx.with_command_execute(TokioCommandExecute);
    }

    // StaticEnv overrides specific environment variables on top of OsEnv
    ctx.with_env(StaticEnv { home_dir, envs })
}

pub async fn assert_credentials_work(ctx: &Context, credential: &Credential) {
    if std::env::var("REQSIGN_AWS_V4_VALIDATE_CREDENTIALS").unwrap_or_default() != "on" {
        return;
    }

    let region = std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-west-1".to_string());
    let endpoint =
        format!("https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15");
    let request = Request::builder()
        .method(Method::GET)
        .uri(endpoint)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
        .body(Bytes::new())
        .expect("GetCallerIdentity request should be valid");
    let (mut parts, body) = request.into_parts();

    RequestSigner::new("sts", &region)
        .sign_request(ctx, &mut parts, Some(credential), None)
        .await
        .expect("GetCallerIdentity request should be signed");

    let response = ctx
        .http_send(Request::from_parts(parts, body))
        .await
        .expect("GetCallerIdentity should reach AWS STS");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GetCallerIdentity failed: {}",
        String::from_utf8_lossy(response.body())
    );
    assert!(
        response
            .body()
            .windows(b"<GetCallerIdentityResult".len())
            .any(|window| window == b"<GetCallerIdentityResult"),
        "GetCallerIdentity returned an unexpected response"
    );
}
