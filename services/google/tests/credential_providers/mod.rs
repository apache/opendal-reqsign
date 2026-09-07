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

mod authorized_user;
mod default;
mod env;
mod external_account;
mod file;
mod impersonated_service_account;
mod service_account_impersonation;
mod static_provider;
mod token;
mod vm_metadata;

use bytes::Bytes;
use reqsign_core::{Context, Error, OsEnv, ProvideCredential, Signer, StaticEnv};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_google::{Credential, RequestSigner};
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::collections::HashMap;

const EXPECTED_PROBE_BODY: &[u8] = b"reqsign-live-google-ok\n";

pub fn create_test_context() -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenvy::dotenv();

    Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv)
}

pub fn create_test_context_with_env(mut envs: HashMap<String, String>) -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenvy::dotenv();

    let home_dir = std::env::var("HOME").ok().map(std::path::PathBuf::from);
    if let Some(home) = &home_dir {
        envs.entry("HOME".to_string())
            .or_insert_with(|| home.to_string_lossy().into_owned());
    }

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    ctx.with_env(StaticEnv { home_dir, envs })
}

pub async fn assert_provider_reads_probe(
    provider: impl ProvideCredential<Credential = Credential> + 'static,
    ctx: Context,
) -> reqsign_core::Result<()> {
    let url = std::env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_PROBE_URL")
        .map_err(|_| Error::unexpected("REQSIGN_GOOGLE_CLOUD_STORAGE_PROBE_URL must be set"))?;
    let scope = std::env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_only".to_string());
    let signer = Signer::new(
        ctx.clone(),
        provider,
        RequestSigner::new("storage").with_scope(scope),
    );
    let request = http::Request::get(url).body(Bytes::new()).map_err(|err| {
        Error::unexpected("failed to build Google Cloud Storage probe request").with_source(err)
    })?;
    let (mut parts, body) = request.into_parts();

    signer.sign(&mut parts, None).await?;
    let response = ctx
        .http_send(http::Request::from_parts(parts, body))
        .await?;

    if response.status() != http::StatusCode::OK {
        return Err(Error::unexpected(format!(
            "Google Cloud Storage probe returned HTTP {}",
            response.status()
        )));
    }
    if response.body().as_ref() != EXPECTED_PROBE_BODY {
        return Err(Error::unexpected(
            "Google Cloud Storage probe returned an unexpected body",
        ));
    }
    Ok(())
}
