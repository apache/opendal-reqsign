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
use reqsign_azure_storage::{Credential, RequestSigner};
use reqsign_command_execute_tokio::TokioCommandExecute;
use reqsign_core::{Context, OsEnv, ProvideCredential, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

pub mod default;
pub mod env;
pub mod static_provider;

#[cfg(not(target_arch = "wasm32"))]
pub mod azure_cli;

#[cfg(not(target_arch = "wasm32"))]
pub mod client_certificate;

pub mod azure_pipelines;
pub mod client_secret;
pub mod imds;
pub mod workload_identity;

const EXPECTED_PROBE_BODY: &[u8] = b"reqsign-live-azure-ok\n";

pub fn live_context() -> Context {
    Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_command_execute(TokioCommandExecute)
        .with_env(OsEnv)
}

pub async fn assert_provider_reads_probe(
    provider: impl ProvideCredential<Credential = Credential> + 'static,
    ctx: Context,
) -> anyhow::Result<()> {
    let url = std::env::var("REQSIGN_AZURE_STORAGE_URL")
        .map_err(|_| anyhow::anyhow!("REQSIGN_AZURE_STORAGE_URL must be set"))?;
    let signer = Signer::new(ctx.clone(), provider, RequestSigner::new());
    let request = http::Request::get(url)
        .header("x-ms-version", "2023-11-03")
        .body(Bytes::new())?;
    let (mut parts, body) = request.into_parts();

    signer.sign(&mut parts, None).await?;
    let response = ctx
        .http_send(http::Request::from_parts(parts, body))
        .await?;

    anyhow::ensure!(
        response.status() == http::StatusCode::OK,
        "Azure Blob probe returned HTTP {}",
        response.status()
    );
    anyhow::ensure!(
        response.body().as_ref() == EXPECTED_PROBE_BODY,
        "Azure Blob probe returned an unexpected body"
    );
    Ok(())
}
