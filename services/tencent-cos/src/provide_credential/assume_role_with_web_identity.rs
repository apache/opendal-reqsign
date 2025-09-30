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

use crate::constants::*;
use crate::Credential;
use async_trait::async_trait;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use log::debug;
use reqsign_core::time::{now, parse_rfc3339};
use reqsign_core::Result;
use reqsign_core::{Context, ProvideCredential};
use serde::{Deserialize, Serialize};

/// Loader that loads credential via AssumeRoleWithWebIdentity.
#[derive(Debug, Default, Clone)]
pub struct AssumeRoleWithWebIdentityCredentialProvider {}

impl AssumeRoleWithWebIdentityCredentialProvider {
    /// Create a new AssumeRoleWithWebIdentityCredentialProvider
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleWithWebIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Read environment variables at runtime
        let region = ctx
            .env_var(TENCENTCLOUD_REGION)
            .or_else(|| ctx.env_var(TKE_REGION));
        let token_file = ctx
            .env_var(TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE)
            .or_else(|| ctx.env_var(TKE_IDENTITY_TOKEN_FILE));
        let role_arn = ctx
            .env_var(TENCENTCLOUD_ROLE_ARN)
            .or_else(|| ctx.env_var(TKE_ROLE_ARN));
        let provider_id = ctx
            .env_var(TENCENTCLOUD_PROVIDER_ID)
            .or_else(|| ctx.env_var(TKE_PROVIDER_ID));
        let role_session_name = ctx
            .env_var(TENCENTCLOUD_ROLE_SESSSION_NAME)
            .or_else(|| ctx.env_var(TKE_ROLE_SESSSION_NAME))
            .unwrap_or_else(|| "reqsign".to_string());

        let (region, token_file, role_arn, provider_id) =
            match (region, token_file, role_arn, provider_id) {
                (Some(region), Some(token_file), Some(role_arn), Some(provider_id)) => {
                    (region, token_file, role_arn, provider_id)
                }
                (region, token_file, role_arn, provider_id) => {
                    let missing = [
                        ("region", region.is_none()),
                        ("web_identity_token_file", token_file.is_none()),
                        ("role_arn", role_arn.is_none()),
                        ("provider_id", provider_id.is_none()),
                    ]
                    .iter()
                    .filter_map(|&(k, v)| if v { Some(k) } else { None })
                    .collect::<Vec<_>>()
                    .join(", ");

                    debug!(
                    "assume_role_with_web_identity is not configured fully: [{missing}] is missing"
                );

                    return Ok(None);
                }
            };

        let token = ctx.file_read_as_string(&token_file).await?;

        // Construct request to Tencent Cloud STS Service.
        let url = "https://sts.tencentcloudapi.com";
        let bs = serde_json::to_vec(&AssumeRoleWithWebIdentityRequest {
            role_session_name,
            web_identity_token: token,
            role_arn: role_arn.clone(),
            provider_id: provider_id.clone(),
        })
        .map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to serialize request: {e}"))
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(AUTHORIZATION.as_str(), "SKIP")
            .header(CONTENT_TYPE.as_str(), "application/json")
            .header(CONTENT_LENGTH, bs.len())
            .header("X-TC-Action", "AssumeRoleWithWebIdentity")
            .header("X-TC-Region", &region)
            .header("X-TC-Timestamp", now().as_second())
            .header("X-TC-Version", "2018-08-13")
            .body(bs.into())?;

        let resp = ctx.http_send(req).await?;
        let status = resp.status();
        let body = resp.into_body();

        if status != http::StatusCode::OK {
            return Err(reqsign_core::Error::unexpected(format!(
                "request to Tencent Cloud STS Services failed: {}",
                String::from_utf8_lossy(&body)
            )));
        }

        let resp: AssumeRoleWithWebIdentityResult = serde_json::from_slice(&body).map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to parse STS response: {e}"))
        })?;
        if let Some(error) = resp.response.error {
            return Err(reqsign_core::Error::unexpected(format!(
                "request to Tencent Cloud STS Services failed: {error:?}"
            )));
        }
        let resp_expiration = resp.response.expiration;
        let resp_cred = resp.response.credentials;

        let cred = Credential {
            secret_id: resp_cred.tmp_secret_id,
            secret_key: resp_cred.tmp_secret_key,
            security_token: Some(resp_cred.token),
            expires_in: Some(parse_rfc3339(&resp_expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityRequest {
    role_session_name: String,
    web_identity_token: String,
    role_arn: String,
    provider_id: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    response: AssumeRoleWithWebIdentityResponse,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    error: Option<AssumeRoleWithWebIdentityError>,
    expiration: String,
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    token: String,
    tmp_secret_id: String,
    tmp_secret_key: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityError {
    code: String,
    message: String,
}
