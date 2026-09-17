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

use crate::Credential;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, Result};
use std::collections::HashMap;
use std::time::Duration;

/// Load credential from Azure Instance Metadata Service (IMDS).
///
/// This loader attempts to retrieve an access token from the Azure Instance Metadata Service
/// which is available on Azure VMs and other Azure compute resources.
///
/// Reference: <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal,http#using-the-rest-protocol>
#[derive(Debug, Default, Clone)]
pub struct ImdsCredentialProvider {
    endpoint: Option<String>,
}

impl ImdsCredentialProvider {
    /// Create a new IMDS loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IMDS endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}
impl ProvideCredential for ImdsCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let token =
            get_access_token("https://storage.azure.com/", self.endpoint.as_deref(), ctx).await?;

        let expires_on = if token.expires_on.is_empty() {
            Timestamp::now() + Duration::from_secs(600)
        } else {
            // Azure IMDS returns expires_on as Unix timestamp (seconds since epoch)
            let timestamp = token.expires_on.parse::<i64>().map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse expires_on timestamp")
                    .with_source(e)
            })?;
            Timestamp::from_second(timestamp).map_err(|e| {
                reqsign_core::Error::unexpected(format!("invalid expires_on timestamp: {e}"))
            })?
        };

        Ok(Some(Credential::with_bearer_token(
            &token.access_token,
            Some(expires_on),
        )))
    }
}

#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_on: String,
}

async fn get_access_token(
    resource: &str,
    endpoint_override: Option<&str>,
    ctx: &Context,
) -> Result<AccessTokenResponse> {
    let envs = ctx.env_vars();
    let url = build_request_url(resource, endpoint_override, &envs);

    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri(&url)
        .header("Metadata", "true");

    // App Service exposes a secret header for its managed identity endpoint.
    if let Some(msi_secret) = envs.get("AZURE_MSI_SECRET").filter(|s| !s.is_empty()) {
        req = req.header("X-IDENTITY-HEADER", msi_secret);
    }

    let req = req.body(bytes::Bytes::new()).map_err(|e| {
        reqsign_core::Error::unexpected("failed to build IMDS request").with_source(e)
    })?;

    let resp = ctx.http_send(req).await?;

    if !resp.status().is_success() {
        return Err(
            reqsign_core::Error::credential_invalid("Azure IMDS token request failed")
                .with_context(format!("http_status: {}", resp.status())),
        );
    }

    let token: AccessTokenResponse = serde_json::from_slice(resp.body()).map_err(|e| {
        reqsign_core::Error::unexpected("failed to parse IMDS response").with_source(e)
    })?;
    Ok(token)
}

fn build_request_url(
    resource: &str,
    endpoint_override: Option<&str>,
    envs: &HashMap<String, String>,
) -> String {
    let endpoint = endpoint_override
        .filter(|endpoint| !endpoint.is_empty())
        .or_else(|| {
            envs.get("AZBLOB_ENDPOINT")
                .or_else(|| envs.get("AZURE_IMDS_ENDPOINT"))
                .filter(|e| !e.is_empty())
                .map(|s| s.as_str())
        })
        .unwrap_or("http://169.254.169.254/metadata/identity/oauth2/token");

    let mut query = form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("api-version", "2018-02-01")
        .append_pair("resource", resource);

    if let Some(object_id) = envs.get("AZURE_OBJECT_ID").filter(|s| !s.is_empty()) {
        query.append_pair("object_id", object_id);
    } else if let Some(client_id) = envs.get("AZURE_CLIENT_ID").filter(|s| !s.is_empty()) {
        query.append_pair("client_id", client_id);
    } else if let Some(msi_res_id) = envs
        .get("AZURE_MSI_RESOURCE_ID")
        .or_else(|| envs.get("AZURE_MSI_RES_ID"))
        .filter(|s| !s.is_empty())
    {
        query.append_pair("msi_res_id", msi_res_id);
    }

    format!("{endpoint}?{}", query.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redacted_real_imds_response() {
        let response = include_bytes!("../../tests/fixtures/imds_token_response.json");
        let parsed: AccessTokenResponse = serde_json::from_slice(response).unwrap();

        assert_eq!(parsed.access_token, "REDACTED");
        assert!(!parsed.expires_on.is_empty());
    }

    #[test]
    fn explicit_endpoint_and_managed_identity_resource_id_are_used() {
        let envs = HashMap::from([
            (
                "AZURE_IMDS_ENDPOINT".to_string(),
                "http://ignored.example/token".to_string(),
            ),
            (
                "AZURE_MSI_RESOURCE_ID".to_string(),
                "/subscriptions/0000/resourceGroups/test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test"
                    .to_string(),
            ),
        ]);

        let url = build_request_url(
            "https://storage.azure.com/",
            Some("http://configured.example/token"),
            &envs,
        );
        assert!(url.starts_with("http://configured.example/token?"));
        assert!(url.contains("resource=https%3A%2F%2Fstorage.azure.com%2F"));
        assert!(url.contains("msi_res_id=%2Fsubscriptions%2F0000%2F"));
    }
}
