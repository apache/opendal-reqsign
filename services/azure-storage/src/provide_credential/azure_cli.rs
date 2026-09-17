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

use crate::credential::Credential;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential};
use serde::Deserialize;

/// AzureCliCredentialProvider provides credentials from Azure CLI
///
/// This provider reads tokens from Azure CLI's local storage or invokes
/// `az account get-access-token` to retrieve fresh tokens.
#[derive(Clone, Debug, Default)]
pub struct AzureCliCredentialProvider {}

impl AzureCliCredentialProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute `az account get-access-token` command
    async fn get_access_token_from_cli(
        &self,
        ctx: &Context,
        resource: &str,
    ) -> Result<AzureCliToken, reqsign_core::Error> {
        let args = [
            "account",
            "get-access-token",
            "--resource",
            resource,
            "--output",
            "json",
        ];

        let output = ctx.command_execute("az", &args).await?;

        if !output.success() {
            return Err(reqsign_core::Error::credential_invalid(format!(
                "Azure CLI command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let token: AzureCliToken = serde_json::from_slice(&output.stdout).map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to parse Azure CLI output: {e}"))
        })?;

        Ok(token)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureCliToken {
    access_token: String,
    expires_on: Option<String>,
    #[serde(rename = "expires_on")]
    expires_on_timestamp: Option<i64>,
    #[allow(dead_code)]
    subscription: Option<String>,
    #[allow(dead_code)]
    tenant: Option<String>,
    #[allow(dead_code)]
    token_type: String,
}
impl ProvideCredential for AzureCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(
        &self,
        ctx: &Context,
    ) -> Result<Option<Self::Credential>, reqsign_core::Error> {
        // For Azure Storage, we need the storage resource
        let resource = "https://storage.azure.com/";

        // Try to get access token from Azure CLI
        let token = self.get_access_token_from_cli(ctx, resource).await?;

        // Calculate expiration time
        let expires_on = if let Some(timestamp) = token.expires_on_timestamp {
            Timestamp::from_second(timestamp).ok()
        } else if let Some(expires_str) = token.expires_on {
            Timestamp::parse_datetime_utc(&expires_str).ok()
        } else {
            None
        };

        Ok(Some(Credential::with_bearer_token(
            &token.access_token,
            expires_on,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redacted_real_azure_cli_response() {
        let response = include_bytes!("../../tests/fixtures/azure_cli_token_response.json");
        let token: AzureCliToken = serde_json::from_slice(response).unwrap();
        assert_eq!(token.access_token, "REDACTED");
        assert_eq!(token.expires_on_timestamp, Some(1788423131));
        assert_eq!(token.token_type, "Bearer");
    }
}
