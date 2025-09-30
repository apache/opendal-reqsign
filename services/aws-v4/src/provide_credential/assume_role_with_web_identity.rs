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

use crate::provide_credential::utils::{parse_sts_error, sts_endpoint};
use crate::Credential;
use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de;
use reqsign_core::time::parse_rfc3339;
use reqsign_core::{utils::Redact, Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};
use std::path::PathBuf;

/// AssumeRoleWithWebIdentityCredentialProvider will load credential via assume role with web identity.
///
/// This provider reads configuration from:
/// 1. Constructor parameters (if provided)
/// 2. Environment variables (when constructor parameters are not set)
#[derive(Debug, Default, Clone)]
pub struct AssumeRoleWithWebIdentityCredentialProvider {
    // Web Identity configuration
    role_arn: Option<String>,
    role_session_name: Option<String>,
    web_identity_token_file: Option<PathBuf>,

    // STS configuration
    region: Option<String>,
    use_regional_sts_endpoint: Option<bool>,
}

impl AssumeRoleWithWebIdentityCredentialProvider {
    /// Create a new `AssumeRoleWithWebIdentityCredentialProvider` instance that reads from environment variables.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `AssumeRoleWithWebIdentityCredentialProvider` instance with explicit configuration.
    pub fn with_config(role_arn: String, token_file: PathBuf) -> Self {
        Self {
            role_arn: Some(role_arn),
            role_session_name: None,
            web_identity_token_file: Some(token_file),
            region: None,
            use_regional_sts_endpoint: None,
        }
    }

    /// Set the role ARN.
    pub fn with_role_arn(mut self, role_arn: impl Into<String>) -> Self {
        self.role_arn = Some(role_arn.into());
        self
    }

    /// Set the web identity token file path.
    pub fn with_web_identity_token_file(mut self, token_file: impl Into<PathBuf>) -> Self {
        self.web_identity_token_file = Some(token_file.into());
        self
    }

    /// Set the role session name.
    pub fn with_role_session_name(mut self, name: String) -> Self {
        self.role_session_name = Some(name);
        self
    }

    /// Set the region.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Use regional STS endpoint.
    pub fn with_regional_sts_endpoint(mut self) -> Self {
        self.use_regional_sts_endpoint = Some(true);
        self
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleWithWebIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        // Get role_arn from config or environment
        let role_arn = self
            .role_arn
            .as_ref()
            .or_else(|| envs.get("AWS_ROLE_ARN"))
            .cloned();

        // Get token file from config or environment
        let token_file = self
            .web_identity_token_file
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| envs.get("AWS_WEB_IDENTITY_TOKEN_FILE").cloned());

        // If either is missing, we can't proceed
        let (role_arn, token_file) = match (role_arn, token_file) {
            (Some(arn), Some(file)) => (arn, file),
            _ => return Ok(None),
        };

        let token = ctx.file_read_as_string(&token_file).await.map_err(|e| {
            Error::config_invalid("failed to read web identity token file")
                .with_source(e)
                .with_context(format!("file: {token_file}"))
                .with_context("hint: check if the token file exists and is readable")
        })?;

        // Get region from config or environment
        let region = self
            .region
            .as_ref()
            .or_else(|| envs.get("AWS_REGION"))
            .cloned();

        // Check if we should use regional STS endpoint
        let use_regional = self.use_regional_sts_endpoint.unwrap_or_else(|| {
            envs.get("AWS_STS_REGIONAL_ENDPOINTS")
                .map(|v| v == "regional")
                .unwrap_or(false)
        });

        let endpoint = sts_endpoint(region.as_deref(), use_regional)
            .map_err(|e| e.with_context(format!("role_arn: {role_arn}")))?;

        // Get session name from config or environment or use default
        let session_name = self
            .role_session_name
            .as_ref()
            .or_else(|| envs.get("AWS_ROLE_SESSION_NAME"))
            .cloned()
            .unwrap_or_else(|| "reqsign".to_string());

        // Construct request to AWS STS Service.
        let url = format!("https://{endpoint}/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={session_name}");
        let req = http::request::Request::builder()
            .method("GET")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .body(Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build STS AssumeRoleWithWebIdentity request")
                    .with_source(e)
                    .with_context(format!("role_arn: {role_arn}"))
                    .with_context(format!("endpoint: https://{endpoint}"))
            })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to send AssumeRoleWithWebIdentity request to STS")
                .with_source(e)
                .with_context(format!("role_arn: {role_arn}"))
                .with_context(format!("endpoint: https://{endpoint}"))
                .set_retryable(true)
        })?;

        // Extract request ID and status before consuming response
        let status = resp.status();
        let request_id = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if status != http::StatusCode::OK {
            let content = resp.into_body();
            return Err(parse_sts_error(
                "AssumeRoleWithWebIdentity",
                status,
                &content,
                request_id.as_deref(),
            )
            .with_context(format!("role_arn: {role_arn}"))
            .with_context(format!("session_name: {session_name}"))
            .with_context(format!("token_file: {token_file}")));
        }

        let body = resp.into_body();
        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&body).map_err(|e| {
            Error::unexpected("failed to parse STS AssumeRoleWithWebIdentity response")
                .with_source(e)
                .with_context(format!("response_length: {}", body.len()))
                .with_context(format!("role_arn: {role_arn}"))
        })?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration).map_err(|e| {
                Error::unexpected("failed to parse web identity credential expiration")
                    .with_source(e)
                    .with_context(format!("expiration_value: {}", resp_cred.expiration))
                    .with_context(format!("role_arn: {role_arn}"))
            })?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

impl Debug for AssumeRoleWithWebIdentityCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleWithWebIdentityCredentials")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("secret_access_key", &Redact::from(&self.secret_access_key))
            .field("session_token", &Redact::from(&self.session_token))
            .field("expiration", &self.expiration)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }
}
