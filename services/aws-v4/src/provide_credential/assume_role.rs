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

use crate::constants::X_AMZ_CONTENT_SHA_256;
use crate::credential::Credential;
use crate::provide_credential::utils::{parse_sts_error, sts_endpoint};
use crate::EMPTY_STRING_SHA256;
use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de;
use reqsign_core::time::parse_rfc3339;
use reqsign_core::{Context, Error, ProvideCredential, Result, Signer};
use serde::Deserialize;
use std::fmt::Write;

/// AssumeRoleCredentialProvider will load credential via assume role.
#[derive(Debug)]
pub struct AssumeRoleCredentialProvider {
    // Role configuration
    role_arn: String,
    role_session_name: String,
    external_id: Option<String>,
    duration_seconds: Option<u32>,
    tags: Option<Vec<(String, String)>>,

    // MFA configuration
    serial_number: Option<String>,
    token_code: Option<String>,

    // STS configuration
    region: Option<String>,
    use_regional_sts_endpoint: bool,

    // Base credential provider
    sts_signer: Signer<Credential>,
}

impl AssumeRoleCredentialProvider {
    /// Create a new assume role loader.
    pub fn new(role_arn: String, sts_signer: Signer<Credential>) -> Self {
        Self {
            role_arn,
            role_session_name: "reqsign".to_string(),
            external_id: None,
            duration_seconds: Some(3600),
            tags: None,
            serial_number: None,
            token_code: None,
            region: None,
            use_regional_sts_endpoint: false,
            sts_signer,
        }
    }

    /// Set the role session name.
    pub fn with_role_session_name(mut self, name: String) -> Self {
        self.role_session_name = name;
        self
    }

    /// Set the external ID.
    pub fn with_external_id(mut self, id: String) -> Self {
        self.external_id = Some(id);
        self
    }

    /// Set the duration in seconds.
    pub fn with_duration_seconds(mut self, seconds: u32) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Set the tags.
    pub fn with_tags(mut self, tags: Vec<(String, String)>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Set the region.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Use regional STS endpoint.
    pub fn with_regional_sts_endpoint(mut self) -> Self {
        self.use_regional_sts_endpoint = true;
        self
    }

    /// Set MFA serial number.
    pub fn with_mfa_serial(mut self, serial_number: String) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    /// Set MFA token code.
    pub fn with_mfa_code(mut self, token_code: String) -> Self {
        self.token_code = Some(token_code);
        self
    }

    /// Create from environment variables.
    pub fn from_env(ctx: &Context, sts_signer: Signer<Credential>) -> Option<Self> {
        let role_arn = ctx.env_var("AWS_ROLE_ARN")?;
        let mut provider = Self::new(role_arn, sts_signer);

        if let Some(name) = ctx.env_var("AWS_ROLE_SESSION_NAME") {
            provider = provider.with_role_session_name(name);
        }

        if let Some(id) = ctx.env_var("AWS_EXTERNAL_ID") {
            provider = provider.with_external_id(id);
        }

        if let Some(region) = ctx.env_var("AWS_REGION") {
            provider = provider.with_region(region);
        }

        if ctx.env_var("AWS_STS_REGIONAL_ENDPOINTS") == Some("regional".to_string()) {
            provider = provider.with_regional_sts_endpoint();
        }

        Some(provider)
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let endpoint = sts_endpoint(self.region.as_deref(), self.use_regional_sts_endpoint)
            .map_err(|e| e.with_context(format!("role_arn: {}", self.role_arn)))?;

        // Construct request to AWS STS Service.
        let mut url = format!("https://{endpoint}/?Action=AssumeRole&RoleArn={}&Version=2011-06-15&RoleSessionName={}", self.role_arn, self.role_session_name);
        if let Some(external_id) = &self.external_id {
            write!(url, "&ExternalId={external_id}")
                .map_err(|e| Error::unexpected("failed to format URL").with_source(e))?;
        }
        if let Some(duration_seconds) = &self.duration_seconds {
            write!(url, "&DurationSeconds={duration_seconds}")
                .map_err(|e| Error::unexpected("failed to format URL").with_source(e))?;
        }
        if let Some(tags) = &self.tags {
            for (idx, (key, value)) in tags.iter().enumerate() {
                let tag_index = idx + 1;
                write!(
                    url,
                    "&Tags.member.{tag_index}.Key={key}&Tags.member.{tag_index}.Value={value}"
                )
                .map_err(|e| Error::unexpected("failed to format URL").with_source(e))?;
            }
        }
        if let Some(serial_number) = &self.serial_number {
            write!(url, "&SerialNumber={serial_number}")
                .map_err(|e| Error::unexpected("failed to format URL").with_source(e))?;
        }
        if let Some(token_code) = &self.token_code {
            write!(url, "&TokenCode={token_code}")
                .map_err(|e| Error::unexpected("failed to format URL").with_source(e))?;
        }

        let req = http::request::Request::builder()
            .method("GET")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            // Set content sha to empty string.
            .header(X_AMZ_CONTENT_SHA_256, EMPTY_STRING_SHA256)
            .body(Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build STS AssumeRole request")
                    .with_source(e)
                    .with_context(format!("role_arn: {}", self.role_arn))
                    .with_context(format!("endpoint: https://{endpoint}"))
            })?;

        let (mut parts, body) = req.into_parts();
        self.sts_signer.sign(&mut parts, None).await?;
        let req = http::Request::from_parts(parts, body);

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to send AssumeRole request to STS")
                .with_source(e)
                .with_context(format!("role_arn: {}", self.role_arn))
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
            return Err(
                parse_sts_error("AssumeRole", status, &content, request_id.as_deref())
                    .with_context(format!("role_arn: {}", self.role_arn))
                    .with_context(format!("session_name: {}", self.role_session_name)),
            );
        }

        let body = resp.into_body();
        let resp: AssumeRoleResponse = de::from_str(&body).map_err(|e| {
            Error::unexpected("failed to parse STS AssumeRole response")
                .with_source(e)
                .with_context(format!("response_length: {}", body.len()))
                .with_context(format!("role_arn: {}", self.role_arn))
        })?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration).map_err(|e| {
                Error::unexpected("failed to parse AssumeRole credential expiration")
                    .with_source(e)
                    .with_context(format!("expiration_value: {}", resp_cred.expiration))
                    .with_context(format!("role_arn: {}", self.role_arn))
            })?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResponse {
    #[serde(rename = "AssumeRoleResult")]
    result: AssumeRoleResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResult {
    credentials: AssumeRoleCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::de;

    #[test]
    fn test_parse_assume_role_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#;

        let resp: AssumeRoleResponse = de::from_str(content).expect("xml deserialize must success");

        assert_eq!(
            &resp.result.credentials.access_key_id,
            "ASIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
        );
        assert_eq!(
            resp.result.credentials.session_token.trim(),
            "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
        );
        assert_eq!(&resp.result.credentials.expiration, "2019-11-09T13:34:41Z");

        Ok(())
    }
}
