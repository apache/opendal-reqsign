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

use crate::{constants::*, Credential};
use async_trait::async_trait;
use reqsign_core::time::{format_rfc3339, now, parse_rfc3339};
use reqsign_core::Result;
use reqsign_core::{Context, ProvideCredential};
use serde::Deserialize;

/// AssumeRoleWithOidcCredentialProvider loads credential via assume role with OIDC.
///
/// This provider reads configuration from environment variables at runtime:
/// - `ALIBABA_CLOUD_ROLE_ARN`: The ARN of the role to assume
/// - `ALIBABA_CLOUD_OIDC_PROVIDER_ARN`: The ARN of the OIDC provider
/// - `ALIBABA_CLOUD_OIDC_TOKEN_FILE`: Path to the OIDC token file
/// - `ALIBABA_CLOUD_STS_ENDPOINT`: Optional custom STS endpoint
#[derive(Debug, Default, Clone)]
pub struct AssumeRoleWithOidcCredentialProvider {
    sts_endpoint: Option<String>,
}

impl AssumeRoleWithOidcCredentialProvider {
    /// Create a new `AssumeRoleWithOidcCredentialProvider` instance.
    /// This will read configuration from environment variables at runtime.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the STS endpoint.
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = Some(endpoint.into());
        self
    }

    fn get_sts_endpoint(&self, envs: &std::collections::HashMap<String, String>) -> String {
        if let Some(endpoint) = &self.sts_endpoint {
            return endpoint.clone();
        }

        match envs.get(ALIBABA_CLOUD_STS_ENDPOINT) {
            Some(endpoint) => format!("https://{endpoint}"),
            None => "https://sts.aliyuncs.com".to_string(),
        }
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleWithOidcCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        // Get values from environment variables
        let token_file = envs.get(ALIBABA_CLOUD_OIDC_TOKEN_FILE);
        let role_arn = envs.get(ALIBABA_CLOUD_ROLE_ARN);
        let provider_arn = envs.get(ALIBABA_CLOUD_OIDC_PROVIDER_ARN);

        let (token_file, role_arn, provider_arn) = match (token_file, role_arn, provider_arn) {
            (Some(tf), Some(ra), Some(pa)) => (tf, ra, pa),
            _ => return Ok(None),
        };

        let token = ctx.file_read(token_file).await?;
        let token = String::from_utf8(token)?;
        let role_session_name = "reqsign"; // Default session name

        // Construct request to Aliyun STS Service.
        let url = format!(
            "{}/?Action=AssumeRoleWithOIDC&OIDCProviderArn={}&RoleArn={}&RoleSessionName={}&Format=JSON&Version=2015-04-01&Timestamp={}&OIDCToken={}",
            self.get_sts_endpoint(&envs),
            provider_arn,
            role_arn,
            role_session_name,
            format_rfc3339(now()),
            token
        );

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Vec::new())?;

        let resp = ctx.http_send(req.map(|body| body.into())).await?;

        if resp.status() != http::StatusCode::OK {
            let content = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "request to Aliyun STS Services failed: {content}"
            )));
        }

        let resp: AssumeRoleWithOidcResponse =
            serde_json::from_slice(resp.body()).map_err(|e| {
                reqsign_core::Error::unexpected(format!("Failed to parse STS response: {e}"))
            })?;
        let resp_cred = resp.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            access_key_secret: resp_cred.access_key_secret,
            security_token: Some(resp_cred.security_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default)]
struct AssumeRoleWithOidcResponse {
    #[serde(rename = "Credentials")]
    credentials: AssumeRoleWithOidcCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithOidcCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[test]
    fn test_parse_assume_role_with_oidc_response() -> Result<()> {
        let content = r#"{
    "RequestId": "3D57EAD2-8723-1F26-B69C-F8707D8B565D",
    "OIDCTokenInfo": {
        "Subject": "KryrkIdjylZb7agUgCEf****",
        "Issuer": "https://dev-xxxxxx.okta.com",
        "ClientIds": "496271242565057****"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "33157794895460****",
        "Arn": "acs:ram::113511544585****:role/testoidc/TestOidcAssumedRoleSession"
    },
    "Credentials": {
        "SecurityToken": "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****",
        "Expiration": "2021-10-20T04:27:09Z",
        "AccessKeySecret": "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****",
        "AccessKeyId": "STS.NUgYrLnoC37mZZCNnAbez****"
    }
}"#;

        let resp: AssumeRoleWithOidcResponse =
            serde_json::from_str(content).expect("json deserialize must success");

        assert_eq!(
            &resp.credentials.access_key_id,
            "STS.NUgYrLnoC37mZZCNnAbez****"
        );
        assert_eq!(
            &resp.credentials.access_key_secret,
            "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****"
        );
        assert_eq!(
            &resp.credentials.security_token,
            "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****"
        );
        assert_eq!(&resp.credentials.expiration, "2021-10-20T04:27:09Z");

        Ok(())
    }

    #[tokio::test]
    async fn test_assume_role_with_oidc_loader_without_config() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let loader = AssumeRoleWithOidcCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }
}
