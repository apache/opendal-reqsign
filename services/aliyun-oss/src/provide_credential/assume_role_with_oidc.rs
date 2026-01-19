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

use crate::{Credential, constants::*};
use async_trait::async_trait;
use form_urlencoded::Serializer;
use reqsign_core::Result;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential};
use serde::Deserialize;

/// AssumeRoleWithOidcCredentialProvider loads credential via assume role with OIDC.
///
/// This provider reads configuration from environment variables at runtime:
/// - `ALIBABA_CLOUD_ROLE_ARN`: The ARN of the role to assume
/// - `ALIBABA_CLOUD_ROLE_SESSION_NAME`: Optional role session name
/// - `ALIBABA_CLOUD_OIDC_PROVIDER_ARN`: The ARN of the OIDC provider
/// - `ALIBABA_CLOUD_OIDC_TOKEN_FILE`: Path to the OIDC token file
/// - `ALIBABA_CLOUD_STS_ENDPOINT`: Optional custom STS endpoint
#[derive(Debug, Default, Clone)]
pub struct AssumeRoleWithOidcCredentialProvider {
    sts_endpoint: Option<String>,
    role_session_name: Option<String>,
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

    /// Set the role session name.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_ROLE_SESSION_NAME`.
    pub fn with_role_session_name(mut self, name: impl Into<String>) -> Self {
        self.role_session_name = Some(name.into());
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

    fn get_role_session_name(&self, envs: &std::collections::HashMap<String, String>) -> String {
        if let Some(name) = &self.role_session_name {
            return name.clone();
        }

        envs.get(ALIBABA_CLOUD_ROLE_SESSION_NAME)
            .cloned()
            .unwrap_or_else(|| "reqsign".to_string())
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

        let token = ctx.file_read_as_string(token_file).await?;
        let token = token.trim();
        let role_session_name = self.get_role_session_name(&envs);

        // Construct request to Aliyun STS Service.
        let query = Serializer::new(String::new())
            .append_pair("Action", "AssumeRoleWithOIDC")
            .append_pair("OIDCProviderArn", provider_arn)
            .append_pair("RoleArn", role_arn)
            .append_pair("RoleSessionName", &role_session_name)
            .append_pair("Format", "JSON")
            .append_pair("Version", "2015-04-01")
            .append_pair("Timestamp", &Timestamp::now().format_rfc3339_zulu())
            .append_pair("OIDCToken", token)
            .finish();
        let url = format!("{}/?{query}", self.get_sts_endpoint(&envs));

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
            expires_in: Some(resp_cred.expiration.parse()?),
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
    use async_trait::async_trait;
    use bytes::Bytes;
    use reqsign_core::StaticEnv;
    use reqsign_core::{Context, FileRead, HttpSend};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

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

    #[derive(Debug)]
    struct TestFileRead {
        expected_path: String,
        content: Vec<u8>,
    }

    #[async_trait]
    impl FileRead for TestFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            assert_eq!(path, self.expected_path);
            Ok(self.content.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct CaptureHttpSend {
        uri: Arc<Mutex<Option<String>>>,
        body: String,
    }

    impl CaptureHttpSend {
        fn new(body: impl Into<String>) -> Self {
            Self {
                uri: Arc::new(Mutex::new(None)),
                body: body.into(),
            }
        }

        fn uri(&self) -> Option<String> {
            self.uri.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpSend for CaptureHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            *self.uri.lock().unwrap() = Some(req.uri().to_string());
            let resp = http::Response::builder()
                .status(http::StatusCode::OK)
                .body(Bytes::from(self.body.clone()))
                .expect("response must build");
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_assume_role_with_oidc_supports_role_session_name() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let token_path = "/mock/token";
        let raw_token = "header.payload.signature\n";

        let file_read = TestFileRead {
            expected_path: token_path.to_string(),
            content: raw_token.as_bytes().to_vec(),
        };

        let http_body = r#"{"Credentials":{"SecurityToken":"security_token","Expiration":"2124-05-25T11:45:17Z","AccessKeySecret":"secret_access_key","AccessKeyId":"access_key_id"}}"#;
        let http_send = CaptureHttpSend::new(http_body);

        let ctx = Context::new()
            .with_file_read(file_read)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from_iter([
                    (
                        ALIBABA_CLOUD_OIDC_TOKEN_FILE.to_string(),
                        token_path.to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_ROLE_ARN.to_string(),
                        "acs:ram::123456789012:role/test-role".to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_OIDC_PROVIDER_ARN.to_string(),
                        "acs:ram::123456789012:oidc-provider/test-provider".to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_ROLE_SESSION_NAME.to_string(),
                        "my-session".to_string(),
                    ),
                ]),
            });

        let provider = AssumeRoleWithOidcCredentialProvider::new();
        let cred = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        assert_eq!(cred.access_key_id, "access_key_id");
        assert_eq!(cred.access_key_secret, "secret_access_key");
        assert_eq!(cred.security_token.as_deref(), Some("security_token"));

        let recorded_uri = http_send
            .uri()
            .expect("http_send must capture outgoing uri");
        let uri: http::Uri = recorded_uri.parse().expect("uri must parse");
        let query = uri.query().expect("query must exist");
        let params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            params.get("RoleSessionName").map(String::as_str),
            Some("my-session")
        );
        assert_eq!(
            params.get("OIDCToken").map(String::as_str),
            Some("header.payload.signature")
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_assume_role_with_oidc_role_session_name_overrides_env() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let token_path = "/mock/token";

        let file_read = TestFileRead {
            expected_path: token_path.to_string(),
            content: b"token".to_vec(),
        };

        let http_body = r#"{"Credentials":{"SecurityToken":"security_token","Expiration":"2124-05-25T11:45:17Z","AccessKeySecret":"secret_access_key","AccessKeyId":"access_key_id"}}"#;
        let http_send = CaptureHttpSend::new(http_body);

        let ctx = Context::new()
            .with_file_read(file_read)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from_iter([
                    (
                        ALIBABA_CLOUD_OIDC_TOKEN_FILE.to_string(),
                        token_path.to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_ROLE_ARN.to_string(),
                        "acs:ram::123456789012:role/test-role".to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_OIDC_PROVIDER_ARN.to_string(),
                        "acs:ram::123456789012:oidc-provider/test-provider".to_string(),
                    ),
                    (
                        ALIBABA_CLOUD_ROLE_SESSION_NAME.to_string(),
                        "env-session".to_string(),
                    ),
                ]),
            });

        let provider =
            AssumeRoleWithOidcCredentialProvider::new().with_role_session_name("override-session");
        let _ = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        let recorded_uri = http_send
            .uri()
            .expect("http_send must capture outgoing uri");
        let uri: http::Uri = recorded_uri.parse().expect("uri must parse");
        let query = uri.query().expect("query must exist");
        let params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            params.get("RoleSessionName").map(String::as_str),
            Some("override-session")
        );

        Ok(())
    }
}
