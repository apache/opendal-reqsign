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

use crate::provide_credential::{
    ConfigFileCredentialProvider, CredentialsFileCredentialProvider, EnvCredentialProvider,
    OssProfileCredentialProvider,
};
use crate::{Credential, constants::*};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static ALIYUN_RPC_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
static SIGNATURE_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// AssumeRoleCredentialProvider loads credentials via Alibaba Cloud STS AssumeRole.
///
/// `new()` reads role configuration from environment variables at runtime and
/// resolves the base access key credential from the default static chain:
/// env -> OSS profile -> shared credentials file -> config file.
///
/// Use `with_base_provider(...)` to make the base credential source explicit and
/// to avoid depending on the default static chain.
#[derive(Debug, Clone)]
pub struct AssumeRoleCredentialProvider {
    base_provider: Arc<dyn ProvideCredentialDyn<Credential = Credential>>,
    uses_default_base_provider: bool,
    role_arn: Option<String>,
    role_session_name: Option<String>,
    external_id: Option<String>,
    sts_endpoint: Option<String>,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    signature_nonce: Option<String>,
}

impl Default for AssumeRoleCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AssumeRoleCredentialProvider {
    /// Create a new `AssumeRoleCredentialProvider` instance.
    ///
    /// This provider reads role configuration from environment variables at
    /// runtime. The base access key credential is loaded from the default
    /// static chain unless overridden with `with_base_provider(...)`.
    pub fn new() -> Self {
        Self {
            base_provider: Arc::new(default_base_provider_chain()),
            uses_default_base_provider: true,
            role_arn: None,
            role_session_name: None,
            external_id: None,
            sts_endpoint: None,
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            signature_nonce: None,
        }
    }

    /// Set the base credential provider used to call STS.
    ///
    /// This source must yield an access key ID and access key secret. When set,
    /// the provider no longer depends on the default static chain.
    pub fn with_base_provider(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.base_provider = Arc::new(provider);
        self.uses_default_base_provider = false;
        self
    }

    /// Set the role ARN.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_ROLE_ARN`.
    pub fn with_role_arn(mut self, role_arn: impl Into<String>) -> Self {
        self.role_arn = Some(role_arn.into());
        self
    }

    /// Set the role session name.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_ROLE_SESSION_NAME`.
    pub fn with_role_session_name(mut self, name: impl Into<String>) -> Self {
        self.role_session_name = Some(name.into());
        self
    }

    /// Set the external ID.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_EXTERNAL_ID`.
    pub fn with_external_id(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Set the STS endpoint.
    ///
    /// This setting takes precedence over `ALIBABA_CLOUD_STS_ENDPOINT`.
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = Some(endpoint.into());
        self
    }

    pub(crate) fn with_default_base_provider(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        if self.uses_default_base_provider {
            self.base_provider = Arc::new(provider);
        }
        self
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    #[cfg(test)]
    fn with_signature_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.signature_nonce = Some(nonce.into());
        self
    }

    fn get_role_arn(&self, envs: &HashMap<String, String>) -> Option<String> {
        self.role_arn
            .clone()
            .or_else(|| envs.get(ALIBABA_CLOUD_ROLE_ARN).cloned())
    }

    fn get_role_session_name(&self, envs: &HashMap<String, String>) -> String {
        self.role_session_name
            .clone()
            .or_else(|| envs.get(ALIBABA_CLOUD_ROLE_SESSION_NAME).cloned())
            .unwrap_or_else(|| "reqsign".to_string())
    }

    fn get_external_id(&self, envs: &HashMap<String, String>) -> Option<String> {
        self.external_id
            .clone()
            .or_else(|| envs.get(ALIBABA_CLOUD_EXTERNAL_ID).cloned())
    }

    fn get_sts_endpoint(&self, envs: &HashMap<String, String>) -> String {
        if let Some(endpoint) = &self.sts_endpoint {
            return endpoint.clone();
        }

        match envs.get(ALIBABA_CLOUD_STS_ENDPOINT) {
            Some(endpoint) => format!("https://{endpoint}"),
            None => "https://sts.aliyuncs.com".to_string(),
        }
    }

    fn get_time(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }

        Timestamp::now()
    }

    fn get_signature_nonce(&self, signing_time: Timestamp) -> String {
        #[cfg(test)]
        if let Some(nonce) = &self.signature_nonce {
            return nonce.clone();
        }

        let counter = SIGNATURE_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}-{}-{counter}",
            signing_time.as_second(),
            signing_time.subsec_nanosecond()
        )
    }
}

impl ProvideCredential for AssumeRoleCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        let Some(role_arn) = self.get_role_arn(&envs) else {
            return Ok(None);
        };

        let Some(base_credential) = self.base_provider.provide_credential_dyn(ctx).await? else {
            return Ok(None);
        };
        if base_credential.access_key_id.is_empty() || base_credential.access_key_secret.is_empty()
        {
            return Ok(None);
        }

        let signing_time = self.get_time();
        let signature_nonce = self.get_signature_nonce(signing_time);
        let role_session_name = self.get_role_session_name(&envs);

        let mut params = BTreeMap::new();
        params.insert(
            "AccessKeyId".to_string(),
            base_credential.access_key_id.clone(),
        );
        params.insert("Action".to_string(), "AssumeRole".to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("RoleArn".to_string(), role_arn);
        params.insert("RoleSessionName".to_string(), role_session_name);
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureNonce".to_string(), signature_nonce);
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("Timestamp".to_string(), signing_time.format_rfc3339_zulu());
        params.insert("Version".to_string(), "2015-04-01".to_string());

        if let Some(external_id) = self.get_external_id(&envs) {
            params.insert("ExternalId".to_string(), external_id);
        }
        if let Some(token) = &base_credential.security_token {
            params.insert("SecurityToken".to_string(), token.clone());
        }

        let canonicalized_query_string = canonicalized_query_string(&params);
        let string_to_sign = format!(
            "GET&%2F&{}",
            percent_encode_query_value(&canonicalized_query_string)
        );
        let signature = base64_hmac_sha1(
            format!("{}&", base_credential.access_key_secret).as_bytes(),
            string_to_sign.as_bytes(),
        );

        let url = format!(
            "{}/?{}&Signature={}",
            self.get_sts_endpoint(&envs),
            canonicalized_query_string,
            percent_encode_query_value(&signature)
        );

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Vec::new())?;

        let resp = ctx.http_send(req.map(Into::into)).await?;
        if resp.status() != http::StatusCode::OK {
            let content = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "request to Aliyun STS Services failed: {content}"
            )));
        }

        let resp: AssumeRoleResponse = serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to parse STS response: {e}"))
        })?;
        let resp_cred = resp.credentials;

        Ok(Some(Credential {
            access_key_id: resp_cred.access_key_id,
            access_key_secret: resp_cred.access_key_secret,
            security_token: Some(resp_cred.security_token),
            expires_in: Some(resp_cred.expiration.parse()?),
        }))
    }
}

fn default_base_provider_chain() -> ProvideCredentialChain<Credential> {
    ProvideCredentialChain::new()
        .push(EnvCredentialProvider::new())
        .push(OssProfileCredentialProvider::new())
        .push(CredentialsFileCredentialProvider::new())
        .push(ConfigFileCredentialProvider::new())
}

fn canonicalized_query_string(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode_query_value(key),
                percent_encode_query_value(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode_query_value(value: &str) -> String {
    utf8_percent_encode(value, &ALIYUN_RPC_QUERY_ENCODE_SET).to_string()
}

#[derive(Default, Debug, Deserialize)]
#[serde(default)]
struct AssumeRoleResponse {
    #[serde(rename = "Credentials")]
    credentials: AssumeRoleCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestSigner;
    use bytes::Bytes;
    use reqsign_core::{Context, HttpSend, Signer, StaticEnv};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct TestBaseCredentialProvider {
        credential: Option<Credential>,
    }

    impl TestBaseCredentialProvider {
        fn new(credential: Option<Credential>) -> Self {
            Self { credential }
        }
    }

    impl ProvideCredential for TestBaseCredentialProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(self.credential.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct CaptureHttpSend {
        uri: Arc<Mutex<Option<String>>>,
        bodies: Arc<Vec<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
    }

    impl CaptureHttpSend {
        fn new(bodies: Vec<Vec<u8>>) -> Self {
            Self {
                uri: Arc::new(Mutex::new(None)),
                bodies: Arc::new(bodies),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn uri(&self) -> Option<String> {
            self.uri.lock().unwrap().clone()
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl HttpSend for CaptureHttpSend {
        async fn http_send(
            &self,
            req: http::Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            *self.uri.lock().unwrap() = Some(req.uri().to_string());
            let body = self
                .bodies
                .get(index)
                .cloned()
                .or_else(|| self.bodies.last().cloned())
                .unwrap_or_default();

            Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(Bytes::from(body))
                .expect("response must build"))
        }
    }

    #[test]
    fn test_parse_assume_role_response() -> Result<()> {
        let content = r#"{
    "RequestId": "3D57EAD2-8723-1F26-B69C-F8707D8B565D",
    "AssumedRoleUser": {
        "AssumedRoleId": "33157794895460****",
        "Arn": "acs:ram::113511544585****:role/test-role/test-session"
    },
    "Credentials": {
        "SecurityToken": "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****",
        "Expiration": "2021-10-20T04:27:09Z",
        "AccessKeySecret": "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****",
        "AccessKeyId": "STS.NUgYrLnoC37mZZCNnAbez****"
    }
}"#;

        let resp: AssumeRoleResponse =
            serde_json::from_str(content).expect("json deserialize must succeed");

        assert_eq!(
            resp.credentials.access_key_id,
            "STS.NUgYrLnoC37mZZCNnAbez****"
        );
        assert_eq!(
            resp.credentials.access_key_secret,
            "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****"
        );
        assert_eq!(
            resp.credentials.security_token,
            "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****"
        );
        assert_eq!(resp.credentials.expiration, "2021-10-20T04:27:09Z");

        Ok(())
    }

    #[tokio::test]
    async fn test_assume_role_loader_without_config() {
        let ctx = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let provider = AssumeRoleCredentialProvider::new();
        let credential = provider.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_assume_role_signs_query_with_explicit_base_provider() -> Result<()> {
        let base_credential = Credential {
            access_key_id: "base-ak".to_string(),
            access_key_secret: "base-sk".to_string(),
            security_token: Some("base-token".to_string()),
            expires_in: None,
        };
        let http_send = CaptureHttpSend::new(vec![
            br#"{"Credentials":{"SecurityToken":"sts-token","Expiration":"2124-05-25T11:45:17Z","AccessKeySecret":"sts-secret","AccessKeyId":"sts-ak"}}"#
                .to_vec(),
        ]);
        let ctx = Context::new()
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let signing_time: Timestamp = "2024-03-05T06:07:08Z".parse().unwrap();
        let provider = AssumeRoleCredentialProvider::new()
            .with_base_provider(TestBaseCredentialProvider::new(Some(
                base_credential.clone(),
            )))
            .with_role_arn("acs:ram::123456789012:role/test-role")
            .with_role_session_name("test-session")
            .with_external_id("external-id")
            .with_sts_endpoint("https://sts.example.com")
            .with_time(signing_time)
            .with_signature_nonce("test-nonce");

        let credential = provider.provide_credential(&ctx).await?.unwrap();
        assert_eq!("sts-ak", credential.access_key_id);
        assert_eq!("sts-secret", credential.access_key_secret);
        assert_eq!(Some("sts-token".to_string()), credential.security_token);

        let recorded_uri = http_send.uri().expect("request uri must be captured");
        let uri: http::Uri = recorded_uri.parse().expect("uri must parse");
        assert_eq!(
            "https://sts.example.com/",
            format!("https://{}{}", uri.authority().unwrap(), uri.path())
        );
        let query = uri.query().expect("query must exist");
        let params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            Some("base-ak"),
            params.get("AccessKeyId").map(String::as_str)
        );
        assert_eq!(Some("AssumeRole"), params.get("Action").map(String::as_str));
        assert_eq!(
            Some("acs:ram::123456789012:role/test-role"),
            params.get("RoleArn").map(String::as_str)
        );
        assert_eq!(
            Some("test-session"),
            params.get("RoleSessionName").map(String::as_str)
        );
        assert_eq!(
            Some("external-id"),
            params.get("ExternalId").map(String::as_str)
        );
        assert_eq!(
            Some("base-token"),
            params.get("SecurityToken").map(String::as_str)
        );
        assert_eq!(
            Some("2024-03-05T06:07:08Z"),
            params.get("Timestamp").map(String::as_str)
        );
        assert_eq!(
            Some("test-nonce"),
            params.get("SignatureNonce").map(String::as_str)
        );

        let mut expected_params = BTreeMap::new();
        expected_params.insert("AccessKeyId".to_string(), "base-ak".to_string());
        expected_params.insert("Action".to_string(), "AssumeRole".to_string());
        expected_params.insert("ExternalId".to_string(), "external-id".to_string());
        expected_params.insert("Format".to_string(), "JSON".to_string());
        expected_params.insert(
            "RoleArn".to_string(),
            "acs:ram::123456789012:role/test-role".to_string(),
        );
        expected_params.insert("RoleSessionName".to_string(), "test-session".to_string());
        expected_params.insert("SecurityToken".to_string(), "base-token".to_string());
        expected_params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        expected_params.insert("SignatureNonce".to_string(), "test-nonce".to_string());
        expected_params.insert("SignatureVersion".to_string(), "1.0".to_string());
        expected_params.insert("Timestamp".to_string(), "2024-03-05T06:07:08Z".to_string());
        expected_params.insert("Version".to_string(), "2015-04-01".to_string());

        let canonicalized = canonicalized_query_string(&expected_params);
        let string_to_sign = format!("GET&%2F&{}", percent_encode_query_value(&canonicalized));
        let expected_signature = base64_hmac_sha1(
            format!("{}&", base_credential.access_key_secret).as_bytes(),
            string_to_sign.as_bytes(),
        );
        assert_eq!(
            Some(expected_signature.as_str()),
            params.get("Signature").map(String::as_str)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_assume_role_refreshes_expiring_credential() -> Result<()> {
        let http_send = CaptureHttpSend::new(vec![
            br#"{"Credentials":{"SecurityToken":"sts-token-1","Expiration":"2024-03-05T06:08:00Z","AccessKeySecret":"sts-secret-1","AccessKeyId":"sts-ak-1"}}"#
                .to_vec(),
            br#"{"Credentials":{"SecurityToken":"sts-token-2","Expiration":"2124-03-05T06:09:00Z","AccessKeySecret":"sts-secret-2","AccessKeyId":"sts-ak-2"}}"#
                .to_vec(),
        ]);
        let ctx = Context::new()
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let provider = AssumeRoleCredentialProvider::new()
            .with_base_provider(TestBaseCredentialProvider::new(Some(Credential {
                access_key_id: "base-ak".to_string(),
                access_key_secret: "base-sk".to_string(),
                security_token: None,
                expires_in: None,
            })))
            .with_role_arn("acs:ram::123456789012:role/test-role")
            .with_role_session_name("test-session")
            .with_sts_endpoint("https://sts.example.com")
            .with_time("2024-03-05T06:07:08Z".parse().unwrap())
            .with_signature_nonce("test-nonce");
        let signer = Signer::new(ctx, provider, RequestSigner::new("test-bucket"));

        let mut first_req =
            http::Request::get("https://test-bucket.oss-cn-beijing.aliyuncs.com/object")
                .body(())
                .unwrap()
                .into_parts()
                .0;
        signer.sign(&mut first_req, None).await?;
        assert!(
            first_req
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .expect("authorization must exist")
                .starts_with("OSS sts-ak-1:")
        );

        let mut second_req =
            http::Request::get("https://test-bucket.oss-cn-beijing.aliyuncs.com/object")
                .body(())
                .unwrap()
                .into_parts()
                .0;
        signer.sign(&mut second_req, None).await?;

        let authorization = second_req
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .expect("authorization must exist");
        assert!(authorization.starts_with("OSS sts-ak-2:"));
        assert_eq!(2, http_send.calls());

        Ok(())
    }
}
