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

//! Shared Alibaba Cloud STS `AssumeRole` machinery.
//!
//! This module holds the RPC request construction, HMAC-SHA1 signing, and
//! response parsing used by both the fixed-configuration
//! [`AssumeRoleCredentialProvider`](crate::AssumeRoleCredentialProvider) and the
//! explicit [`AssumeRoleGranter`]. The provider loads its role configuration and
//! base credential from the environment and the default static chain; the
//! granter binds a typed [`AssumeRoleGrant`] and consumes a source credential
//! supplied by [`reqsign_core::Granter`].

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use serde::Deserialize;

use crate::Credential;

static ALIYUN_RPC_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(crate) const DEFAULT_STS_ENDPOINT: &str = "https://sts.aliyuncs.com";

static SIGNATURE_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

const STS_REQUEST_HEADROOM: Duration = Duration::from_secs(20);
const MIN_ASSUME_ROLE_DURATION: Duration = Duration::from_secs(900);
const MAX_ASSUME_ROLE_DURATION: Duration = Duration::from_secs(43_200);

/// A typed, explicitly bound Alibaba Cloud RAM STS `AssumeRole` grant.
///
/// Bind the target role and optional session parameters, then hand this to
/// [`AssumeRoleGranter::new`]. Unlike
/// [`AssumeRoleCredentialProvider`](crate::AssumeRoleCredentialProvider), a
/// grant never reads configuration from the environment.
#[derive(Clone)]
pub struct AssumeRoleGrant {
    role_arn: String,
    role_session_name: Option<String>,
    external_id: Option<String>,
    policy: Option<String>,
}

impl Debug for AssumeRoleGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Keep the session policy out of Debug output.
        f.debug_struct("AssumeRoleGrant")
            .field("role_arn", &self.role_arn)
            .field("role_session_name", &self.role_session_name)
            .field("external_id", &self.external_id)
            .finish_non_exhaustive()
    }
}

impl AssumeRoleGrant {
    /// Create a grant for the target role ARN (`acs:ram::<account>:role/<name>`).
    pub fn new(role_arn: impl Into<String>) -> Self {
        Self {
            role_arn: role_arn.into(),
            role_session_name: None,
            external_id: None,
            policy: None,
        }
    }

    /// Set the role session name. Defaults to `reqsign` when unset.
    pub fn with_role_session_name(mut self, name: impl Into<String>) -> Self {
        self.role_session_name = Some(name.into());
        self
    }

    /// Set the external ID required by the target role's trust policy.
    pub fn with_external_id(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Set an inline session policy that further restricts the granted credential.
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    fn role_session_name(&self) -> String {
        self.role_session_name
            .clone()
            .unwrap_or_else(|| "reqsign".to_string())
    }
}

/// Normalize an STS endpoint into an absolute origin without a trailing slash.
pub(crate) fn normalize_sts_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.starts_with("https://") || endpoint.starts_with("http://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    }
}

pub(crate) fn canonicalized_query_string(params: &BTreeMap<String, String>) -> String {
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

pub(crate) fn percent_encode_query_value(value: &str) -> String {
    utf8_percent_encode(value, &ALIYUN_RPC_QUERY_ENCODE_SET).to_string()
}

pub(crate) fn signature_nonce(signing_time: Timestamp) -> String {
    let counter = SIGNATURE_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{}-{}-{counter}",
        signing_time.as_second(),
        signing_time.subsec_nanosecond()
    )
}

/// Build a signed Alibaba Cloud RPC-style STS request.
///
/// `endpoint` must already be normalized. `params` must contain every RPC
/// parameter except `Signature`; the caller owns action-specific parameters.
/// The request is signed with HMAC-SHA1 using `access_key_secret`.
pub(crate) fn signed_rpc_request(
    endpoint: &str,
    params: &BTreeMap<String, String>,
    access_key_secret: &str,
) -> Result<http::Request<Vec<u8>>> {
    let canonicalized_query_string = canonicalized_query_string(params);
    let string_to_sign = format!(
        "GET&%2F&{}",
        percent_encode_query_value(&canonicalized_query_string)
    );
    let signature = base64_hmac_sha1(
        format!("{access_key_secret}&").as_bytes(),
        string_to_sign.as_bytes(),
    );

    let url = format!(
        "{}/?{}&Signature={}",
        endpoint,
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
    Ok(req)
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

/// Parse a successful STS `AssumeRole` JSON response into a [`Credential`].
pub(crate) fn parse_credential(body: &[u8]) -> Result<Credential> {
    let resp: AssumeRoleResponse = serde_json::from_slice(body)
        .map_err(|e| Error::unexpected(format!("Failed to parse STS response: {e}")))?;
    let resp_cred = resp.credentials;

    Ok(Credential {
        access_key_id: resp_cred.access_key_id,
        access_key_secret: resp_cred.access_key_secret,
        security_token: Some(resp_cred.security_token),
        expires_in: Some(resp_cred.expiration.parse()?),
    })
}

/// Explicitly grants an Alibaba Cloud RAM STS `AssumeRole` credential.
///
/// The source credential supplied by [`reqsign_core::Granter`] signs the STS
/// request directly with HMAC-SHA1. Both long-lived access keys and valid
/// temporary credentials are accepted; a temporary source's `SecurityToken` is
/// included in the request. Every call performs a new STS exchange, and granted
/// credentials are never cached.
///
/// `AssumeRole` is an authority transition: the returned session receives the
/// intersection of the target role's permissions and the optional inline
/// session policy in [`AssumeRoleGrant`], not necessarily a subset of the
/// source principal's direct permissions.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_aliyun_oss::{AssumeRoleGrant, AssumeRoleGranter, StaticCredentialProvider};
/// use reqsign_core::{Context, Granter};
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = StaticCredentialProvider::new("source-access-key-id", "source-access-key-secret");
/// let grant = AssumeRoleGrant::new("acs:ram::123456789012:role/customer-reader")
///     .with_role_session_name("customer-a");
/// // Supply a Context configured with an HttpSend implementation.
/// let context = Context::new();
/// let credential = Granter::new(context, source, AssumeRoleGranter::new(grant))
///     .grant(Some(Duration::from_secs(3600)))
///     .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AssumeRoleGranter {
    grant: AssumeRoleGrant,
    sts_endpoint: Option<String>,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    signature_nonce: Option<String>,
}

impl Debug for AssumeRoleGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleGranter").finish_non_exhaustive()
    }
}

impl AssumeRoleGranter {
    /// Create a granter bound to an authority transition.
    ///
    /// The STS endpoint defaults to `https://sts.aliyuncs.com`; override it with
    /// [`AssumeRoleGranter::with_sts_endpoint`] for a regional or VPC endpoint.
    pub fn new(grant: AssumeRoleGrant) -> Self {
        Self {
            grant,
            sts_endpoint: None,
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            signature_nonce: None,
        }
    }

    /// Replace the bound authority transition.
    pub fn with_grant(mut self, grant: AssumeRoleGrant) -> Self {
        self.grant = grant;
        self
    }

    /// Set the STS endpoint. Accepts a bare host or a full URL.
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = Some(endpoint.into());
        self
    }

    fn endpoint(&self) -> String {
        match &self.sts_endpoint {
            Some(endpoint) => normalize_sts_endpoint(endpoint),
            None => DEFAULT_STS_ENDPOINT.to_string(),
        }
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn nonce(&self, signing_time: Timestamp) -> String {
        #[cfg(test)]
        if let Some(nonce) = &self.signature_nonce {
            return nonce.clone();
        }
        signature_nonce(signing_time)
    }

    fn duration_seconds(expires_in: Option<Duration>) -> Result<Option<u32>> {
        let Some(expires_in) = expires_in else {
            return Ok(None);
        };
        if !(MIN_ASSUME_ROLE_DURATION..=MAX_ASSUME_ROLE_DURATION).contains(&expires_in) {
            return Err(Error::request_invalid(
                "Aliyun STS AssumeRole duration must be between 900 and 43200 seconds",
            ));
        }
        let seconds = u32::try_from(expires_in.as_secs()).map_err(|_| {
            Error::request_invalid(
                "Aliyun STS AssumeRole duration must be between 900 and 43200 seconds",
            )
        })?;
        Ok(Some(seconds))
    }

    fn validate_source(&self, credential: &Credential, required_until: Timestamp) -> Result<()> {
        if credential.access_key_id.is_empty() || credential.access_key_secret.is_empty() {
            return Err(Error::credential_invalid(
                "Aliyun STS AssumeRole requires a source access key id and access key secret",
            ));
        }
        if credential
            .security_token
            .as_ref()
            .is_some_and(|token| token.trim().is_empty())
        {
            return Err(Error::credential_invalid(
                "Aliyun STS AssumeRole source security token is invalid",
            ));
        }
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Aliyun source credential expires before the STS AssumeRole request can complete",
            ));
        }
        Ok(())
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
}

impl GrantCredential for AssumeRoleGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + STS_REQUEST_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let duration_seconds = Self::duration_seconds(expires_in)?;
        let required_until = self.required_valid_until(credential, expires_in);
        self.validate_source(credential, required_until)?;

        let signing_time = self.now();
        let mut params = BTreeMap::new();
        params.insert("AccessKeyId".to_string(), credential.access_key_id.clone());
        params.insert("Action".to_string(), "AssumeRole".to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("RoleArn".to_string(), self.grant.role_arn.clone());
        params.insert(
            "RoleSessionName".to_string(),
            self.grant.role_session_name(),
        );
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureNonce".to_string(), self.nonce(signing_time));
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("Timestamp".to_string(), signing_time.format_rfc3339_zulu());
        params.insert("Version".to_string(), "2015-04-01".to_string());

        if let Some(external_id) = &self.grant.external_id {
            params.insert("ExternalId".to_string(), external_id.clone());
        }
        if let Some(token) = &credential.security_token {
            params.insert("SecurityToken".to_string(), token.clone());
        }
        if let Some(policy) = &self.grant.policy {
            params.insert("Policy".to_string(), policy.clone());
        }
        if let Some(duration_seconds) = duration_seconds {
            params.insert("DurationSeconds".to_string(), duration_seconds.to_string());
        }

        let req = signed_rpc_request(&self.endpoint(), &params, &credential.access_key_secret)?;
        let resp = ctx.http_send(req.map(Into::into)).await?;
        if resp.status() != http::StatusCode::OK {
            let content = String::from_utf8_lossy(resp.body());
            return Err(Error::unexpected(format!(
                "request to Aliyun STS Services failed: {content}"
            )));
        }

        let granted = parse_credential(resp.body())?;
        if !granted.is_valid_at(self.now()) {
            return Err(Error::credential_invalid(
                "Aliyun STS AssumeRole returned a credential that is already expired",
            ));
        }
        Ok(granted)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use reqsign_core::{Context, Granter, HttpSend, ProvideCredential};

    use super::*;

    const SUCCESS_BODY: &[u8] = br#"{"Credentials":{"SecurityToken":"sts-token","Expiration":"2124-05-25T11:45:17Z","AccessKeySecret":"sts-secret","AccessKeyId":"sts-ak"}}"#;

    #[derive(Debug, Clone)]
    struct TestSourceProvider {
        credential: Option<Credential>,
    }

    impl ProvideCredential for TestSourceProvider {
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

    fn source_credential(security_token: Option<&str>) -> Credential {
        Credential {
            access_key_id: "base-ak".to_string(),
            access_key_secret: "base-sk".to_string(),
            security_token: security_token.map(str::to_owned),
            expires_in: None,
        }
    }

    fn source_provider(security_token: Option<&str>) -> TestSourceProvider {
        TestSourceProvider {
            credential: Some(source_credential(security_token)),
        }
    }

    fn query_params(uri: &str) -> HashMap<String, String> {
        let uri: http::Uri = uri.parse().expect("uri must parse");
        form_urlencoded::parse(uri.query().expect("query must exist").as_bytes())
            .into_owned()
            .collect()
    }

    #[test]
    fn test_normalize_sts_endpoint_accepts_bare_host_and_full_url() {
        assert_eq!(
            "https://sts.aliyuncs.com",
            normalize_sts_endpoint("sts.aliyuncs.com")
        );
        assert_eq!(
            "https://sts.example.com",
            normalize_sts_endpoint("https://sts.example.com/")
        );
        assert_eq!(
            "http://sts.example.com",
            normalize_sts_endpoint("http://sts.example.com/")
        );
    }

    #[test]
    fn test_parse_credential_maps_sts_fields() -> Result<()> {
        let credential = parse_credential(SUCCESS_BODY)?;
        assert_eq!("sts-ak", credential.access_key_id);
        assert_eq!("sts-secret", credential.access_key_secret);
        assert_eq!(Some("sts-token".to_string()), credential.security_token);
        assert!(credential.expires_in.is_some());
        Ok(())
    }

    #[test]
    fn test_duration_seconds_rejects_out_of_range() {
        assert!(AssumeRoleGranter::duration_seconds(None).unwrap().is_none());
        assert_eq!(
            Some(3600),
            AssumeRoleGranter::duration_seconds(Some(Duration::from_secs(3600))).unwrap()
        );
        assert!(AssumeRoleGranter::duration_seconds(Some(Duration::from_secs(899))).is_err());
        assert!(AssumeRoleGranter::duration_seconds(Some(Duration::from_secs(43_201))).is_err());
    }

    #[tokio::test]
    async fn test_grant_signs_request_and_returns_credential() -> Result<()> {
        let http_send = CaptureHttpSend::new(vec![SUCCESS_BODY.to_vec()]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let signing_time: Timestamp = "2024-03-05T06:07:08Z".parse().unwrap();
        let grant = AssumeRoleGrant::new("acs:ram::123456789012:role/test-role")
            .with_role_session_name("test-session")
            .with_external_id("external-id")
            .with_policy("{\"Version\":\"1\"}");
        let granter = AssumeRoleGranter::new(grant)
            .with_sts_endpoint("https://sts.example.com")
            .with_time(signing_time)
            .with_signature_nonce("test-nonce");

        let credential = Granter::new(ctx, source_provider(Some("base-token")), granter)
            .grant(Some(Duration::from_secs(3600)))
            .await?;

        assert_eq!("sts-ak", credential.access_key_id);
        assert_eq!("sts-secret", credential.access_key_secret);
        assert_eq!(Some("sts-token".to_string()), credential.security_token);
        assert_eq!(1, http_send.calls());

        let uri = http_send.uri().expect("request uri must be captured");
        let parsed: http::Uri = uri.parse().expect("uri must parse");
        assert_eq!(
            "https://sts.example.com/",
            format!("https://{}{}", parsed.authority().unwrap(), parsed.path())
        );
        let params = query_params(&uri);
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
            Some("{\"Version\":\"1\"}"),
            params.get("Policy").map(String::as_str)
        );
        assert_eq!(
            Some("3600"),
            params.get("DurationSeconds").map(String::as_str)
        );
        assert_eq!(
            Some("test-nonce"),
            params.get("SignatureNonce").map(String::as_str)
        );

        // Golden signature over the exact signed parameter set.
        let mut expected = BTreeMap::new();
        expected.insert("AccessKeyId".to_string(), "base-ak".to_string());
        expected.insert("Action".to_string(), "AssumeRole".to_string());
        expected.insert("DurationSeconds".to_string(), "3600".to_string());
        expected.insert("ExternalId".to_string(), "external-id".to_string());
        expected.insert("Format".to_string(), "JSON".to_string());
        expected.insert("Policy".to_string(), "{\"Version\":\"1\"}".to_string());
        expected.insert(
            "RoleArn".to_string(),
            "acs:ram::123456789012:role/test-role".to_string(),
        );
        expected.insert("RoleSessionName".to_string(), "test-session".to_string());
        expected.insert("SecurityToken".to_string(), "base-token".to_string());
        expected.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        expected.insert("SignatureNonce".to_string(), "test-nonce".to_string());
        expected.insert("SignatureVersion".to_string(), "1.0".to_string());
        expected.insert("Timestamp".to_string(), "2024-03-05T06:07:08Z".to_string());
        expected.insert("Version".to_string(), "2015-04-01".to_string());
        let canonical = canonicalized_query_string(&expected);
        let string_to_sign = format!("GET&%2F&{}", percent_encode_query_value(&canonical));
        let expected_signature = base64_hmac_sha1("base-sk&".as_bytes(), string_to_sign.as_bytes());
        assert_eq!(
            Some(expected_signature.as_str()),
            params.get("Signature").map(String::as_str)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_grant_omits_optional_params_when_unset() -> Result<()> {
        let http_send = CaptureHttpSend::new(vec![SUCCESS_BODY.to_vec()]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let granter =
            AssumeRoleGranter::new(AssumeRoleGrant::new("acs:ram::123456789012:role/test-role"))
                .with_time("2024-03-05T06:07:08Z".parse().unwrap())
                .with_signature_nonce("test-nonce");

        Granter::new(ctx, source_provider(None), granter)
            .grant(None)
            .await?;

        let params = query_params(&http_send.uri().unwrap());
        assert_eq!(
            Some("reqsign"),
            params.get("RoleSessionName").map(String::as_str)
        );
        assert!(!params.contains_key("SecurityToken"));
        assert!(!params.contains_key("ExternalId"));
        assert!(!params.contains_key("Policy"));
        assert!(!params.contains_key("DurationSeconds"));
        Ok(())
    }

    #[tokio::test]
    async fn test_grant_rejects_invalid_source_before_io() {
        let http_send = CaptureHttpSend::new(vec![SUCCESS_BODY.to_vec()]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let granter =
            AssumeRoleGranter::new(AssumeRoleGrant::new("acs:ram::123456789012:role/test-role"));
        let empty = Credential {
            access_key_id: String::new(),
            access_key_secret: String::new(),
            security_token: None,
            expires_in: None,
        };

        let result = Granter::new(
            ctx,
            TestSourceProvider {
                credential: Some(empty),
            },
            granter,
        )
        .grant(None)
        .await;
        assert!(result.is_err());
        assert_eq!(0, http_send.calls());
    }

    #[tokio::test]
    async fn test_grant_rejects_out_of_range_duration_before_io() {
        let http_send = CaptureHttpSend::new(vec![SUCCESS_BODY.to_vec()]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let granter =
            AssumeRoleGranter::new(AssumeRoleGrant::new("acs:ram::123456789012:role/test-role"));

        let result = Granter::new(ctx, source_provider(None), granter)
            .grant(Some(Duration::from_secs(60)))
            .await;
        assert!(result.is_err());
        assert_eq!(0, http_send.calls());
    }

    #[tokio::test]
    async fn test_grant_rejects_expired_granted_credential() {
        let expired = br#"{"Credentials":{"SecurityToken":"sts-token","Expiration":"2000-01-01T00:00:00Z","AccessKeySecret":"sts-secret","AccessKeyId":"sts-ak"}}"#;
        let http_send = CaptureHttpSend::new(vec![expired.to_vec()]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let granter =
            AssumeRoleGranter::new(AssumeRoleGrant::new("acs:ram::123456789012:role/test-role"));

        let result = Granter::new(ctx, source_provider(None), granter)
            .grant(None)
            .await;
        assert!(result.is_err());
        assert_eq!(1, http_send.calls());
    }
}
