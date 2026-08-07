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

use std::fmt::{Debug, Formatter};
use std::time::Duration;

use reqsign_aws_core::assume_role::{AssumeRoleOperation, regional_sts_endpoint};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SignRequest, SigningCredential};

use crate::{AssumeRoleGrant, Credential, RequestSigner};

const STS_REQUEST_HEADROOM: Duration = Duration::from_secs(20);
const MIN_ASSUME_ROLE_DURATION: Duration = Duration::from_secs(900);
const MAX_ASSUME_ROLE_DURATION: Duration = Duration::from_secs(43_200);

/// Explicitly grants an AWS STS assumed-role credential.
///
/// The source credential provided to [`reqsign_core::Granter`] signs the STS
/// request directly. Both long-lived credentials and valid temporary
/// credentials are supported; a temporary source's session token is included
/// in the SigV4 request.
///
/// `AssumeRole` is an authority transition. The returned session receives the
/// intersection of the target role's permissions and the optional session
/// policies in [`AssumeRoleGrant`], not necessarily a subset of the source
/// principal's direct permissions.
///
/// AWS limits role chaining to one hour, but an opaque [`Credential`] does not
/// reliably identify whether a temporary source is an assumed-role session.
/// Callers performing role chaining must request at most one hour; STS remains
/// authoritative for this and for the target role's configured maximum.
///
/// This granter uses the standard regional STS endpoint for the bound signing
/// region. Every call performs a new STS exchange; granted credentials are
/// never cached.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_aws_v4::{
///     AssumeRoleGrant, AssumeRoleGranter, StaticCredentialProvider,
/// };
/// use reqsign_core::{Context, Granter};
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = StaticCredentialProvider::new("source-access-key", "source-secret-key");
/// let grant = AssumeRoleGrant::new(
///     "arn:aws:iam::123456789012:role/customer-reader",
///     "customer-a",
/// );
/// // Supply a Context configured with an HttpSend implementation.
/// let context = Context::new();
/// let credential = Granter::new(
///     context,
///     source,
///     AssumeRoleGranter::new("us-east-1", grant),
/// )
/// .grant(Some(Duration::from_secs(3600)))
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AssumeRoleGranter {
    region: String,
    grant: AssumeRoleGrant,
    #[cfg(test)]
    time: Option<Timestamp>,
}

impl Debug for AssumeRoleGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleGranter").finish_non_exhaustive()
    }
}

impl AssumeRoleGranter {
    /// Create a granter for a signing region and bound AssumeRole grant.
    pub fn new(region: impl Into<String>, grant: AssumeRoleGrant) -> Self {
        Self {
            region: region.into(),
            grant,
            #[cfg(test)]
            time: None,
        }
    }

    /// Replace the bound authority transition.
    pub fn with_grant(mut self, grant: AssumeRoleGrant) -> Self {
        self.grant = grant;
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn request_signer(&self) -> RequestSigner {
        let signer = RequestSigner::new("sts", &self.region);
        #[cfg(test)]
        if let Some(time) = self.time {
            return signer.with_time(time);
        }
        signer
    }

    fn duration_seconds(expires_in: Option<Duration>) -> Result<Option<u32>> {
        let Some(expires_in) = expires_in else {
            return Ok(None);
        };
        if !(MIN_ASSUME_ROLE_DURATION..=MAX_ASSUME_ROLE_DURATION).contains(&expires_in) {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole duration must be between 900 and 43200 seconds",
            ));
        }
        let seconds = u32::try_from(expires_in.as_secs()).map_err(|_| {
            Error::request_invalid(
                "AWS STS AssumeRole duration must be between 900 and 43200 seconds",
            )
        })?;
        Ok(Some(seconds))
    }

    fn validate_source(&self, credential: &Credential, required_until: Timestamp) -> Result<()> {
        if !(16..=128).contains(&credential.access_key_id.chars().count())
            || !credential
                .access_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || credential.secret_access_key.is_empty()
        {
            return Err(Error::credential_invalid(
                "AWS STS AssumeRole requires a source access key and secret access key",
            ));
        }
        if credential.session_token.as_ref().is_some_and(|token| {
            token.trim().is_empty() || http::HeaderValue::try_from(token.as_str()).is_err()
        }) {
            return Err(Error::credential_invalid(
                "AWS STS AssumeRole source session token is invalid",
            ));
        }
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "AWS source credential expires before the STS AssumeRole request can complete",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
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
        let endpoint = regional_sts_endpoint(&self.region, &self.grant)?;
        let operation = AssumeRoleOperation::new(endpoint, &self.grant, duration_seconds)?;
        let required_until = self.required_valid_until(credential, expires_in);
        self.validate_source(credential, required_until)?;

        let request = operation.build_request()?;
        let (mut parts, body) = request.into_parts();
        self.request_signer()
            .sign_request(ctx, &mut parts, Some(credential), None)
            .await
            .map_err(|err| {
                Error::new(err.kind(), "failed to sign AWS STS AssumeRole request")
                    .set_retryable(err.is_retryable())
            })?;
        operation
            .send(ctx, http::Request::from_parts(parts, body))
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aws_credential_types::Credentials as AwsCredentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    };
    use aws_sigv4::sign::v4;
    use bytes::Bytes;
    use http::HeaderMap;
    use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName};
    use reqsign_core::hash::hex_sha256;
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer};

    use super::*;
    use crate::AssumeRoleCredentialProvider;

    const SOURCE_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SOURCE_SECRET_KEY: &str = "source-secret-key";
    const SOURCE_SESSION_TOKEN: &str = "source-session-token";
    const RETURNED_SECRET_KEY: &str = "returned-secret-key";
    const RETURNED_SESSION_TOKEN: &str = "returned-session-token";
    const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/customer-reader";
    const REGION: &str = "us-east-1";
    const EXPIRATION: &str = "2099-11-09T13:34:41Z";

    fn signing_time() -> Timestamp {
        "2026-07-30T08:00:00Z"
            .parse()
            .expect("signing time must parse")
    }

    fn source_credential(session_token: Option<&str>) -> Credential {
        Credential {
            access_key_id: SOURCE_ACCESS_KEY.to_string(),
            secret_access_key: SOURCE_SECRET_KEY.to_string(),
            session_token: session_token.map(str::to_owned),
            expires_in: Some(EXPIRATION.parse().expect("expiration must parse")),
        }
    }

    fn valid_grant() -> AssumeRoleGrant {
        AssumeRoleGrant::new(ROLE_ARN, "customer-a")
    }

    fn sign_with_aws_sdk(
        mut request: http::Request<Bytes>,
        session_token: Option<&str>,
    ) -> http::Request<Bytes> {
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Double;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let identity = AwsCredentials::new(
            SOURCE_ACCESS_KEY,
            SOURCE_SECRET_KEY,
            session_token.map(str::to_owned),
            None,
            "reqsign-assume-role-test",
        )
        .into();
        let signing = v4::SigningParams::builder()
            .identity(&identity)
            .region(REGION)
            .name("sts")
            .time(signing_time().as_system_time())
            .settings(settings)
            .build()
            .expect("AWS SDK signing parameters must build");
        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                request.method().as_str(),
                request.uri().to_string(),
                request.headers().iter().map(|(name, value)| {
                    (
                        name.as_str(),
                        std::str::from_utf8(value.as_bytes())
                            .expect("request headers must contain text"),
                    )
                }),
                SignableBody::Bytes(request.body()),
            )
            .expect("request must be signable"),
            &signing.into(),
        )
        .expect("AWS SDK must sign the request");
        let (instructions, _) = output.into_parts();
        instructions.apply_to_request_http1x(&mut request);
        request
    }

    fn success_response(access_key_id: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from(format!(
                "<AssumeRoleResponse>\
                    <AssumeRoleResult>\
                        <Credentials>\
                            <AccessKeyId>{access_key_id}</AccessKeyId>\
                            <SecretAccessKey>{RETURNED_SECRET_KEY}</SecretAccessKey>\
                            <SessionToken>{RETURNED_SESSION_TOKEN}</SessionToken>\
                            <Expiration>{EXPIRATION}</Expiration>\
                        </Credentials>\
                    </AssumeRoleResult>\
                </AssumeRoleResponse>"
            )))
            .expect("response must build")
    }

    #[derive(Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CapturedRequest")
                .field("method", &self.method)
                .field("uri", &"REDACTED")
                .field("headers", &"REDACTED")
                .field("body", &"REDACTED")
                .finish()
        }
    }

    #[derive(Clone)]
    struct MockHttpSend {
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
    }

    impl Debug for MockHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockHttpSend").finish_non_exhaustive()
        }
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().expect("lock poisoned").clone()
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (parts, body) = request.into_parts();
            self.requests
                .lock()
                .expect("lock poisoned")
                .push(CapturedRequest {
                    method: parts.method,
                    uri: parts.uri,
                    headers: parts.headers,
                    body,
                });
            self.responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock response queue is empty"))
        }
    }

    #[derive(Clone)]
    struct FixedCredentialProvider {
        credential: Credential,
        calls: Arc<AtomicUsize>,
    }

    impl Debug for FixedCredentialProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FixedCredentialProvider")
                .finish_non_exhaustive()
        }
    }

    impl FixedCredentialProvider {
        fn new(credential: Credential) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    credential,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl ProvideCredential for FixedCredentialProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.credential.clone()))
        }
    }

    #[derive(Debug)]
    struct SecretTransportError;

    impl HttpSend for SecretTransportError {
        async fn http_send(&self, _request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            Err(
                Error::unexpected("transport captured source-secret-key and policy-secret")
                    .set_retryable(true),
            )
        }
    }

    #[derive(Debug)]
    struct NonRetryableTransportError;

    impl HttpSend for NonRetryableTransportError {
        async fn http_send(&self, _request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            Err(Error::unexpected("temporary transport failure"))
        }
    }

    #[tokio::test]
    async fn signs_exact_wire_with_explicit_source_and_never_caches_output() {
        let http = MockHttpSend::new([
            success_response("ASIAFIRSTOUTPUT001"),
            success_response("ASIASECONDOUTPUT01"),
        ]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, provider_calls) =
            FixedCredentialProvider::new(source_credential(Some(SOURCE_SESSION_TOKEN)));
        let operation =
            AssumeRoleGranter::new(REGION, valid_grant().with_external_id("tenant/123"))
                .with_time(signing_time());
        let granter = Granter::new(context, provider, operation);

        let first = granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect("first grant must succeed");
        let second = granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect("second grant must execute again");

        assert_eq!(first.access_key_id, "ASIAFIRSTOUTPUT001");
        assert_eq!(second.access_key_id, "ASIASECONDOUTPUT01");
        assert_ne!(first.access_key_id, SOURCE_ACCESS_KEY);
        assert_ne!(first.secret_access_key, SOURCE_SECRET_KEY);
        assert_ne!(first.session_token.as_deref(), Some(SOURCE_SESSION_TOKEN));
        assert_eq!(
            first.expires_in,
            Some(EXPIRATION.parse().expect("expiration must parse"))
        );
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls(), 2);

        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, http::Method::GET);
        assert!(requests[0].body.is_empty());
        assert_eq!(
            requests[0].uri.to_string(),
            "https://sts.us-east-1.amazonaws.com/?Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fcustomer-reader&Version=2011-06-15&RoleSessionName=customer-a&ExternalId=tenant%2F123&DurationSeconds=3600"
        );
        assert_eq!(
            requests[0]
                .headers
                .get(CONTENT_TYPE)
                .expect("content type must be set"),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            requests[0]
                .headers
                .get("x-amz-date")
                .expect("signing date must be set"),
            "20260730T080000Z"
        );
        assert_eq!(
            requests[0]
                .headers
                .get("x-amz-security-token")
                .expect("source session token must be signed"),
            SOURCE_SESSION_TOKEN
        );
        assert_eq!(
            requests[0]
                .headers
                .get(HeaderName::from_static("x-amz-content-sha256"))
                .expect("payload hash must be set"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            crate::EMPTY_STRING_SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            requests[0]
                .headers
                .get(AUTHORIZATION)
                .expect("authorization must be set")
                .to_str()
                .expect("authorization must be text"),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260730/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=9561cc1cbe7212bd5763162afbaf215cd24c153eb27ac2718ebee4b12ff82a5f"
        );
        let sdk_request = sign_with_aws_sdk(
            AssumeRoleOperation::new(
                "sts.us-east-1.amazonaws.com",
                &valid_grant().with_external_id("tenant/123"),
                Some(3_600),
            )
            .expect("operation must build")
            .build_request()
            .expect("request must build"),
            Some(SOURCE_SESSION_TOKEN),
        );
        assert_eq!(
            requests[0]
                .headers
                .get(AUTHORIZATION)
                .expect("reqsign authorization must be set"),
            sdk_request
                .headers()
                .get(AUTHORIZATION)
                .expect("AWS SDK authorization must be set")
        );
        assert_eq!(requests[0].uri, requests[1].uri);
        assert_eq!(requests[0].headers, requests[1].headers);
    }

    #[tokio::test]
    async fn signs_large_grant_as_post_with_an_independent_oracle() {
        let grant = valid_grant().with_tags(
            (0..8)
                .map(|index| (format!("Tag{index}"), "x".repeat(256)))
                .collect(),
        );
        let sdk_request = sign_with_aws_sdk(
            AssumeRoleOperation::new("sts.us-east-1.amazonaws.com", &grant, Some(3_600))
                .expect("operation must build")
                .build_request()
                .expect("request must build"),
            Some(SOURCE_SESSION_TOKEN),
        );
        let http = MockHttpSend::new([success_response("ASIAPOSTOUTPUT0001")]);
        let context = Context::new().with_http_send(http.clone());
        let operation = AssumeRoleGranter::new(REGION, grant).with_time(signing_time());

        operation
            .grant_credential(
                &context,
                &source_credential(Some(SOURCE_SESSION_TOKEN)),
                Some(Duration::from_secs(3_600)),
            )
            .await
            .expect("large AssumeRole grant must succeed");

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, http::Method::POST);
        assert_eq!(request.uri, "https://sts.us-east-1.amazonaws.com/");
        assert!(request.uri.query().is_none());
        assert!(request.body.len() > 2_048);
        assert!(request.body.starts_with(b"Action=AssumeRole&"));
        assert_eq!(
            request
                .headers
                .get("x-amz-content-sha256")
                .expect("payload hash must be set")
                .to_str()
                .expect("payload hash must be text"),
            hex_sha256(&request.body)
        );
        assert_eq!(
            request
                .headers
                .get(AUTHORIZATION)
                .expect("reqsign authorization must be set"),
            sdk_request
                .headers()
                .get(AUTHORIZATION)
                .expect("AWS SDK authorization must be set")
        );
        assert_eq!(
            request
                .headers
                .get("x-amz-content-sha256")
                .expect("reqsign payload hash must be set"),
            sdk_request
                .headers()
                .get("x-amz-content-sha256")
                .expect("AWS SDK payload hash must be set")
        );
    }

    #[tokio::test]
    async fn supports_long_lived_and_temporary_source_credentials() {
        let http = MockHttpSend::new([
            success_response("ASIALONGTERMSOURCE1"),
            success_response("ASIATEMPSOURCE00001"),
        ]);
        let context = Context::new().with_http_send(http.clone());
        let operation = AssumeRoleGranter::new(REGION, valid_grant()).with_time(signing_time());
        let mut long_lived_source = source_credential(None);
        long_lived_source.expires_in = None;

        operation
            .grant_credential(&context, &long_lived_source, None)
            .await
            .expect("long-lived source must be supported");
        operation
            .grant_credential(
                &context,
                &source_credential(Some(SOURCE_SESSION_TOKEN)),
                None,
            )
            .await
            .expect("temporary source must be supported");

        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert!(
            !requests[0]
                .uri
                .query()
                .expect("AssumeRole query must be present")
                .contains("DurationSeconds"),
            "None must use the AWS default session duration"
        );
        assert!(
            requests[0].headers.get("x-amz-security-token").is_none(),
            "long-lived sources must not add a session token"
        );
        assert_eq!(
            requests[1]
                .headers
                .get("x-amz-security-token")
                .expect("temporary source token must be set"),
            SOURCE_SESSION_TOKEN
        );
        for request in requests {
            assert!(
                request
                    .headers
                    .get(AUTHORIZATION)
                    .expect("authorization must be set")
                    .to_str()
                    .expect("authorization must be text")
                    .contains(SOURCE_ACCESS_KEY)
            );
        }
    }

    #[tokio::test]
    async fn validates_typed_grant_region_and_lifetime_before_sts_io() {
        let http = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
        let context = Context::new().with_http_send(http.clone());
        let source = source_credential(None);
        let valid_policy_arn = "arn:aws:iam::123456789012:policy/customer-reader".to_string();

        let invalid_operations = vec![
            AssumeRoleGranter::new(REGION, AssumeRoleGrant::new("not-an-arn", "customer-a")),
            AssumeRoleGranter::new(REGION, AssumeRoleGrant::new(ROLE_ARN, "x")),
            AssumeRoleGranter::new(REGION, valid_grant().with_external_id("contains space")),
            AssumeRoleGranter::new(REGION, valid_grant().with_policy("not-json")),
            AssumeRoleGranter::new(
                REGION,
                valid_grant().with_policy(r#"{"Statement":"policy-secret-😀"}"#),
            ),
            AssumeRoleGranter::new(
                REGION,
                valid_grant().with_policy_arns(vec![valid_policy_arn.clone(); 11]),
            ),
            AssumeRoleGranter::new(
                REGION,
                valid_grant().with_policy_arns(vec!["arn:aws:s3:::not-an-iam-policy".to_string()]),
            ),
            AssumeRoleGranter::new(
                REGION,
                valid_grant().with_policy_arns(vec![
                    "arn:aws:iam::210987654321:policy/customer-reader".to_string(),
                ]),
            ),
            AssumeRoleGranter::new(
                REGION,
                valid_grant().with_tags(vec![
                    ("Project".to_string(), "one".to_string()),
                    ("project".to_string(), "two".to_string()),
                ]),
            ),
            AssumeRoleGranter::new(
                REGION,
                valid_grant().with_mfa("arn:aws:iam::123456789012:mfa/customer-a", "12345"),
            ),
            AssumeRoleGranter::new("us east 1", valid_grant()),
            AssumeRoleGranter::new(
                REGION,
                AssumeRoleGrant::new(
                    "arn:aws-cn:iam::123456789012:role/customer-reader",
                    "customer-a",
                ),
            ),
        ];

        for operation in invalid_operations {
            let error = operation
                .grant_credential(&context, &source, None)
                .await
                .expect_err("invalid typed grant must be rejected");
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::RequestInvalid | ErrorKind::ConfigInvalid
                ),
                "unexpected error: {error:?}"
            );
        }

        let operation = AssumeRoleGranter::new(REGION, valid_grant()).with_time(signing_time());
        for duration in [899, 43_201] {
            let error = operation
                .grant_credential(&context, &source, Some(Duration::from_secs(duration)))
                .await
                .expect_err("invalid duration must be rejected");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        }
        assert_eq!(http.calls(), 0);
    }

    #[tokio::test]
    async fn rejects_invalid_source_variants_before_sts_io() {
        let http = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
        let context = Context::new().with_http_send(http.clone());
        let operation = AssumeRoleGranter::new(REGION, valid_grant()).with_time(signing_time());
        let invalid_sources = [
            Credential::default(),
            Credential {
                access_key_id: SOURCE_ACCESS_KEY.to_string(),
                ..Default::default()
            },
            source_credential(Some("")),
            source_credential(Some("prefix\nsuffix")),
            Credential {
                expires_in: Some(signing_time() + Duration::from_secs(10)),
                ..source_credential(None)
            },
        ];

        for source in invalid_sources {
            let error = operation
                .grant_credential(&context, &source, None)
                .await
                .expect_err("invalid source must be rejected");
            assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
            let debug = format!("{error:?}");
            assert!(!debug.contains(SOURCE_SECRET_KEY));
            assert!(!debug.contains(SOURCE_SESSION_TOKEN));
        }
        assert_eq!(http.calls(), 0);
    }

    #[tokio::test]
    async fn rejects_expired_and_malformed_outputs_after_sts_io() {
        let expired = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                br#"<AssumeRoleResponse><AssumeRoleResult><Credentials>
                    <AccessKeyId>ASIAEXPIREDOUTPUT1</AccessKeyId>
                    <SecretAccessKey>expired-secret</SecretAccessKey>
                    <SessionToken>expired-token</SessionToken>
                    <Expiration>2020-01-01T00:00:00Z</Expiration>
                </Credentials></AssumeRoleResult></AssumeRoleResponse>"#,
            ))
            .expect("response must build");
        let malformed = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                br#"<AssumeRoleResponse><AssumeRoleResult><Credentials>
                    <AccessKeyId>ASIAMALFORMEDOUT01</AccessKeyId>
                    <SecretAccessKey>malformed-secret</SecretAccessKey>
                    <SessionToken></SessionToken>
                    <Expiration>2035-01-01T00:00:00Z</Expiration>
                </Credentials></AssumeRoleResult></AssumeRoleResponse>"#,
            ))
            .expect("response must build");
        let malformed_access_key = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                br#"<AssumeRoleResponse><AssumeRoleResult><Credentials>
                    <AccessKeyId>ASIAINVALID@OUTPUT1</AccessKeyId>
                    <SecretAccessKey>malformed-secret</SecretAccessKey>
                    <SessionToken>malformed-token</SessionToken>
                    <Expiration>2035-01-01T00:00:00Z</Expiration>
                </Credentials></AssumeRoleResult></AssumeRoleResponse>"#,
            ))
            .expect("response must build");
        let malformed_session_token = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                br#"<AssumeRoleResponse><AssumeRoleResult><Credentials>
                    <AccessKeyId>ASIAMALFORMEDOUT02</AccessKeyId>
                    <SecretAccessKey>malformed-secret</SecretAccessKey>
                    <SessionToken>prefix&#10;suffix</SessionToken>
                    <Expiration>2035-01-01T00:00:00Z</Expiration>
                </Credentials></AssumeRoleResult></AssumeRoleResponse>"#,
            ))
            .expect("response must build");
        let http = MockHttpSend::new([
            expired,
            malformed,
            malformed_access_key,
            malformed_session_token,
        ]);
        let context = Context::new().with_http_send(http.clone());
        let operation = AssumeRoleGranter::new(REGION, valid_grant()).with_time(signing_time());

        let expired_error = operation
            .grant_credential(&context, &source_credential(None), None)
            .await
            .expect_err("expired output must be rejected");
        assert_eq!(expired_error.kind(), ErrorKind::CredentialInvalid);
        let malformed_error = operation
            .grant_credential(&context, &source_credential(None), None)
            .await
            .expect_err("malformed output must be rejected");
        assert_eq!(malformed_error.kind(), ErrorKind::Unexpected);
        for _ in 0..2 {
            let error = operation
                .grant_credential(&context, &source_credential(None), None)
                .await
                .expect_err("unusable output must be rejected");
            assert_eq!(error.kind(), ErrorKind::Unexpected);
        }
        assert_eq!(http.calls(), 4);
    }

    #[tokio::test]
    async fn fixed_provider_preserves_global_endpoint_and_request_defaults() {
        let http = MockHttpSend::new([success_response("ASIAPROVIDERDEFAULT1")]);
        let context = Context::new().with_http_send(http.clone());
        let (source, _) = FixedCredentialProvider::new(source_credential(None));
        let provider = AssumeRoleCredentialProvider::new(
            ROLE_ARN.to_string(),
            Signer::new(
                context.clone(),
                source,
                RequestSigner::new("sts", REGION).with_time(signing_time()),
            ),
        );

        provider
            .provide_credential(&context)
            .await
            .expect("fixed provider must succeed")
            .expect("fixed provider must return a credential");

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].uri.to_string(),
            "https://sts.amazonaws.com/?Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fcustomer-reader&Version=2011-06-15&RoleSessionName=reqsign&DurationSeconds=3600"
        );
    }

    #[tokio::test]
    async fn fixed_provider_accepts_valid_iam_role_paths_and_preserves_retryability() {
        let success_http = MockHttpSend::new([success_response("ASIAVALIDROLEPATH01")]);
        let success_context = Context::new().with_http_send(success_http);
        let (source, _) = FixedCredentialProvider::new(source_credential(None));
        let provider = AssumeRoleCredentialProvider::new(
            "arn:aws:iam::123456789012:role/team!prod/Reader".to_string(),
            Signer::new(
                success_context.clone(),
                source,
                RequestSigner::new("sts", REGION).with_time(signing_time()),
            ),
        );
        provider
            .provide_credential(&success_context)
            .await
            .expect("valid role path must be accepted")
            .expect("provider must return a credential");

        let (source, _) = FixedCredentialProvider::new(source_credential(None));
        let provider = AssumeRoleCredentialProvider::new(
            ROLE_ARN.to_string(),
            Signer::new(
                Context::new(),
                source,
                RequestSigner::new("sts", REGION).with_time(signing_time()),
            ),
        );
        let error = provider
            .provide_credential(&Context::new().with_http_send(NonRetryableTransportError))
            .await
            .expect_err("transport must fail");
        assert_eq!(error.kind(), ErrorKind::Unexpected);
        assert!(error.is_retryable());
    }

    #[tokio::test]
    async fn fixed_provider_and_explicit_granter_share_wire_and_result_path() {
        let grant = valid_grant()
            .with_external_id("tenant/123")
            .with_policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::customer-a/*"}]}"#,
            )
            .with_policy_arns(vec![
                "arn:aws:iam::123456789012:policy/customer-reader".to_string(),
            ])
            .with_tags(vec![("Project".to_string(), "Customer A".to_string())])
            .with_mfa(
                "arn:aws:iam::123456789012:mfa/customer-a",
                "123456",
            );
        let http = MockHttpSend::new([
            success_response("ASIAGRANTEROUTPUT01"),
            success_response("ASIAPROVIDEROUTPUT1"),
        ]);
        let context = Context::new().with_http_send(http.clone());
        let operation = AssumeRoleGranter::new(REGION, grant.clone()).with_time(signing_time());
        let granted = operation
            .grant_credential(
                &context,
                &source_credential(Some(SOURCE_SESSION_TOKEN)),
                Some(Duration::from_secs(3_600)),
            )
            .await
            .expect("explicit grant must succeed");

        let (provider_source, _) =
            FixedCredentialProvider::new(source_credential(Some(SOURCE_SESSION_TOKEN)));
        let sts_signer = Signer::new(
            context.clone(),
            provider_source,
            RequestSigner::new("sts", REGION).with_time(signing_time()),
        );
        let provider = AssumeRoleCredentialProvider::new(ROLE_ARN.to_string(), sts_signer)
            .with_role_session_name("customer-a".to_string())
            .with_external_id("tenant/123".to_string())
            .with_duration_seconds(3_600)
            .with_policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::customer-a/*"}]}"#.to_string(),
            )
            .with_policy_arns(vec![
                "arn:aws:iam::123456789012:policy/customer-reader".to_string(),
            ])
            .with_tags(vec![("Project".to_string(), "Customer A".to_string())])
            .with_mfa_serial("arn:aws:iam::123456789012:mfa/customer-a".to_string())
            .with_mfa_code("123456".to_string())
            .with_region(REGION.to_string())
            .with_regional_sts_endpoint();
        let provided = provider
            .provide_credential(&context)
            .await
            .expect("fixed provider must succeed")
            .expect("fixed provider must return a credential");

        assert_eq!(granted.secret_access_key, provided.secret_access_key);
        assert_eq!(granted.session_token, provided.session_token);
        assert_eq!(granted.expires_in, provided.expires_in);
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, requests[1].method);
        assert_eq!(requests[0].uri, requests[1].uri);
        assert_eq!(requests[0].headers, requests[1].headers);
        assert_eq!(requests[0].body, requests[1].body);
    }

    #[tokio::test]
    async fn redacts_debug_transport_sts_errors_and_raw_responses() {
        let grant = valid_grant()
            .with_external_id("external-secret")
            .with_policy(r#"{"Statement":"policy-secret"}"#)
            .with_mfa("arn:aws:iam::123456789012:mfa/customer-a", "654321");
        let operation = AssumeRoleGranter::new(REGION, grant.clone()).with_time(signing_time());
        let source = source_credential(Some(SOURCE_SESSION_TOKEN));

        for debug in [
            format!("{grant:?}"),
            format!("{operation:?}"),
            format!("{source:?}"),
        ] {
            for secret in [
                "external-secret",
                "policy-secret",
                "654321",
                SOURCE_ACCESS_KEY,
                SOURCE_SECRET_KEY,
                SOURCE_SESSION_TOKEN,
            ] {
                assert!(!debug.contains(secret), "{secret} leaked through Debug");
            }
        }

        let transport_context = Context::new().with_http_send(SecretTransportError);
        let transport_error = operation
            .grant_credential(&transport_context, &source, None)
            .await
            .expect_err("transport must fail");
        let transport_debug = format!("{transport_error:?}");
        assert!(!transport_debug.contains(SOURCE_SECRET_KEY));
        assert!(!transport_debug.contains("policy-secret"));
        assert!(transport_error.is_retryable());

        let known_sts_error_response = http::Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .header("x-amzn-requestid", "response-request-id-secret")
            .body(Bytes::from_static(
                br#"<ErrorResponse><Error><Code>AccessDenied</Code>
                    <Message>policy-secret raw-response-secret returned-session-token</Message>
                </Error></ErrorResponse>"#,
            ))
            .expect("response must build");
        let unknown_sts_error_response = http::Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(Bytes::from_static(
                br#"<ErrorResponse><Error><Code>raw-response-secret</Code>
                    <Message>policy-secret returned-session-token</Message>
                </Error></ErrorResponse>"#,
            ))
            .expect("response must build");
        let malformed_success = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                b"raw-response-secret returned-session-token",
            ))
            .expect("response must build");
        let http = MockHttpSend::new([
            known_sts_error_response,
            unknown_sts_error_response,
            malformed_success,
        ]);
        let context = Context::new().with_http_send(http);
        for _ in 0..3 {
            let error = operation
                .grant_credential(&context, &source, None)
                .await
                .expect_err("response must fail");
            let debug = format!("{error:?}");
            assert!(!debug.contains("policy-secret"));
            assert!(!debug.contains("raw-response-secret"));
            assert!(!debug.contains("returned-session-token"));
            assert!(!debug.contains("response-request-id-secret"));
        }

        let (provider_source, _) = FixedCredentialProvider::new(source);
        let provider = AssumeRoleCredentialProvider::new(
            ROLE_ARN.to_string(),
            Signer::new(
                Context::new(),
                provider_source,
                RequestSigner::new("sts", REGION),
            ),
        )
        .with_policy(r#"{"Statement":"provider-policy-secret"}"#.to_string())
        .with_mfa_code("111111".to_string());
        let provider_debug = format!("{provider:?}");
        assert!(!provider_debug.contains("provider-policy-secret"));
        assert!(!provider_debug.contains("111111"));
    }
}
