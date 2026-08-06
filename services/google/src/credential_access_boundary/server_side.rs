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

use std::fmt::{self, Debug};
use std::time::Duration;

use form_urlencoded::Serializer;
use http::header::{ACCEPT, CONTENT_TYPE};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use serde::Deserialize;

use super::CredentialAccessBoundaryGrant;
use super::sts::{
    ACCESS_TOKEN_TYPE, MAX_ACCESS_TOKEN_LIFETIME, STS_ENDPOINT, TOKEN_EXCHANGE_GRANT_TYPE,
    checked_expiration, sts_error,
};
use crate::constants::TOKEN_OPERATION_HEADROOM;
use crate::{Credential, Token};

const TOKEN_EXCHANGE_HEADROOM: Duration = Duration::from_secs(10);

/// Exchanges a Google OAuth access token for a server-issued CAB token.
///
/// The bound grant is stable configuration. Construct another granter (or use
/// [`ServerSideCredentialAccessBoundaryGranter::with_grant`]) for a different
/// authorization decision. The server-side CAB exchange does not accept a
/// requested lifetime, so [`reqsign_core::Granter::grant`] must be called with
/// `None`.
///
/// The source must be a token-only [`Credential`] containing a Google-issued
/// OAuth access token with a known absolute expiration and the
/// `https://www.googleapis.com/auth/cloud-platform` scope. Server-issued CAB
/// tokens support user and service-account principals. STS rejects tokens that
/// already carry security attributes; the opaque token string does not expose
/// enough information to detect its principal, scope, or existing attributes
/// locally. Credentials with unknown expiration or an attached service account
/// are rejected before STS I/O.
///
/// The returned [`Credential`] is token-only and can be consumed directly by
/// the existing Google [`crate::RequestSigner`]. Every grant performs a new STS
/// exchange; the service layer does not cache granted outputs.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter, time::Timestamp};
/// use reqsign_google::{
///     CredentialAccessBoundaryGrant, CredentialAccessBoundaryPermissions,
///     ServerSideCredentialAccessBoundaryGranter, TokenCredentialProvider,
/// };
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = TokenCredentialProvider::new("source-oauth-token")
///     .with_expires_at(Timestamp::now() + Duration::from_secs(3600));
/// let grant = CredentialAccessBoundaryGrant::for_object_prefix(
///     "example-bucket",
///     "customer-a/",
///     CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
/// );
/// // Supply a Context configured with an HttpSend implementation.
/// let context = Context::new();
/// let credential = Granter::new(
///     context,
///     source,
///     ServerSideCredentialAccessBoundaryGranter::new(grant),
/// )
/// .grant(None)
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ServerSideCredentialAccessBoundaryGranter {
    grant: CredentialAccessBoundaryGrant,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for ServerSideCredentialAccessBoundaryGranter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSideCredentialAccessBoundaryGranter")
            .finish_non_exhaustive()
    }
}

impl ServerSideCredentialAccessBoundaryGranter {
    /// Create a server-side granter for a bound Credential Access Boundary.
    pub fn new(grant: CredentialAccessBoundaryGrant) -> Self {
        Self {
            grant,
            #[cfg(test)]
            now: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound grant.
    pub fn with_grant(mut self, grant: CredentialAccessBoundaryGrant) -> Self {
        self.grant = grant;
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    fn time_after_request(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.time_after_request {
            return now;
        }
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    #[cfg(test)]
    fn with_time(mut self, now: Timestamp) -> Self {
        self.now = Some(now);
        self.time_after_request = Some(now);
        self
    }

    #[cfg(test)]
    fn with_time_after_request(mut self, now: Timestamp) -> Self {
        self.time_after_request = Some(now);
        self
    }

    fn source_token<'a>(
        &self,
        credential: &'a Credential,
        required_until: Timestamp,
    ) -> Result<&'a Token> {
        if credential.service_account.is_some() {
            return Err(Error::credential_invalid(
                "server-side credential access boundary exchange requires a token-only source credential",
            ));
        }
        let token = credential.token.as_ref().ok_or_else(|| {
            Error::credential_invalid(
                "server-side credential access boundary exchange requires an OAuth access token",
            )
        })?;
        if token.access_token.is_empty() {
            return Err(Error::credential_invalid(
                "server-side credential access boundary source access token is empty",
            ));
        }
        if token.expires_at.is_none() {
            return Err(Error::credential_invalid(
                "server-side credential access boundary source token expiration is required",
            ));
        }
        if !token.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "source OAuth access token expires before the server-side CAB exchange can complete",
            ));
        }
        Ok(token)
    }

    fn build_request(
        &self,
        source_token: &str,
        options: &str,
    ) -> Result<http::Request<bytes::Bytes>> {
        let body = Serializer::new(String::new())
            .append_pair("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
            .append_pair("requested_token_type", ACCESS_TOKEN_TYPE)
            .append_pair("subject_token_type", ACCESS_TOKEN_TYPE)
            .append_pair("subject_token", source_token)
            .append_pair("options", options)
            .finish();

        http::Request::builder()
            .method(http::Method::POST)
            .uri(STS_ENDPOINT)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())
            .map_err(|err| {
                Error::unexpected("failed to build server-side CAB request").with_source(err)
            })
    }

    fn parse_response(
        &self,
        response: http::Response<bytes::Bytes>,
        source: &Token,
        response_time: Timestamp,
    ) -> Result<Credential> {
        if response.status() != http::StatusCode::OK {
            return Err(sts_error(response.status(), response.body()));
        }

        let token_response: StsTokenResponse = serde_json::from_slice(response.body())
            .map_err(|_| Error::unexpected("failed to parse server-side CAB STS response"))?;
        if token_response.access_token.is_empty()
            || token_response.issued_token_type != ACCESS_TOKEN_TYPE
            || token_response.token_type != "Bearer"
        {
            return Err(Error::unexpected(
                "server-side CAB STS response is malformed",
            ));
        }

        let source_expiration = source.expires_at.ok_or_else(|| {
            Error::credential_invalid(
                "server-side credential access boundary source token expiration is required",
            )
        })?;
        if source_expiration <= response_time {
            return Err(Error::credential_invalid(
                "source OAuth access token expired during the server-side CAB exchange",
            ));
        }

        let response_expiration = token_response
            .expires_in
            .map(|expires_in| {
                let expires_in = Duration::from_secs(expires_in);
                if expires_in.is_zero() || expires_in > MAX_ACCESS_TOKEN_LIFETIME {
                    return Err(Error::unexpected(
                        "server-side CAB STS expiration is invalid",
                    ));
                }
                checked_expiration(response_time, expires_in)
            })
            .transpose()?;
        let expires_at = response_expiration
            .map(|response| response.min(source_expiration))
            .unwrap_or(source_expiration);
        if expires_at <= response_time {
            return Err(Error::unexpected(
                "server-side CAB STS token is already expired",
            ));
        }

        let credential = Credential::with_token(Token {
            access_token: token_response.access_token,
            expires_at: Some(expires_at),
        });
        let required_until = checked_expiration(response_time, TOKEN_OPERATION_HEADROOM)?;
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "server-issued CAB token is not valid long enough for Google signing",
            ));
        }
        Ok(credential)
    }
}

impl GrantCredential for ServerSideCredentialAccessBoundaryGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + TOKEN_EXCHANGE_HEADROOM + TOKEN_OPERATION_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        if expires_in.is_some() {
            return Err(Error::request_invalid(
                "server-side credential access boundary exchange does not accept a requested lifetime",
            ));
        }

        let options = self.grant.options_json()?;
        let required_until = self.required_valid_until(credential, expires_in);
        let source = self.source_token(credential, required_until)?;
        let request = self.build_request(&source.access_token, &options)?;
        let response = ctx.http_send(request).await.map_err(|err| {
            Error::new(err.kind(), "server-side CAB STS request failed")
                .set_retryable(err.is_retryable())
        })?;
        self.parse_response(response, source, self.time_after_request())
    }
}

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    issued_token_type: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::fmt::Formatter;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http::header::{AUTHORIZATION, HeaderMap};
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer};

    use super::*;
    use crate::{CredentialAccessBoundaryPermissions, RequestSigner, ServiceAccount};

    #[derive(Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("CapturedRequest")
                .field("method", &self.method)
                .field("uri", &self.uri)
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
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
                    body: body.to_vec(),
                });
            self.responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock response queue is empty"))
        }
    }

    #[derive(Debug)]
    struct SecretTransportError;

    impl HttpSend for SecretTransportError {
        async fn http_send(&self, _request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            Err(
                Error::unexpected("transport captured subject_token=source-secret")
                    .set_retryable(true),
            )
        }
    }

    #[derive(Clone)]
    struct FixedCredentialProvider {
        credential: Credential,
        calls: Arc<AtomicUsize>,
    }

    impl Debug for FixedCredentialProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must be valid")
    }

    fn source_token(access_token: &str, expires_at: Option<Timestamp>) -> Credential {
        Credential::with_token(Token {
            access_token: access_token.to_string(),
            expires_at,
        })
    }

    fn response(status: http::StatusCode, body: impl Into<Bytes>) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(body.into())
            .expect("response must build")
    }

    fn success_response(access_token: &str, expires_in: Option<u64>) -> http::Response<Bytes> {
        let mut value = serde_json::json!({
            "access_token": access_token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer"
        });
        if let Some(expires_in) = expires_in {
            value["expires_in"] = expires_in.into();
        }
        response(
            http::StatusCode::OK,
            serde_json::to_vec(&value).expect("response JSON must serialize"),
        )
    }

    fn viewer_bucket_grant() -> CredentialAccessBoundaryGrant {
        CredentialAccessBoundaryGrant::for_bucket(
            "example-bucket",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        )
    }

    fn form_fields(request: &CapturedRequest) -> BTreeMap<String, String> {
        form_urlencoded::parse(&request.body).into_owned().collect()
    }

    fn output_token(credential: &Credential) -> &Token {
        assert!(credential.service_account.is_none());
        credential
            .token
            .as_ref()
            .expect("granted credential must contain a token")
    }

    #[tokio::test]
    async fn sends_exact_server_side_exchange_shape() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:02Z");
        let http = MockHttpSend::new([success_response("downscoped-token", Some(3600))]);
        let operation = ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time);
        let output = operation
            .grant_credential(
                &Context::new().with_http_send(http.clone()),
                &source_token("source-token", Some(timestamp("2030-01-01T02:00:00Z"))),
                None,
            )
            .await
            .expect("token exchange must succeed");

        assert_eq!(output_token(&output).access_token, "downscoped-token");
        assert_eq!(
            output_token(&output).expires_at,
            Some(timestamp("2030-01-01T01:00:02Z"))
        );
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, http::Method::POST);
        assert_eq!(request.uri, STS_ENDPOINT);
        assert_eq!(request.headers[ACCEPT], "application/json");
        assert_eq!(
            request.headers[CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        assert!(!request.headers.contains_key(AUTHORIZATION));
        assert_eq!(
            String::from_utf8(request.body.clone()).expect("form body must be UTF-8"),
            concat!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
                "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                "&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                "&subject_token=source-token",
                "&options=%7B%22accessBoundary%22%3A%7B%22accessBoundaryRules%22%3A%5B%7B",
                "%22availableResource%22%3A%22%2F%2Fstorage.googleapis.com%2Fprojects%2F_",
                "%2Fbuckets%2Fexample-bucket%22%2C%22availablePermissions%22%3A%5B",
                "%22inRole%3Aroles%2Fstorage.objectViewer%22%5D%7D%5D%7D%7D"
            )
        );
    }

    #[tokio::test]
    async fn form_encoding_keeps_source_and_policy_separate() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source = "source+token/%=&options=broader";
        let http = MockHttpSend::new([success_response("downscoped-token", Some(3600))]);
        let operation = ServerSideCredentialAccessBoundaryGranter::new(
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "tenant&rule=broader",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
        )
        .with_time(now);

        operation
            .grant_credential(
                &Context::new().with_http_send(http.clone()),
                &source_token(source, Some(timestamp("2030-01-01T02:00:00Z"))),
                None,
            )
            .await
            .expect("token exchange must succeed");

        let request = &http.requests()[0];
        let fields = form_fields(request);
        assert_eq!(fields.len(), 5);
        assert_eq!(fields["grant_type"], TOKEN_EXCHANGE_GRANT_TYPE);
        assert_eq!(fields["requested_token_type"], ACCESS_TOKEN_TYPE);
        assert_eq!(fields["subject_token_type"], ACCESS_TOKEN_TYPE);
        assert_eq!(fields["subject_token"], source);
        assert!(fields["options"].contains("tenant&rule=broader"));
        let raw = String::from_utf8(request.body.clone()).expect("form body must be UTF-8");
        assert!(raw.contains("subject_token=source%2Btoken%2F%25%3D%26options%3Dbroader"));
        assert!(!raw.contains("&options=broader&"));
    }

    #[tokio::test]
    async fn rejects_invalid_policy_lifetime_and_source_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let valid_source = source_token("source", Some(timestamp("2030-01-01T02:00:00Z")));

        let invalid_grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        );
        let err = ServerSideCredentialAccessBoundaryGranter::new(invalid_grant)
            .with_time(now)
            .grant_credential(&ctx, &valid_source, None)
            .await
            .expect_err("invalid grant must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);

        let operation =
            ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let err = operation
            .grant_credential(&ctx, &valid_source, Some(Duration::from_secs(60)))
            .await
            .expect_err("server-side lifetime selection must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);

        let mut mixed = valid_source.clone();
        mixed.service_account = Some(ServiceAccount {
            private_key: "private-secret".to_string(),
            client_email: "service@example.com".to_string(),
        });
        let invalid_sources = [
            Credential::with_service_account(ServiceAccount {
                private_key: "private-secret".to_string(),
                client_email: "service@example.com".to_string(),
            }),
            mixed,
            source_token("", Some(timestamp("2030-01-01T02:00:00Z"))),
            source_token("unknown-expiration", None),
            source_token("expiring", Some(timestamp("2030-01-01T00:00:20Z"))),
        ];
        for source in invalid_sources {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("incompatible source must fail");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            let debug = format!("{err:?}");
            assert!(!debug.contains("private-secret"));
            assert!(!debug.contains("unknown-expiration"));
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn anchors_clamps_and_revalidates_expiration_after_io() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:05Z");
        let source_expiry = timestamp("2030-01-01T00:10:00Z");
        let http = MockHttpSend::new([
            success_response("anchored", Some(300)),
            success_response("inherited", None),
            success_response("clamped", Some(3600)),
            success_response("too-short", Some(10)),
            success_response("source-expired", Some(3600)),
        ]);
        let operation = ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time);
        let ctx = Context::new().with_http_send(http);
        let source = source_token("source", Some(source_expiry));

        let anchored = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("explicit expiration must succeed");
        assert_eq!(
            output_token(&anchored).expires_at,
            Some(timestamp("2030-01-01T00:05:05Z"))
        );
        let inherited = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("missing expires_in must inherit source expiration");
        assert_eq!(output_token(&inherited).expires_at, Some(source_expiry));
        let clamped = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("STS expiration must clamp to source expiration");
        assert_eq!(output_token(&clamped).expires_at, Some(source_expiry));

        let err = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect_err("short output must fail after I/O");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        let err = operation
            .grant_credential(
                &ctx,
                &source_token("source-expired", Some(response_time)),
                None,
            )
            .await
            .expect_err("source expiry during I/O must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
    }

    #[tokio::test]
    async fn accepts_maximum_documented_access_token_lifetime() {
        let response_time = timestamp("2030-01-01T00:00:05Z");
        let output = ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(timestamp("2030-01-01T00:00:00Z"))
            .with_time_after_request(response_time)
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "downscoped-token",
                    Some(MAX_ACCESS_TOKEN_LIFETIME.as_secs()),
                )])),
                &source_token("source-token", Some(timestamp("2030-01-02T00:00:00Z"))),
                None,
            )
            .await
            .expect("maximum documented lifetime must be accepted");

        assert_eq!(
            output_token(&output).expires_at,
            Some(timestamp("2030-01-01T12:00:05Z"))
        );
    }

    #[tokio::test]
    async fn validates_malformed_success_and_sts_error_without_secrets() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let responses = [
            response(http::StatusCode::OK, br#"{}"#.as_slice()),
            success_response("", Some(3600)),
            success_response("response-secret", Some(0)),
            success_response(
                "response-secret",
                Some(MAX_ACCESS_TOKEN_LIFETIME.as_secs() + 1),
            ),
            response(
                http::StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant","error_description":"source-secret"}"#,
            ),
            response(
                http::StatusCode::FORBIDDEN,
                r#"{"error":"access_denied","error_description":"response-secret"}"#,
            ),
            response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"backend_error","error_description":"response-secret"}"#,
            ),
        ];
        let http = MockHttpSend::new(responses);
        let operation =
            ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let ctx = Context::new().with_http_send(http);
        let source = source_token("source-secret", Some(timestamp("2030-01-01T13:00:00Z")));

        let expected = [
            (ErrorKind::Unexpected, false),
            (ErrorKind::Unexpected, false),
            (ErrorKind::Unexpected, false),
            (ErrorKind::Unexpected, false),
            (ErrorKind::CredentialInvalid, false),
            (ErrorKind::PermissionDenied, false),
            (ErrorKind::Unexpected, true),
        ];
        for (kind, retryable) in expected {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("invalid response must fail");
            assert_eq!(err.kind(), kind);
            assert_eq!(err.is_retryable(), retryable);
            let debug = format!("{err:?}");
            assert!(!debug.contains("source-secret"));
            assert!(!debug.contains("response-secret"));
        }
    }

    #[tokio::test]
    async fn transport_error_is_redacted_and_classified() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let err = ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .grant_credential(
                &Context::new().with_http_send(SecretTransportError),
                &source_token("source-secret", Some(timestamp("2030-01-01T01:00:00Z"))),
                None,
            )
            .await
            .expect_err("transport error must fail");

        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());
        assert!(!format!("{err:?}").contains("source-secret"));
        assert!(!format!("{err:?}").contains("transport captured"));
    }

    #[tokio::test]
    async fn granter_caches_source_but_never_server_side_outputs() {
        let now = Timestamp::now();
        let source_expiry = now + Duration::from_secs(2 * 60 * 60);
        let (provider, provider_calls) =
            FixedCredentialProvider::new(source_token("source", Some(source_expiry)));
        let http = MockHttpSend::new([
            success_response("downscoped-1", Some(3600)),
            success_response("downscoped-2", Some(3600)),
            response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"backend_error","error_description":"do not return stale output"}"#,
            ),
        ]);
        let granter = Granter::new(
            Context::new().with_http_send(http.clone()),
            provider,
            ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now),
        );

        let first = granter.grant(None).await.expect("first grant must succeed");
        let second = granter
            .grant(None)
            .await
            .expect("second grant must succeed");
        assert_eq!(output_token(&first).access_token, "downscoped-1");
        assert_eq!(output_token(&second).access_token, "downscoped-2");
        let err = granter
            .grant(None)
            .await
            .expect_err("failed exchange must not return stale output");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn core_granter_replacements_preserve_source_cache_isolation() {
        let now = Timestamp::now();
        let source_expiry = now + Duration::from_secs(2 * 60 * 60);
        let source = source_token("source", Some(source_expiry));
        let (provider, provider_calls) = FixedCredentialProvider::new(source);
        let first_http = MockHttpSend::new([
            success_response("downscoped-1", Some(3600)),
            success_response("downscoped-2", Some(3600)),
            success_response("downscoped-3", Some(3600)),
            success_response("downscoped-provider-replaced", Some(3600)),
        ]);
        let second_http =
            MockHttpSend::new([success_response("downscoped-context-isolated", Some(3600))]);
        let operation =
            ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let granter = Granter::new(
            Context::new().with_http_send(first_http.clone()),
            provider,
            operation.clone(),
        );

        let first = granter.grant(None).await.expect("first grant must succeed");
        let second = granter
            .clone()
            .grant(None)
            .await
            .expect("clone grant must succeed");
        let replaced = granter
            .clone()
            .with_credential_granter(operation.with_grant(
                CredentialAccessBoundaryGrant::for_object_prefix(
                    "example-bucket",
                    "next/",
                    CredentialAccessBoundaryPermissions::OBJECT_CREATOR,
                ),
            ))
            .grant(None)
            .await
            .expect("replacement granter must succeed");
        let (replacement_provider, replacement_provider_calls) =
            FixedCredentialProvider::new(source_token("replacement-source", Some(source_expiry)));
        let provider_replaced = granter
            .clone()
            .with_credential_provider(replacement_provider)
            .grant(None)
            .await
            .expect("replacement provider must succeed");
        let context_isolated = granter
            .with_context(Context::new().with_http_send(second_http.clone()))
            .grant(None)
            .await
            .expect("replacement context must reload the source");

        assert_eq!(output_token(&first).access_token, "downscoped-1");
        assert_eq!(output_token(&second).access_token, "downscoped-2");
        assert_eq!(output_token(&replaced).access_token, "downscoped-3");
        assert_eq!(
            output_token(&provider_replaced).access_token,
            "downscoped-provider-replaced"
        );
        assert_eq!(
            output_token(&context_isolated).access_token,
            "downscoped-context-isolated"
        );
        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
        assert_eq!(replacement_provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first_http.calls.load(Ordering::SeqCst), 4);
        assert_eq!(second_http.calls.load(Ordering::SeqCst), 1);
        assert!(
            form_fields(&first_http.requests()[2])["options"]
                .contains("inRole:roles/storage.objectCreator")
        );
        assert_eq!(
            form_fields(&first_http.requests()[3])["subject_token"],
            "replacement-source"
        );
    }

    #[tokio::test]
    async fn server_issued_token_uses_existing_google_signer() {
        let now = Timestamp::now();
        let output = ServerSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "downscoped-token",
                    Some(3600),
                )])),
                &source_token("source-token", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect("grant must succeed");
        let (provider, _) = FixedCredentialProvider::new(output);
        let signer = Signer::new(Context::new(), provider, RequestSigner::new("storage"));
        let mut parts =
            http::Request::get("https://storage.googleapis.com/example-bucket/customer/object")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;

        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume server-issued token");
        assert_eq!(parts.headers[AUTHORIZATION], "Bearer downscoped-token");
        assert!(parts.headers[AUTHORIZATION].is_sensitive());
    }

    #[test]
    fn debug_redacts_owned_policy_and_credential_material() {
        let grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "sensitive-bucket",
            "sensitive/prefix",
            CredentialAccessBoundaryPermissions::OBJECT_ADMIN,
        );
        let operation = ServerSideCredentialAccessBoundaryGranter::new(grant.clone());
        let credential = source_token("sensitive-token", Some(Timestamp::now()));
        let captured = CapturedRequest {
            method: http::Method::POST,
            uri: STS_ENDPOINT.parse().expect("URI must parse"),
            headers: HeaderMap::new(),
            body: b"subject_token=sensitive-token".to_vec(),
        };

        for (debug, secret) in [
            (format!("{grant:?}"), "sensitive-bucket"),
            (format!("{grant:?}"), "sensitive/prefix"),
            (format!("{operation:?}"), "sensitive-bucket"),
            (format!("{credential:?}"), "sensitive-token"),
            (format!("{captured:?}"), "sensitive-token"),
        ] {
            assert!(!debug.contains(secret), "{debug}");
        }
        assert_eq!(
            format!("{operation:?}"),
            "ServerSideCredentialAccessBoundaryGranter { .. }"
        );
    }
}
