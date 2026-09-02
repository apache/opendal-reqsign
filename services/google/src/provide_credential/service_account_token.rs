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

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

use form_urlencoded::Serializer;
use http::header::CONTENT_TYPE;
use log::debug;
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, ErrorKind, ProvideCredential, ProvideCredentialDyn, Result, SigningCredential,
};
use serde::{Deserialize, Serialize};

use crate::constants::{DEFAULT_SCOPE, GOOGLE_SCOPE, TOKEN_OPERATION_HEADROOM};
use crate::credential::{Credential, ServiceAccount, Token};

const OAUTH_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const JWT_LIFETIME: Duration = Duration::from_secs(3600);

#[derive(Debug, Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'static str,
    exp: u64,
    iat: u64,
}

impl<'a> Claims<'a> {
    fn new(client_email: &'a str, scope: &'a str, now: Timestamp) -> Result<Self> {
        let iat = u64::try_from(now.as_second())
            .map_err(|_| Error::unexpected("service account JWT timestamp is invalid"))?;
        let exp = iat
            .checked_add(JWT_LIFETIME.as_secs())
            .ok_or_else(|| Error::unexpected("service account JWT timestamp is invalid"))?;
        Ok(Self {
            iss: client_email,
            scope,
            aud: OAUTH_TOKEN_ENDPOINT,
            exp,
            iat,
        })
    }
}

#[derive(Debug, Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

impl JwtHeader {
    fn rs256() -> Self {
        Self {
            alg: "RS256",
            typ: "JWT",
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone)]
enum Source {
    ServiceAccount(ServiceAccount),
    Provider(Arc<dyn ProvideCredentialDyn<Credential = Credential>>),
}

/// Exchanges a service-account credential for an OAuth access token.
///
/// The provider returns a token-only [`Credential`] with a non-optional absolute
/// expiration and preserves the source service account email as signer identity.
/// This makes service-account JSON loaded by providers such as
/// [`super::FileCredentialProvider`] usable as the source of a Google credential
/// granter without requiring the host application to implement the JWT bearer
/// exchange.
///
/// The provider performs an OAuth exchange on every call. Cache and refresh
/// behavior remains owned by the outer [`reqsign_core::Signer`] or
/// [`reqsign_core::Granter`]. It is not inserted into the default credential
/// provider chain.
///
/// # Example
///
/// ```no_run
/// use reqsign_core::{Context, Granter};
/// use reqsign_google::{
///     CredentialAccessBoundaryGrant, CredentialAccessBoundaryPermissions,
///     FileCredentialProvider, ServerSideCredentialAccessBoundaryGranter,
///     ServiceAccountTokenCredentialProvider,
/// };
///
/// # async fn example(context: Context) -> reqsign_core::Result<()> {
/// let source = ServiceAccountTokenCredentialProvider::from_provider(
///     FileCredentialProvider::new("/path/to/service-account.json"),
/// );
/// let grant = CredentialAccessBoundaryGrant::for_object_prefix(
///     "example-bucket",
///     "customer-a/",
///     CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
/// );
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
pub struct ServiceAccountTokenCredentialProvider {
    source: Source,
    scope: Option<String>,
}

impl Debug for ServiceAccountTokenCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountTokenCredentialProvider")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ServiceAccountTokenCredentialProvider {
    /// Create a provider bound to one service account.
    pub fn new(service_account: ServiceAccount) -> Self {
        Self {
            source: Source::ServiceAccount(service_account),
            scope: None,
        }
    }

    /// Create a provider that loads its service account from another provider.
    ///
    /// `None` from the source provider is preserved. A returned credential must
    /// contain a valid service account; other credential variants are rejected
    /// before the OAuth request is sent.
    pub fn from_provider(
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        Self {
            source: Source::Provider(Arc::new(provider)),
            scope: None,
        }
    }

    /// Set the OAuth scope.
    ///
    /// This value takes precedence over `GOOGLE_SCOPE`. When neither is set,
    /// the Google Cloud platform scope is used.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    async fn service_account(&self, ctx: &Context) -> Result<Option<ServiceAccount>> {
        let service_account = match &self.source {
            Source::ServiceAccount(service_account) => service_account.clone(),
            Source::Provider(provider) => {
                let credential = match provider.provide_credential_dyn(ctx).await? {
                    Some(credential) => credential,
                    None => return Ok(None),
                };
                credential.service_account.ok_or_else(|| {
                    Error::credential_invalid(
                        "service account OAuth token provider requires a service-account credential",
                    )
                })?
            }
        };

        if !service_account.is_valid() {
            return Err(Error::credential_invalid(
                "service account OAuth token provider requires a client email and private key",
            ));
        }
        Ok(Some(service_account))
    }
}

impl ProvideCredential for ServiceAccountTokenCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(service_account) = self.service_account(ctx).await? else {
            return Ok(None);
        };
        let scope = resolve_scope(ctx, self.scope.as_deref());
        let token = exchange_service_account_token(ctx, &service_account, &scope).await?;
        Ok(Some(
            Credential::with_token(token).with_signer_email(service_account.client_email),
        ))
    }
}

pub(crate) fn resolve_scope(ctx: &Context, scope: Option<&str>) -> String {
    scope
        .map(ToOwned::to_owned)
        .or_else(|| ctx.env_var(GOOGLE_SCOPE))
        .unwrap_or_else(|| DEFAULT_SCOPE.to_string())
}

pub(crate) async fn exchange_service_account_token(
    ctx: &Context,
    service_account: &ServiceAccount,
    scope: &str,
) -> Result<Token> {
    if !service_account.is_valid() {
        return Err(Error::credential_invalid(
            "service account OAuth exchange requires a client email and private key",
        ));
    }

    debug!("exchanging service account for token with scope: {scope}");
    let request = build_token_request(service_account, scope, Timestamp::now())?;
    let request_started_at = Timestamp::now();
    let response = ctx.http_send(request).await.map_err(|err| {
        Error::new(err.kind(), "service account OAuth token request failed")
            .set_retryable(err.is_retryable())
    })?;
    let completed_at = Timestamp::now();

    if response.status() != http::StatusCode::OK {
        return Err(oauth_error(response.status(), response.body()));
    }
    let token = parse_token_response(response.body(), request_started_at)?;
    validate_token(&token, completed_at)?;
    Ok(token)
}

fn build_token_request(
    service_account: &ServiceAccount,
    scope: &str,
    now: Timestamp,
) -> Result<http::Request<bytes::Bytes>> {
    let jwt = reqsign_core::jwt::encode_rs256_pem(
        &JwtHeader::rs256(),
        &Claims::new(&service_account.client_email, scope, now)?,
        service_account.private_key.as_bytes(),
    )?;
    let body = Serializer::new(String::new())
        .append_pair("grant_type", JWT_BEARER_GRANT_TYPE)
        .append_pair("assertion", &jwt)
        .finish();

    http::Request::builder()
        .method(http::Method::POST)
        .uri(OAUTH_TOKEN_ENDPOINT)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.into_bytes().into())
        .map_err(|err| {
            Error::unexpected("failed to build service account OAuth token request")
                .with_source(err)
        })
}

fn parse_token_response(body: &[u8], request_started_at: Timestamp) -> Result<Token> {
    let response: TokenResponse = serde_json::from_slice(body)
        .map_err(|_| Error::unexpected("failed to parse service account OAuth token response"))?;
    if response.access_token.is_empty() || response.expires_in == 0 {
        return Err(Error::unexpected(
            "service account OAuth token response is malformed",
        ));
    }
    let expires_at =
        checked_expiration(request_started_at, Duration::from_secs(response.expires_in))?;
    Ok(Token {
        access_token: response.access_token,
        expires_at: Some(expires_at),
    })
}

fn validate_token(token: &Token, completed_at: Timestamp) -> Result<()> {
    let required_until = checked_expiration(completed_at, TOKEN_OPERATION_HEADROOM)?;
    if !token.is_valid_at(required_until) {
        return Err(Error::credential_invalid(
            "service account OAuth token is not valid long enough for Google signing",
        ));
    }
    Ok(())
}

fn checked_expiration(started_at: Timestamp, expires_in: Duration) -> Result<Timestamp> {
    let expires_in_seconds = i64::try_from(expires_in.as_secs())
        .map_err(|_| Error::unexpected("service account OAuth token expiration is invalid"))?;
    let expiration_second = started_at
        .as_second()
        .checked_add(expires_in_seconds)
        .ok_or_else(|| Error::unexpected("service account OAuth token expiration is invalid"))?;
    Timestamp::from_second(expiration_second)
        .map_err(|_| Error::unexpected("service account OAuth token expiration is invalid"))
}

fn oauth_error(status: http::StatusCode, body: &[u8]) -> Error {
    let error_code = serde_json::from_slice::<OAuthErrorResponse>(body)
        .ok()
        .and_then(|response| response.error);
    let recognized_code = match error_code.as_deref() {
        Some(
            code @ ("invalid_grant"
            | "invalid_request"
            | "invalid_scope"
            | "unsupported_grant_type"
            | "unauthorized_client"
            | "invalid_client"
            | "access_denied"
            | "temporarily_unavailable"),
        ) => Some(code),
        _ => None,
    };

    let mut error = match recognized_code {
        Some("invalid_grant" | "invalid_client") => Error::credential_invalid(
            "service account OAuth token exchange rejected the source credential",
        ),
        Some("invalid_request" | "invalid_scope" | "unsupported_grant_type") => {
            Error::request_invalid("service account OAuth token exchange rejected the request")
        }
        Some("unauthorized_client" | "access_denied") => {
            Error::permission_denied("service account OAuth token exchange was denied")
        }
        Some("temporarily_unavailable") => {
            Error::unexpected("service account OAuth token exchange is temporarily unavailable")
                .set_retryable(true)
        }
        _ if status == http::StatusCode::UNAUTHORIZED => Error::credential_invalid(
            "service account OAuth token exchange rejected the source credential",
        ),
        _ if status == http::StatusCode::FORBIDDEN => {
            Error::permission_denied("service account OAuth token exchange was denied")
        }
        _ if status == http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("service account OAuth token exchange was rate limited")
        }
        _ => Error::unexpected("service account OAuth token exchange failed")
            .set_retryable(status.is_server_error()),
    }
    .with_context(format!("oauth_status: {}", status.as_u16()));

    if let Some(code) = recognized_code {
        error = error.with_context(format!("oauth_error: {code}"));
    }
    if error.kind() == ErrorKind::Unexpected && status.is_server_error() {
        error = error.set_retryable(true);
    }
    error
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use reqsign_core::hash::base64_decode;
    use reqsign_core::{FileRead, Granter, HttpSend, SignRequest, StaticEnv, time::Timestamp};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use serde_json::Value;

    use crate::{
        CredentialAccessBoundaryGrant, CredentialAccessBoundaryPermissions,
        DefaultCredentialProvider, FileCredentialProvider, RequestSigner,
        ServerSideCredentialAccessBoundaryGranter, StaticCredentialProvider,
    };

    use super::*;

    #[derive(Debug)]
    struct CapturedRequest {
        method: Method,
        uri: String,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    struct MockHttpSend {
        responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn requests(&self) -> std::sync::MutexGuard<'_, Vec<CapturedRequest>> {
            self.requests.lock().expect("lock must not be poisoned")
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            let (parts, body) = request.into_parts();
            self.requests
                .lock()
                .expect("lock must not be poisoned")
                .push(CapturedRequest {
                    method: parts.method,
                    uri: parts.uri.to_string(),
                    headers: parts.headers,
                    body: body.to_vec(),
                });
            self.responses
                .lock()
                .expect("lock must not be poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock HTTP response is missing"))
        }
    }

    #[derive(Clone, Debug)]
    struct FixedFileRead {
        content: Arc<Vec<u8>>,
    }

    impl FixedFileRead {
        fn new(content: impl Into<Vec<u8>>) -> Self {
            Self {
                content: Arc::new(content.into()),
            }
        }
    }

    impl FileRead for FixedFileRead {
        async fn file_read(&self, _path: &str) -> Result<Vec<u8>> {
            Ok(self.content.as_ref().clone())
        }
    }

    #[derive(Debug)]
    struct FixedProvider {
        credential: Option<Credential>,
    }

    impl ProvideCredential for FixedProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(self.credential.clone())
        }
    }

    fn service_account() -> ServiceAccount {
        let key = RsaPrivateKey::new(&mut OsRng, 1024).expect("test RSA key must generate");
        let private_key = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("test RSA key must encode")
            .to_string();
        ServiceAccount {
            private_key,
            client_email: "provider@example.iam.gserviceaccount.com".to_string(),
        }
    }

    fn service_account_json(service_account: &ServiceAccount) -> String {
        serde_json::json!({
            "type": "service_account",
            "private_key": service_account.private_key,
            "client_email": service_account.client_email,
        })
        .to_string()
    }

    fn response(status: http::StatusCode, body: impl Into<Bytes>) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(body.into())
            .expect("response must build")
    }

    fn oauth_success(access_token: &str, expires_in: u64) -> http::Response<Bytes> {
        response(
            http::StatusCode::OK,
            serde_json::to_vec(&serde_json::json!({
                "access_token": access_token,
                "expires_in": expires_in,
                "token_type": "Bearer",
            }))
            .expect("response JSON must serialize"),
        )
    }

    fn cab_success(access_token: &str, expires_in: u64) -> http::Response<Bytes> {
        response(
            http::StatusCode::OK,
            serde_json::to_vec(&serde_json::json!({
                "access_token": access_token,
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": expires_in,
            }))
            .expect("response JSON must serialize"),
        )
    }

    fn form_fields(body: &[u8]) -> BTreeMap<String, String> {
        form_urlencoded::parse(body).into_owned().collect()
    }

    fn decode_jwt_json(segment: &str) -> Value {
        let mut standard = segment.replace('-', "+").replace('_', "/");
        while standard.len() % 4 != 0 {
            standard.push('=');
        }
        serde_json::from_slice(&base64_decode(&standard).expect("JWT segment must decode"))
            .expect("JWT segment must contain JSON")
    }

    #[tokio::test]
    async fn exchanges_service_account_with_exact_request_shape() -> Result<()> {
        let http = MockHttpSend::new([oauth_success("source-token", 3600)]);
        let service_account = service_account();
        let provider = ServiceAccountTokenCredentialProvider::new(service_account.clone())
            .with_scope("scope-a scope-b");
        let output = provider
            .provide_credential(&Context::new().with_http_send(http.clone()))
            .await?
            .expect("credential must be returned");

        assert!(output.service_account.is_none());
        assert_eq!(
            output.signer_email.as_deref(),
            Some(service_account.client_email.as_str())
        );
        let token = output.token.expect("token must be present");
        assert_eq!(token.access_token, "source-token");
        assert!(token.expires_at.is_some());

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.uri, OAUTH_TOKEN_ENDPOINT);
        assert_eq!(
            request.headers[CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );

        let fields = form_fields(&request.body);
        assert_eq!(fields["grant_type"], JWT_BEARER_GRANT_TYPE);
        let segments = fields["assertion"].split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3);
        assert_eq!(
            decode_jwt_json(segments[0]),
            serde_json::json!({"alg": "RS256", "typ": "JWT"})
        );
        let claims = decode_jwt_json(segments[1]);
        assert_eq!(claims["iss"], service_account.client_email);
        assert_eq!(claims["scope"], "scope-a scope-b");
        assert_eq!(claims["aud"], OAUTH_TOKEN_ENDPOINT);
        assert_eq!(
            claims["exp"].as_u64().expect("exp must be an integer")
                - claims["iat"].as_u64().expect("iat must be an integer"),
            JWT_LIFETIME.as_secs()
        );
        Ok(())
    }

    #[test]
    fn scope_precedence_is_explicit_then_environment_then_default() {
        let ctx = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([(GOOGLE_SCOPE.to_string(), "environment-scope".to_string())]),
        });
        assert_eq!(
            resolve_scope(&ctx, Some("explicit-scope")),
            "explicit-scope"
        );
        assert_eq!(resolve_scope(&ctx, None), "environment-scope");
        assert_eq!(resolve_scope(&Context::new(), None), DEFAULT_SCOPE);
    }

    #[tokio::test]
    async fn rejects_invalid_source_before_oauth_io_and_preserves_none() -> Result<()> {
        let http = MockHttpSend::default();
        let ctx = Context::new().with_http_send(http.clone());

        let missing = ServiceAccountTokenCredentialProvider::from_provider(FixedProvider {
            credential: None,
        });
        assert!(missing.provide_credential(&ctx).await?.is_none());

        let wrong_variant = ServiceAccountTokenCredentialProvider::from_provider(FixedProvider {
            credential: Some(Credential::with_token(Token {
                access_token: "source-token".to_string(),
                expires_at: None,
            })),
        });
        let err = wrong_variant
            .provide_credential(&ctx)
            .await
            .expect_err("token-only source must be rejected");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);

        let invalid_key = ServiceAccountTokenCredentialProvider::new(ServiceAccount {
            private_key: "private-key-secret".to_string(),
            client_email: "provider@example.iam.gserviceaccount.com".to_string(),
        });
        let err = invalid_key
            .provide_credential(&ctx)
            .await
            .expect_err("invalid private key must be rejected");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.requests().len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn accepts_file_and_default_service_account_sources() -> Result<()> {
        let service_account = service_account();
        let content = service_account_json(&service_account).into_bytes();

        let file_http = MockHttpSend::new([oauth_success("file-token", 3600)]);
        let file_context = Context::new()
            .with_file_read(FixedFileRead::new(content.clone()))
            .with_http_send(file_http);
        let file_output = ServiceAccountTokenCredentialProvider::from_provider(
            FileCredentialProvider::new("/service-account.json"),
        )
        .provide_credential(&file_context)
        .await?
        .expect("file source must return a credential");
        assert_eq!(
            file_output
                .token
                .expect("file source token must be present")
                .access_token,
            "file-token"
        );

        let default_http = MockHttpSend::new([oauth_success("default-token", 3600)]);
        let default_context = Context::new()
            .with_file_read(FixedFileRead::new(content))
            .with_http_send(default_http)
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    crate::constants::GOOGLE_APPLICATION_CREDENTIALS.to_string(),
                    "/service-account.json".to_string(),
                )]),
            });
        let default_output =
            ServiceAccountTokenCredentialProvider::from_provider(DefaultCredentialProvider::new())
                .provide_credential(&default_context)
                .await?
                .expect("default source must return a credential");
        assert_eq!(
            default_output
                .token
                .expect("default source token must be present")
                .access_token,
            "default-token"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_token_that_is_too_short_after_oauth_io() {
        let http = MockHttpSend::new([oauth_success("short-token", 5)]);
        let err = ServiceAccountTokenCredentialProvider::new(service_account())
            .provide_credential(&Context::new().with_http_send(http.clone()))
            .await
            .expect_err("short OAuth token must be rejected");

        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.requests().len(), 1);
    }

    #[test]
    fn expiration_is_anchored_and_checked_without_panicking() {
        let started_at: Timestamp = "2030-01-01T00:00:00Z"
            .parse()
            .expect("timestamp must parse");
        let token = parse_token_response(
            br#"{"access_token":"source-token","expires_in":3600}"#,
            started_at,
        )
        .expect("response must parse");
        assert_eq!(
            token.expires_at,
            Some(
                "2030-01-01T01:00:00Z"
                    .parse()
                    .expect("timestamp must parse")
            )
        );

        let near_limit: Timestamp = "9999-12-30T21:59:59Z"
            .parse()
            .expect("timestamp must parse");
        let err = parse_token_response(
            br#"{"access_token":"source-token","expires_in":2}"#,
            near_limit,
        )
        .expect_err("overflow must be rejected");
        assert_eq!(err.kind(), ErrorKind::Unexpected);

        for malformed in [
            br#"{"access_token":"source-token"}"#.as_slice(),
            br#"{"access_token":"","expires_in":3600}"#.as_slice(),
            br#"{"access_token":"source-token","expires_in":0}"#.as_slice(),
        ] {
            assert!(parse_token_response(malformed, started_at).is_err());
        }
    }

    #[tokio::test]
    async fn redacts_provider_debug_and_oauth_errors() {
        let service_account = service_account();
        let source_json = service_account_json(&service_account);
        let provider = ServiceAccountTokenCredentialProvider::from_provider(
            StaticCredentialProvider::new(source_json),
        );
        let debug = format!("{provider:?}");
        assert!(!debug.contains(&service_account.private_key));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        let body = br#"{
            "error":"invalid_grant",
            "error_description":"private-key-secret assertion-secret access-token-secret"
        }"#;
        let http = MockHttpSend::new([response(http::StatusCode::BAD_REQUEST, body.as_slice())]);
        let err = provider
            .provide_credential(&Context::new().with_http_send(http))
            .await
            .expect_err("OAuth error must be returned");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        let rendered = format!("{err:?}");
        assert!(rendered.contains("oauth_error: invalid_grant"));
        assert!(!rendered.contains("private-key-secret"));
        assert!(!rendered.contains("assertion-secret"));
        assert!(!rendered.contains("access-token-secret"));
    }

    #[tokio::test]
    async fn composes_static_service_account_with_server_side_cab() -> Result<()> {
        let http = MockHttpSend::new([
            oauth_success("source-token", 3600),
            cab_success("downscoped-token", 600),
        ]);
        let service_account = service_account();
        let source = ServiceAccountTokenCredentialProvider::from_provider(
            StaticCredentialProvider::new(service_account_json(&service_account)),
        );
        let grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "customer-a/",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        );
        let output = Granter::new(
            Context::new().with_http_send(http.clone()),
            source,
            ServerSideCredentialAccessBoundaryGranter::new(grant),
        )
        .grant(None)
        .await?;

        assert!(output.service_account.is_none());
        let token = output.token.expect("downscoped token must be present");
        assert_eq!(token.access_token, "downscoped-token");
        assert!(token.expires_at.is_some());

        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].uri, OAUTH_TOKEN_ENDPOINT);
        assert_eq!(requests[1].uri, "https://sts.googleapis.com/v1/token");
        assert_eq!(
            form_fields(&requests[1].body)["subject_token"],
            "source-token"
        );
        Ok(())
    }

    #[tokio::test]
    async fn request_signer_uses_shared_service_account_exchange() -> Result<()> {
        let http = MockHttpSend::new([oauth_success("source-token", 3600)]);
        let credential = Credential::with_service_account(service_account());
        let mut request = http::Request::get("https://storage.googleapis.com/bucket/object")
            .body(())?
            .into_parts()
            .0;

        RequestSigner::new("storage")
            .sign_request(
                &Context::new().with_http_send(http.clone()),
                &mut request,
                Some(&credential),
                None,
            )
            .await?;

        assert_eq!(
            request.headers[http::header::AUTHORIZATION],
            "Bearer source-token"
        );
        assert_eq!(http.requests().len(), 1);
        assert_eq!(http.requests()[0].uri, OAUTH_TOKEN_ENDPOINT);
        Ok(())
    }
}
