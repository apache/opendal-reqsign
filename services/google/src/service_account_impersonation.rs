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

use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use percent_encoding::utf8_percent_encode;
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, ErrorKind, GrantCredential, ProvideCredential, ProvideCredentialDyn, Result,
    SigningCredential,
};
use serde::{Deserialize, Serialize};

use crate::constants::{GOOG_URI_ENCODE_SET, TOKEN_OPERATION_HEADROOM};
use crate::{Credential, Token};

const IAM_CREDENTIALS_ENDPOINT: &str = "https://iamcredentials.googleapis.com";
const IAM_CREDENTIALS_REQUEST_HEADROOM: Duration = Duration::from_secs(10);
const MAX_ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(43_200);

/// A typed, explicitly bound IAM service-account impersonation grant.
///
/// The target service-account email, OAuth scopes, and delegate chain are
/// stable authorization configuration. Construct another grant (or use
/// [`ServiceAccountImpersonationGranter::with_grant`]) to change them. A
/// requested token lifetime is supplied separately to
/// [`reqsign_core::Granter::grant`].
///
/// Delegate values are service-account emails or numeric service-account IDs.
/// Reqsign converts them into the canonical
/// `projects/-/serviceAccounts/{identity}` resource names required by Google.
#[derive(Clone)]
pub struct ServiceAccountImpersonationGrant {
    target_service_account_email: String,
    scopes: Vec<String>,
    delegates: Vec<String>,
}

impl Debug for ServiceAccountImpersonationGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountImpersonationGrant")
            .finish_non_exhaustive()
    }
}

impl ServiceAccountImpersonationGrant {
    /// Create a grant for a target service-account email and OAuth scopes.
    pub fn new(
        target_service_account_email: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            target_service_account_email: target_service_account_email.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
            delegates: Vec::new(),
        }
    }

    /// Append a delegate service-account email or numeric service-account ID.
    pub fn with_delegate(mut self, delegate: impl Into<String>) -> Self {
        self.delegates.push(delegate.into());
        self
    }

    /// Append a chain of delegate service-account emails or numeric IDs.
    pub fn with_delegates(
        mut self,
        delegates: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.delegates.extend(delegates.into_iter().map(Into::into));
        self
    }

    fn validate(&self) -> Result<ValidatedGrant> {
        if !is_service_account_email(&self.target_service_account_email) {
            return Err(Error::request_invalid(
                "Google service-account impersonation target must be a valid service-account email",
            ));
        }
        if self.scopes.is_empty() {
            return Err(Error::request_invalid(
                "Google service-account impersonation requires at least one OAuth scope",
            ));
        }
        if self.scopes.iter().any(|scope| !is_valid_scope(scope)) {
            return Err(Error::request_invalid(
                "Google service-account impersonation scopes must be non-empty and contain no whitespace or control characters",
            ));
        }

        let delegates = self
            .delegates
            .iter()
            .map(|delegate| {
                if !is_service_account_email(delegate)
                    && !(delegate.bytes().all(|byte| byte.is_ascii_digit())
                        && !delegate.is_empty())
                {
                    return Err(Error::request_invalid(
                        "Google service-account impersonation delegates must be service-account emails or numeric service-account IDs",
                    ));
                }
                Ok(format!("projects/-/serviceAccounts/{delegate}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let encoded_target =
            utf8_percent_encode(&self.target_service_account_email, &GOOG_URI_ENCODE_SET);
        Ok(ValidatedGrant {
            target_service_account_email: self.target_service_account_email.clone(),
            endpoint: format!(
                "{IAM_CREDENTIALS_ENDPOINT}/v1/projects/-/serviceAccounts/{encoded_target}:generateAccessToken"
            ),
            scopes: self.scopes.clone(),
            delegates,
        })
    }
}

struct ValidatedGrant {
    target_service_account_email: String,
    endpoint: String,
    scopes: Vec<String>,
    delegates: Vec<String>,
}

/// Exchanges a token-only Google credential through IAM Credentials
/// `generateAccessToken`.
///
/// The source must contain an OAuth access token with a known absolute
/// expiration and no service-account private key. The source must remain valid
/// long enough for the IAM request. The returned credential is token-only,
/// carries Google's authoritative `expireTime`, preserves the target signer
/// identity for query signing, and is directly consumable by Google request
/// signers and Credential Access Boundary granters.
///
/// `None` as the requested lifetime omits the `lifetime` field and lets Google
/// apply its one-hour default. Explicit lifetimes must use whole seconds, leave
/// enough time for a Google operation, and not exceed 12 hours. Google requires
/// an organization policy to allow lifetimes above one hour.
///
/// Every call performs a new IAM Credentials exchange. Granted outputs are not
/// cached by this service granter.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter, time::Timestamp};
/// use reqsign_google::{
///     ServiceAccountImpersonationGrant, ServiceAccountImpersonationGranter,
///     TokenCredentialProvider,
/// };
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = TokenCredentialProvider::new("source-oauth-token")
///     .with_expires_at(Timestamp::now() + Duration::from_secs(3600));
/// let grant = ServiceAccountImpersonationGrant::new(
///     "target@example.iam.gserviceaccount.com",
///     ["https://www.googleapis.com/auth/cloud-platform"],
/// );
/// // Supply a Context configured with an HttpSend implementation.
/// let context = Context::new();
/// let credential = Granter::new(
///     context,
///     source,
///     ServiceAccountImpersonationGranter::new(grant),
/// )
/// .grant(Some(Duration::from_secs(3600)))
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ServiceAccountImpersonationGranter {
    grant: ServiceAccountImpersonationGrant,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for ServiceAccountImpersonationGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountImpersonationGranter")
            .finish_non_exhaustive()
    }
}

impl ServiceAccountImpersonationGranter {
    /// Create a granter for a bound service-account impersonation grant.
    pub fn new(grant: ServiceAccountImpersonationGrant) -> Self {
        Self {
            grant,
            #[cfg(test)]
            now: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound target, scopes, and delegates.
    pub fn with_grant(mut self, grant: ServiceAccountImpersonationGrant) -> Self {
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
                "Google service-account impersonation requires a token-only source credential",
            ));
        }
        let token = credential.token.as_ref().ok_or_else(|| {
            Error::credential_invalid(
                "Google service-account impersonation requires an OAuth access token",
            )
        })?;
        if !is_valid_access_token(&token.access_token) {
            return Err(Error::credential_invalid(
                "Google service-account impersonation source access token is empty or malformed",
            ));
        }
        if token.expires_at.is_none() {
            return Err(Error::credential_invalid(
                "Google service-account impersonation source token expiration is required",
            ));
        }
        if !token.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "source OAuth access token expires before Google service-account impersonation can complete",
            ));
        }
        Ok(token)
    }

    fn validate_lifetime(expires_in: Option<Duration>) -> Result<()> {
        let Some(expires_in) = expires_in else {
            return Ok(());
        };
        if expires_in.subsec_nanos() != 0
            || expires_in <= TOKEN_OPERATION_HEADROOM
            || expires_in > MAX_ACCESS_TOKEN_LIFETIME
        {
            return Err(Error::request_invalid(
                "Google service-account impersonation lifetime must use whole seconds between 11 and 43200 seconds",
            ));
        }
        Ok(())
    }
}

impl GrantCredential for ServiceAccountImpersonationGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + IAM_CREDENTIALS_REQUEST_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        Self::validate_lifetime(expires_in)?;
        let grant = self.grant.validate()?;
        let required_until = self.required_valid_until(credential, expires_in);
        let source = self.source_token(credential, required_until)?;
        let token = generate_access_token(
            ctx,
            &grant.endpoint,
            &source.access_token,
            &grant.scopes,
            Some(&grant.delegates),
            expires_in,
        )
        .await?;

        let response_time = self.time_after_request();
        if !source.is_valid_at(response_time) {
            return Err(Error::credential_invalid(
                "source OAuth access token expired during Google service-account impersonation",
            ));
        }
        if !token.is_valid_at(response_time + TOKEN_OPERATION_HEADROOM) {
            return Err(Error::credential_invalid(
                "impersonated access token is not valid long enough for Google signing",
            ));
        }

        Ok(Credential::with_token(token).with_signer_email(grant.target_service_account_email))
    }
}

/// A Google-specific provider that loads a source credential and applies a
/// fixed service-account impersonation flow.
///
/// This wrapper is useful when the impersonated result must participate in a
/// [`reqsign_core::Signer`] or another provider-oriented composition. It does
/// not cache the source or result; the consuming signer owns output caching.
#[derive(Clone)]
pub struct ServiceAccountImpersonationCredentialProvider {
    source: Arc<dyn ProvideCredentialDyn<Credential = Credential>>,
    granter: ServiceAccountImpersonationGranter,
    lifetime: Option<Duration>,
}

impl Debug for ServiceAccountImpersonationCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountImpersonationCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl ServiceAccountImpersonationCredentialProvider {
    /// Create a provider from a source provider and bound impersonation grant.
    pub fn new(
        source: impl ProvideCredential<Credential = Credential>,
        grant: ServiceAccountImpersonationGrant,
    ) -> Self {
        Self {
            source: Arc::new(source),
            granter: ServiceAccountImpersonationGranter::new(grant),
            lifetime: None,
        }
    }

    /// Request a fixed lifetime for each impersonated credential.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Replace the bound target, scopes, and delegates.
    pub fn with_grant(mut self, grant: ServiceAccountImpersonationGrant) -> Self {
        self.granter = self.granter.with_grant(grant);
        self
    }
}

impl ProvideCredential for ServiceAccountImpersonationCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(source) = self.source.provide_credential_dyn(ctx).await? else {
            return Ok(None);
        };
        self.granter
            .grant_credential(ctx, &source, self.lifetime)
            .await
            .map(Some)
    }
}

#[derive(Serialize)]
struct GenerateAccessTokenRequest<'a> {
    scope: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    delegates: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
    expire_time: String,
}

pub(crate) async fn generate_access_token(
    ctx: &Context,
    endpoint: &str,
    source_access_token: &str,
    scopes: &[String],
    delegates: Option<&[String]>,
    lifetime: Option<Duration>,
) -> Result<Token> {
    let request = GenerateAccessTokenRequest {
        scope: scopes,
        delegates,
        lifetime: lifetime.map(|value| format!("{}s", value.as_secs())),
    };
    let body = serde_json::to_vec(&request).map_err(|err| {
        Error::unexpected("failed to serialize IAM Credentials request").with_source(err)
    })?;
    let mut authorization = format!("Bearer {source_access_token}")
        .parse::<http::HeaderValue>()
        .map_err(|_| {
            Error::credential_invalid("source OAuth access token is not a valid HTTP header value")
        })?;
    authorization.set_sensitive(true);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(endpoint)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, authorization)
        .body(body.into())
        .map_err(|err| {
            Error::unexpected("failed to build IAM Credentials request").with_source(err)
        })?;
    let response = ctx.http_send(request).await.map_err(|err| {
        Error::new(
            err.kind(),
            "IAM Credentials generateAccessToken request failed",
        )
        .set_retryable(err.is_retryable())
    })?;
    if response.status() != http::StatusCode::OK {
        return Err(iam_credentials_error(response.status()));
    }

    let response: GenerateAccessTokenResponse = serde_json::from_slice(response.body())
        .map_err(|_| Error::unexpected("failed to parse IAM Credentials response"))?;
    if !is_valid_access_token(&response.access_token) {
        return Err(Error::unexpected(
            "IAM Credentials response access token is missing or malformed",
        ));
    }
    let expires_at = response.expire_time.parse::<Timestamp>().map_err(|_| {
        Error::unexpected("IAM Credentials response contains an invalid expiration")
    })?;

    Ok(Token {
        access_token: response.access_token,
        expires_at: Some(expires_at),
    })
}

fn iam_credentials_error(status: http::StatusCode) -> Error {
    let error = match status {
        http::StatusCode::UNAUTHORIZED => {
            Error::credential_invalid("IAM Credentials rejected the source credential")
        }
        http::StatusCode::FORBIDDEN => {
            Error::permission_denied("IAM Credentials denied service-account impersonation")
        }
        http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("IAM Credentials rate limit exceeded")
        }
        status if status.is_client_error() => {
            Error::request_invalid("IAM Credentials rejected the impersonation request")
        }
        _ => Error::new(
            ErrorKind::Unexpected,
            "IAM Credentials returned an unexpected response",
        )
        .set_retryable(status.is_server_error()),
    };
    error.with_context(format!("http_status: {}", status.as_u16()))
}

fn is_service_account_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && value.is_ascii()
        && local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && domain.ends_with(".gserviceaccount.com")
}

fn is_valid_scope(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|value| value.is_whitespace() || value.is_control())
}

fn is_valid_access_token(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value
            .bytes()
            .any(|value| value.is_ascii_whitespace() || value.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use reqsign_core::{ErrorKind, Granter, HttpSend};
    use serde_json::json;

    use super::*;
    use crate::ServiceAccount;

    #[derive(Clone, Debug)]
    struct MockHttpSend {
        responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
        requests: Arc<Mutex<Vec<http::Request<Bytes>>>>,
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().expect("lock poisoned").len()
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.requests.lock().expect("lock poisoned").push(request);
            self.responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("unexpected HTTP request"))
        }
    }

    #[derive(Clone, Debug)]
    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        credential: Option<Credential>,
    }

    impl ProvideCredential for CountingProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.credential.clone())
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must parse")
    }

    fn response(status: http::StatusCode, body: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(Bytes::copy_from_slice(body.as_bytes()))
            .expect("response must build")
    }

    fn source(expires_at: &str) -> Credential {
        Credential::with_token(Token {
            access_token: "source-secret-token".to_string(),
            expires_at: Some(timestamp(expires_at)),
        })
    }

    fn grant() -> ServiceAccountImpersonationGrant {
        ServiceAccountImpersonationGrant::new(
            "target@example-project.iam.gserviceaccount.com",
            [
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/devstorage.read_only",
            ],
        )
        .with_delegates([
            "delegate@example-project.iam.gserviceaccount.com",
            "123456789012345678901",
        ])
    }

    #[tokio::test]
    async fn constructs_canonical_request_and_preserves_authoritative_expiration() -> Result<()> {
        let now = timestamp("2026-09-02T00:00:00Z");
        let expires_at = timestamp("2026-09-02T01:00:00Z");
        let http = MockHttpSend::new([response(
            http::StatusCode::OK,
            r#"{"accessToken":"impersonated-secret-token","expireTime":"2026-09-02T01:00:00Z"}"#,
        )]);
        let granter = ServiceAccountImpersonationGranter::new(grant()).with_time(now);

        let credential = granter
            .grant_credential(
                &Context::new().with_http_send(http.clone()),
                &source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(3600)),
            )
            .await?;

        assert_eq!(
            credential.signer_email.as_deref(),
            Some("target@example-project.iam.gserviceaccount.com")
        );
        let token = credential.token.expect("token must exist");
        assert_eq!(token.access_token, "impersonated-secret-token");
        assert_eq!(token.expires_at, Some(expires_at));
        assert!(credential.service_account.is_none());

        let requests = http.requests.lock().expect("lock poisoned");
        let request = requests.first().expect("request must be captured");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.uri(),
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target%40example-project.iam.gserviceaccount.com:generateAccessToken"
        );
        let authorization = request
            .headers()
            .get(AUTHORIZATION)
            .expect("authorization must exist");
        assert_eq!(authorization, "Bearer source-secret-token");
        assert!(authorization.is_sensitive());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(request.body())
                .expect("request body must parse"),
            json!({
                "scope": [
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/devstorage.read_only"
                ],
                "delegates": [
                    "projects/-/serviceAccounts/delegate@example-project.iam.gserviceaccount.com",
                    "projects/-/serviceAccounts/123456789012345678901"
                ],
                "lifetime": "3600s"
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_input_before_iam_io() {
        let now = timestamp("2026-09-02T00:00:00Z");
        let http = MockHttpSend::new([]);
        let context = Context::new().with_http_send(http.clone());

        let invalid_cases = [
            (
                ServiceAccountImpersonationGranter::new(grant()).with_time(now),
                Credential::with_service_account(ServiceAccount {
                    client_email: "source@example-project.iam.gserviceaccount.com".to_string(),
                    private_key: "private-key".to_string(),
                }),
                Some(Duration::from_secs(3600)),
            ),
            (
                ServiceAccountImpersonationGranter::new(grant()).with_time(now),
                Credential::with_token(Token {
                    access_token: "source-secret-token".to_string(),
                    expires_at: None,
                }),
                Some(Duration::from_secs(3600)),
            ),
            (
                ServiceAccountImpersonationGranter::new(grant()).with_time(now),
                Credential::with_token(Token {
                    access_token: "malformed source token".to_string(),
                    expires_at: Some(timestamp("2026-09-02T02:00:00Z")),
                }),
                Some(Duration::from_secs(3600)),
            ),
            (
                ServiceAccountImpersonationGranter::new(ServiceAccountImpersonationGrant::new(
                    "not-a-service-account@example.com",
                    ["https://www.googleapis.com/auth/cloud-platform"],
                ))
                .with_time(now),
                source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(3600)),
            ),
            (
                ServiceAccountImpersonationGranter::new(ServiceAccountImpersonationGrant::new(
                    "target@example-project.iam.gserviceaccount.com",
                    Vec::<String>::new(),
                ))
                .with_time(now),
                source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(3600)),
            ),
            (
                ServiceAccountImpersonationGranter::new(
                    ServiceAccountImpersonationGrant::new(
                        "target@example-project.iam.gserviceaccount.com",
                        ["https://www.googleapis.com/auth/cloud-platform"],
                    )
                    .with_delegate("invalid/delegate"),
                )
                .with_time(now),
                source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(3600)),
            ),
            (
                ServiceAccountImpersonationGranter::new(grant()).with_time(now),
                source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(10)),
            ),
            (
                ServiceAccountImpersonationGranter::new(grant()).with_time(now),
                source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(43_201)),
            ),
            (
                ServiceAccountImpersonationGranter::new(grant()).with_time(now),
                source("2026-09-02T02:00:00Z"),
                Some(Duration::from_millis(3_600_500)),
            ),
        ];

        for (granter, credential, lifetime) in invalid_cases {
            let error = granter
                .grant_credential(&context, &credential, lifetime)
                .await
                .expect_err("input must be rejected");
            assert!(matches!(
                error.kind(),
                ErrorKind::CredentialInvalid | ErrorKind::RequestInvalid
            ));
        }
        assert_eq!(http.request_count(), 0);
    }

    #[tokio::test]
    async fn validates_source_and_output_after_iam_io() {
        let now = timestamp("2026-09-02T00:00:00Z");
        let response_time = timestamp("2026-09-02T00:00:20Z");
        let http = MockHttpSend::new([
            response(
                http::StatusCode::OK,
                r#"{"accessToken":"impersonated-token","expireTime":"2026-09-02T01:00:00Z"}"#,
            ),
            response(
                http::StatusCode::OK,
                r#"{"accessToken":"impersonated-token","expireTime":"2026-09-02T00:00:25Z"}"#,
            ),
        ]);
        let context = Context::new().with_http_send(http);

        let source_expired = ServiceAccountImpersonationGranter::new(grant())
            .with_time(now)
            .with_time_after_request(response_time)
            .grant_credential(
                &context,
                &source("2026-09-02T00:00:15Z"),
                Some(Duration::from_secs(3600)),
            )
            .await
            .expect_err("source expiration during I/O must fail");
        assert_eq!(source_expired.kind(), ErrorKind::CredentialInvalid);

        let output_too_short = ServiceAccountImpersonationGranter::new(grant())
            .with_time(now)
            .with_time_after_request(response_time)
            .grant_credential(
                &context,
                &source("2026-09-02T02:00:00Z"),
                Some(Duration::from_secs(3600)),
            )
            .await
            .expect_err("short output expiration must fail");
        assert_eq!(output_too_short.kind(), ErrorKind::CredentialInvalid);
    }

    #[tokio::test]
    async fn redacts_debug_and_provider_errors() {
        let grant = grant();
        let grant_debug = format!("{grant:?}");
        assert!(!grant_debug.contains("target@"));
        assert!(!grant_debug.contains("delegate@"));
        assert!(!grant_debug.contains("cloud-platform"));

        let http = MockHttpSend::new([response(
            http::StatusCode::FORBIDDEN,
            r#"{"error":{"message":"source-secret-token delegate@example-project.iam.gserviceaccount.com"}}"#,
        )]);
        let error = ServiceAccountImpersonationGranter::new(grant)
            .with_time(timestamp("2026-09-02T00:00:00Z"))
            .grant_credential(
                &Context::new().with_http_send(http),
                &source("2026-09-02T02:00:00Z"),
                None,
            )
            .await
            .expect_err("permission denial must fail");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains("source-secret-token"));
        assert!(!error_debug.contains("delegate@"));
        assert!(error_debug.contains("http_status: 403"));
    }

    #[tokio::test]
    async fn provider_composes_without_a_blanket_adapter() -> Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CountingProvider {
            calls: calls.clone(),
            credential: Some(source("2100-01-01T00:00:00Z")),
        };
        let http = MockHttpSend::new([
            response(
                http::StatusCode::OK,
                r#"{"accessToken":"first-token","expireTime":"2100-01-01T00:00:00Z"}"#,
            ),
            response(
                http::StatusCode::OK,
                r#"{"accessToken":"second-token","expireTime":"2100-01-01T00:00:00Z"}"#,
            ),
        ]);
        let context = Context::new().with_http_send(http.clone());
        let granter = Granter::new(
            context,
            provider,
            ServiceAccountImpersonationGranter::new(grant()),
        );

        let first = granter.grant(None).await?;
        let second = granter.grant(None).await?;
        assert_eq!(
            first.token.expect("token must exist").access_token,
            "first-token"
        );
        assert_eq!(
            second.token.expect("token must exist").access_token,
            "second-token"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.request_count(), 2);

        let wrapper_http = MockHttpSend::new([response(
            http::StatusCode::OK,
            r#"{"accessToken":"provider-token","expireTime":"2100-01-01T00:00:00Z"}"#,
        )]);
        let wrapper = ServiceAccountImpersonationCredentialProvider::new(
            CountingProvider {
                calls: calls.clone(),
                credential: Some(source("2100-01-01T00:00:00Z")),
            },
            grant(),
        );
        let credential = wrapper
            .provide_credential(&Context::new().with_http_send(wrapper_http.clone()))
            .await?
            .expect("provider must return an impersonated credential");
        assert_eq!(
            credential.token.expect("token must exist").access_token,
            "provider-token"
        );
        {
            let requests = wrapper_http.requests.lock().expect("lock poisoned");
            let body = serde_json::from_slice::<serde_json::Value>(
                requests.first().expect("request must exist").body(),
            )
            .expect("request body must parse");
            assert!(body.get("lifetime").is_none());
        }

        let empty_provider = ServiceAccountImpersonationCredentialProvider::new(
            CountingProvider {
                calls,
                credential: None,
            },
            grant(),
        );
        assert!(
            empty_provider
                .provide_credential(&Context::new())
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_malformed_iam_response() {
        let cases = [
            r#"{"accessToken":"","expireTime":"2026-09-02T01:00:00Z"}"#,
            r#"{"accessToken":"token","expireTime":"not-a-time"}"#,
            r#"{"accessToken":"token"}"#,
        ];

        for body in cases {
            let http = MockHttpSend::new([response(http::StatusCode::OK, body)]);
            let error = ServiceAccountImpersonationGranter::new(grant())
                .with_time(timestamp("2026-09-02T00:00:00Z"))
                .grant_credential(
                    &Context::new().with_http_send(http),
                    &source("2026-09-02T02:00:00Z"),
                    None,
                )
                .await
                .expect_err("malformed response must fail");
            assert_eq!(error.kind(), ErrorKind::Unexpected);
        }
    }
}
