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
use std::net::Ipv4Addr;
use std::ops::{BitOr, BitOrAssign};
use std::time::Duration;

use form_urlencoded::Serializer;
use http::header::{ACCEPT, CONTENT_TYPE};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ErrorKind, GrantCredential, Result, SigningCredential};
use serde::{Deserialize, Serialize};

use crate::constants::TOKEN_OPERATION_HEADROOM;
use crate::{Credential, Token};

const STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE_HEADROOM: Duration = Duration::from_secs(10);
const MAX_ACCESS_BOUNDARY_RULES: usize = 10;
const MAX_ACCESS_BOUNDARY_CHARACTERS: usize = 2048;
const MAX_CONDITION_CHARACTERS: usize = 2048;
const MAX_OPTIONS_CHARACTERS: usize = 4 * 1024 * 1024;
const MAX_ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

const OBJECT_VIEWER_ROLE: u8 = 1 << 0;
const OBJECT_CREATOR_ROLE: u8 = 1 << 1;
const OBJECT_USER_ROLE: u8 = 1 << 2;
const OBJECT_ADMIN_ROLE: u8 = 1 << 3;
const ALL_ROLES: u8 =
    OBJECT_VIEWER_ROLE | OBJECT_CREATOR_ROLE | OBJECT_USER_ROLE | OBJECT_ADMIN_ROLE;

/// Typed Google Cloud Storage roles supported by Credential Access Boundaries.
///
/// Google STS names the CAB field `availablePermissions`, but the protocol does
/// not accept individual `storage.objects.*` permission names. It accepts IAM
/// role identifiers prefixed with `inRole:`. These constants deliberately expose
/// only the well-known predefined Cloud Storage object roles, preventing callers
/// from injecting raw role identifiers or binding a grant to a mutable custom
/// role.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialAccessBoundaryPermissions(u8);

impl CredentialAccessBoundaryPermissions {
    /// The predefined Storage Object Viewer role.
    pub const OBJECT_VIEWER: Self = Self(OBJECT_VIEWER_ROLE);
    /// The predefined Storage Object Creator role.
    pub const OBJECT_CREATOR: Self = Self(OBJECT_CREATOR_ROLE);
    /// The predefined Storage Object User role.
    pub const OBJECT_USER: Self = Self(OBJECT_USER_ROLE);
    /// The predefined Storage Object Admin role.
    pub const OBJECT_ADMIN: Self = Self(OBJECT_ADMIN_ROLE);

    /// Return whether no role is selected.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return whether all roles in `other` are selected.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn roles(self) -> Result<Vec<&'static str>> {
        if self.is_empty() || self.0 & !ALL_ROLES != 0 {
            return Err(Error::request_invalid(
                "credential access boundary permissions must contain supported roles",
            ));
        }

        let mut roles = Vec::with_capacity(self.0.count_ones() as usize);
        if self.contains(Self::OBJECT_VIEWER) {
            roles.push("inRole:roles/storage.objectViewer");
        }
        if self.contains(Self::OBJECT_CREATOR) {
            roles.push("inRole:roles/storage.objectCreator");
        }
        if self.contains(Self::OBJECT_USER) {
            roles.push("inRole:roles/storage.objectUser");
        }
        if self.contains(Self::OBJECT_ADMIN) {
            roles.push("inRole:roles/storage.objectAdmin");
        }
        Ok(roles)
    }
}

impl Debug for CredentialAccessBoundaryPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialAccessBoundaryPermissions(REDACTED)")
    }
}

impl BitOr for CredentialAccessBoundaryPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CredentialAccessBoundaryPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone)]
struct CredentialAccessBoundaryRule {
    bucket: String,
    object_prefix: Option<String>,
    permissions: CredentialAccessBoundaryPermissions,
}

/// A typed, bound Google Cloud Storage Credential Access Boundary.
///
/// Use [`CredentialAccessBoundaryGrant::for_bucket`] for bucket-wide access or
/// [`CredentialAccessBoundaryGrant::for_object_prefix`] for a non-empty object
/// prefix. Prefix grants generate the CEL expression internally, including the
/// `objectListPrefix` check required for safely listing objects. Bucket and
/// prefix values are never normalized.
///
/// Additional rules can be added explicitly. Google evaluates CAB rules as a
/// union and allows at most ten rules.
#[derive(Clone)]
pub struct CredentialAccessBoundaryGrant {
    rules: Vec<CredentialAccessBoundaryRule>,
}

impl Debug for CredentialAccessBoundaryGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialAccessBoundaryGrant")
            .field("rules", &"REDACTED")
            .finish()
    }
}

impl CredentialAccessBoundaryGrant {
    /// Create a bucket-wide Credential Access Boundary.
    pub fn for_bucket(
        bucket: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        Self {
            rules: vec![CredentialAccessBoundaryRule {
                bucket: bucket.into(),
                object_prefix: None,
                permissions,
            }],
        }
    }

    /// Create a Credential Access Boundary for a non-empty object prefix.
    ///
    /// Prefix matching preserves the exact Unicode string. For directory-like
    /// semantics, include the trailing `/` explicitly.
    pub fn for_object_prefix(
        bucket: impl Into<String>,
        object_prefix: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        Self {
            rules: vec![CredentialAccessBoundaryRule {
                bucket: bucket.into(),
                object_prefix: Some(object_prefix.into()),
                permissions,
            }],
        }
    }

    /// Add another bucket-wide rule.
    ///
    /// All rules are evaluated as a union.
    pub fn with_bucket_rule(
        mut self,
        bucket: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        self.rules.push(CredentialAccessBoundaryRule {
            bucket: bucket.into(),
            object_prefix: None,
            permissions,
        });
        self
    }

    /// Add another non-empty object-prefix rule.
    ///
    /// All rules are evaluated as a union.
    pub fn with_object_prefix_rule(
        mut self,
        bucket: impl Into<String>,
        object_prefix: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        self.rules.push(CredentialAccessBoundaryRule {
            bucket: bucket.into(),
            object_prefix: Some(object_prefix.into()),
            permissions,
        });
        self
    }

    fn options_json(&self) -> Result<String> {
        if self.rules.is_empty() || self.rules.len() > MAX_ACCESS_BOUNDARY_RULES {
            return Err(Error::request_invalid(
                "credential access boundary must contain between one and ten rules",
            ));
        }

        let rules = self
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                rule.to_wire()
                    .map_err(|err| err.with_context(format!("rule_index: {index}")))
            })
            .collect::<Result<Vec<_>>>()?;

        let access_boundary = AccessBoundary {
            access_boundary_rules: rules,
        };
        let access_boundary_json = serde_json::to_string(&access_boundary).map_err(|err| {
            Error::unexpected("failed to serialize credential access boundary").with_source(err)
        })?;
        if access_boundary_json.chars().count() > MAX_ACCESS_BOUNDARY_CHARACTERS {
            return Err(Error::request_invalid(
                "credential access boundary exceeds the STS size limit",
            ));
        }

        let options = StsOptions { access_boundary };
        let json = serde_json::to_string(&options).map_err(|err| {
            Error::unexpected("failed to serialize credential access boundary").with_source(err)
        })?;
        if json.chars().count() > MAX_OPTIONS_CHARACTERS {
            return Err(Error::request_invalid(
                "credential access boundary options exceed the STS size limit",
            ));
        }
        Ok(json)
    }
}

impl CredentialAccessBoundaryRule {
    fn to_wire(&self) -> Result<AccessBoundaryRule> {
        validate_bucket_name(&self.bucket)?;
        let available_permissions = self.permissions.roles()?;
        let available_resource = format!(
            "//storage.googleapis.com/projects/_/buckets/{}",
            self.bucket
        );

        let availability_condition = self
            .object_prefix
            .as_deref()
            .map(|prefix| build_prefix_condition(&self.bucket, prefix))
            .transpose()?;

        Ok(AccessBoundaryRule {
            available_resource,
            available_permissions,
            availability_condition,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StsOptions {
    access_boundary: AccessBoundary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessBoundary {
    access_boundary_rules: Vec<AccessBoundaryRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessBoundaryRule {
    available_resource: String,
    available_permissions: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    availability_condition: Option<AvailabilityCondition>,
}

#[derive(Serialize)]
struct AvailabilityCondition {
    expression: String,
}

fn validate_bucket_name(bucket: &str) -> Result<()> {
    let length = bucket.len();
    let valid_length = if bucket.contains('.') {
        (3..=222).contains(&length)
    } else {
        (3..=63).contains(&length)
    };
    let valid_characters = bucket
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte));
    let starts_and_ends_with_alphanumeric = bucket
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    let valid_components = bucket.split('.').all(|component| {
        !component.is_empty()
            && component.len() <= 63
            && (!bucket.contains('.')
                || (component.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }) && component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                    && component
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)))
    });
    let reserved =
        bucket.starts_with("goog") || bucket.contains("google") || bucket.contains("g00gle");

    if !valid_length
        || !valid_characters
        || !starts_and_ends_with_alphanumeric
        || !valid_components
        || reserved
        || bucket.parse::<Ipv4Addr>().is_ok()
    {
        return Err(Error::request_invalid(
            "credential access boundary bucket name is invalid",
        ));
    }
    Ok(())
}

fn build_prefix_condition(bucket: &str, prefix: &str) -> Result<AvailabilityCondition> {
    if prefix.is_empty() || prefix.len() > 1024 || prefix.contains('\r') || prefix.contains('\n') {
        return Err(Error::request_invalid(
            "credential access boundary object prefix is invalid",
        ));
    }

    let object_resource_prefix = format!("projects/_/buckets/{bucket}/objects/{prefix}");
    let object_resource_literal =
        serde_json::to_string(&object_resource_prefix).map_err(|err| {
            Error::unexpected("failed to encode object resource prefix").with_source(err)
        })?;
    let list_prefix_literal = serde_json::to_string(prefix)
        .map_err(|err| Error::unexpected("failed to encode object prefix").with_source(err))?;

    let expression = format!(
        "resource.name.startsWith({object_resource_literal}) || \
         api.getAttribute(\"storage.googleapis.com/objectListPrefix\", \"\")\
         .startsWith({list_prefix_literal})"
    );
    if expression.chars().count() > MAX_CONDITION_CHARACTERS {
        return Err(Error::request_invalid(
            "credential access boundary condition exceeds the STS size limit",
        ));
    }

    Ok(AvailabilityCondition { expression })
}

fn checked_expiration(response_time: Timestamp, expires_in: Duration) -> Result<Timestamp> {
    let expires_in_seconds = i64::try_from(expires_in.as_secs())
        .map_err(|_| Error::unexpected("credential access boundary STS expiration is invalid"))?;
    let expiration_second = response_time
        .as_second()
        .checked_add(expires_in_seconds)
        .ok_or_else(|| Error::unexpected("credential access boundary STS expiration is invalid"))?;
    Timestamp::from_second(expiration_second)
        .map_err(|_| Error::unexpected("credential access boundary STS expiration is invalid"))?;
    Ok(response_time + expires_in)
}

/// Exchanges a Google OAuth access token for a CAB-downscoped access token.
///
/// The bound grant is stable configuration. Construct another granter (or use
/// [`CredentialAccessBoundaryGranter::with_grant`]) for a different
/// authorization decision. The server-side CAB exchange does not accept a
/// requested lifetime, so [`reqsign_core::Granter::grant`] must be called with
/// `None`.
///
/// The source must be a token-only [`Credential`] containing a Google-issued
/// OAuth access token with a known absolute expiration and the
/// `https://www.googleapis.com/auth/cloud-platform` scope. STS rejects tokens
/// that already carry security attributes; the opaque token string does not
/// expose enough information to detect that case locally. Token-only input with
/// known expiration keeps the core source cache's validity tied to the same
/// material used by the exchange; credentials with unknown expiration or an
/// attached service account are rejected before STS I/O.
///
/// The returned [`Credential`] is token-only and can be consumed directly by
/// the existing Google [`crate::RequestSigner`].
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter, time::Timestamp};
/// use reqsign_google::{
///     CredentialAccessBoundaryGrant, CredentialAccessBoundaryGranter,
///     CredentialAccessBoundaryPermissions, TokenCredentialProvider,
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
///     CredentialAccessBoundaryGranter::new(grant),
/// )
/// .grant(None)
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CredentialAccessBoundaryGranter {
    grant: CredentialAccessBoundaryGrant,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for CredentialAccessBoundaryGranter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialAccessBoundaryGranter")
            .finish_non_exhaustive()
    }
}

impl CredentialAccessBoundaryGranter {
    /// Create a granter for a bound Credential Access Boundary.
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
                "credential access boundary exchange requires a token-only source credential",
            ));
        }
        let token = credential.token.as_ref().ok_or_else(|| {
            Error::credential_invalid(
                "credential access boundary exchange requires an OAuth access token",
            )
        })?;
        if token.access_token.is_empty() {
            return Err(Error::credential_invalid(
                "credential access boundary source access token is empty",
            ));
        }
        if token.expires_at.is_none() {
            return Err(Error::credential_invalid(
                "credential access boundary source token expiration is required",
            ));
        }
        if !token.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "source OAuth access token expires before token exchange can complete",
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
                Error::unexpected("failed to build credential access boundary request")
                    .with_source(err)
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

        let token_response: StsTokenResponse =
            serde_json::from_slice(response.body()).map_err(|_| {
                Error::unexpected("failed to parse credential access boundary STS response")
            })?;

        if token_response.access_token.is_empty()
            || token_response.issued_token_type != ACCESS_TOKEN_TYPE
            || token_response.token_type != "Bearer"
        {
            return Err(Error::unexpected(
                "credential access boundary STS response is malformed",
            ));
        }

        let source_expiration = source.expires_at.ok_or_else(|| {
            Error::credential_invalid(
                "credential access boundary source token expiration is required",
            )
        })?;
        if source_expiration <= response_time {
            return Err(Error::credential_invalid(
                "source OAuth access token expired during token exchange",
            ));
        }

        let response_expiration = token_response
            .expires_in
            .map(|expires_in| {
                let expires_in = Duration::from_secs(expires_in);
                if expires_in.is_zero() || expires_in > MAX_ACCESS_TOKEN_LIFETIME {
                    return Err(Error::unexpected(
                        "credential access boundary STS expiration is invalid",
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
                "credential access boundary STS token is already expired",
            ));
        }

        let credential = Credential::with_token(Token {
            access_token: token_response.access_token,
            expires_at: Some(expires_at),
        });
        let required_until = checked_expiration(response_time, TOKEN_OPERATION_HEADROOM)?;
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "downscoped OAuth access token is not valid long enough for Google signing",
            ));
        }
        Ok(credential)
    }
}

impl GrantCredential for CredentialAccessBoundaryGranter {
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
                "credential access boundary exchange does not accept a requested lifetime",
            ));
        }

        let options = self.grant.options_json()?;
        let required_until = self.required_valid_until(credential, expires_in);
        let source = self.source_token(credential, required_until)?;
        let request = self.build_request(&source.access_token, &options)?;
        let response = ctx.http_send(request).await.map_err(|err| {
            Error::new(err.kind(), "credential access boundary STS request failed")
                .set_retryable(err.is_retryable())
        })?;
        let response_time = self.time_after_request();
        self.parse_response(response, source, response_time)
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

#[derive(Deserialize)]
struct StsErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

fn sts_error(status: http::StatusCode, body: &[u8]) -> Error {
    let error_code = serde_json::from_slice::<StsErrorResponse>(body)
        .ok()
        .and_then(|response| response.error);
    let recognized_code = match error_code.as_deref() {
        Some(
            code @ ("invalid_grant"
            | "invalid_request"
            | "invalid_target"
            | "invalid_scope"
            | "unsupported_grant_type"
            | "unsupported_token_type"
            | "unauthorized_client"
            | "access_denied"
            | "quota_exceeded"),
        ) => Some(code),
        _ => None,
    };

    let mut error = match recognized_code {
        Some("invalid_grant") => Error::credential_invalid(
            "credential access boundary token exchange rejected the source credential",
        ),
        Some(
            "invalid_request"
            | "invalid_target"
            | "invalid_scope"
            | "unsupported_grant_type"
            | "unsupported_token_type",
        ) => {
            Error::request_invalid("credential access boundary token exchange rejected the request")
        }
        Some("unauthorized_client" | "access_denied") => {
            Error::permission_denied("credential access boundary token exchange was denied")
        }
        Some("quota_exceeded") => {
            Error::rate_limited("credential access boundary token exchange was rate limited")
        }
        _ if status == http::StatusCode::UNAUTHORIZED => Error::credential_invalid(
            "credential access boundary token exchange rejected the source credential",
        ),
        _ if status == http::StatusCode::FORBIDDEN => {
            Error::permission_denied("credential access boundary token exchange was denied")
        }
        _ if status == http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("credential access boundary token exchange was rate limited")
        }
        _ => Error::unexpected("credential access boundary token exchange failed")
            .set_retryable(status.is_server_error()),
    }
    .with_context(format!("sts_status: {}", status.as_u16()));

    if let Some(code) = recognized_code {
        error = error.with_context(format!("sts_error: {code}"));
    }
    if error.kind() == ErrorKind::Unexpected && status.is_server_error() {
        error = error.set_retryable(true);
    }
    error
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
    use crate::{RequestSigner, ServiceAccount};

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

    fn access_boundary_characters(options: &str) -> usize {
        let options: serde_json::Value =
            serde_json::from_str(options).expect("options must be valid JSON");
        serde_json::to_string(&options["accessBoundary"])
            .expect("access boundary must serialize")
            .chars()
            .count()
    }

    fn output_token(credential: &Credential) -> &Token {
        assert!(credential.service_account.is_none());
        credential
            .token
            .as_ref()
            .expect("granted credential must contain a token")
    }

    #[tokio::test]
    async fn sends_exact_official_server_side_exchange_shape() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:02Z");
        let source_expiry = timestamp("2030-01-01T02:00:00Z");
        let http = MockHttpSend::new([success_response("downscoped-token", Some(3600))]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time);

        let source = source_token("source-token", Some(source_expiry));
        let output = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("token exchange must succeed");

        let token = output_token(&output);
        assert_eq!(token.access_token, "downscoped-token");
        assert_eq!(token.expires_at, Some(timestamp("2030-01-01T01:00:02Z")));

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
    async fn form_encodes_source_token_and_options_as_distinct_fields() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source = "source+token/%=&options=broader";
        let http = MockHttpSend::new([success_response("downscoped-token", Some(3600))]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation =
            CredentialAccessBoundaryGranter::new(CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "tenant&rule=broader",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ))
            .with_time(now);

        operation
            .grant_credential(
                &ctx,
                &source_token(source, Some(timestamp("2030-01-01T02:00:00Z"))),
                None,
            )
            .await
            .expect("token exchange must succeed");

        let request = &http.requests()[0];
        let fields = form_fields(request);
        assert_eq!(fields.len(), 5);
        assert_eq!(fields["subject_token"], source);
        assert!(fields["options"].contains("tenant&rule=broader"));
        let raw = String::from_utf8(request.body.clone()).expect("form body must be UTF-8");
        assert!(raw.contains("subject_token=source%2Btoken%2F%25%3D%26options%3Dbroader"));
        assert!(!raw.contains("&options=broader&"));
    }

    #[test]
    fn serializes_typed_roles_bucket_scope_and_prefix_scope() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_ADMIN
            | CredentialAccessBoundaryPermissions::OBJECT_VIEWER
            | CredentialAccessBoundaryPermissions::OBJECT_CREATOR;
        let bucket_json = CredentialAccessBoundaryGrant::for_bucket("bucket_123", permissions)
            .options_json()
            .expect("bucket grant must serialize");
        let bucket: serde_json::Value =
            serde_json::from_str(&bucket_json).expect("options must be JSON");
        let rule = &bucket["accessBoundary"]["accessBoundaryRules"][0];
        assert_eq!(
            rule["availableResource"],
            "//storage.googleapis.com/projects/_/buckets/bucket_123"
        );
        assert_eq!(
            rule["availablePermissions"],
            serde_json::json!([
                "inRole:roles/storage.objectViewer",
                "inRole:roles/storage.objectCreator",
                "inRole:roles/storage.objectAdmin"
            ])
        );
        assert!(rule.get("availabilityCondition").is_none());

        let prefix = r#"tenant/") || true || (""#;
        let prefix_json = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            prefix,
            CredentialAccessBoundaryPermissions::OBJECT_USER,
        )
        .options_json()
        .expect("prefix grant must serialize");
        let prefix_value: serde_json::Value =
            serde_json::from_str(&prefix_json).expect("options must be JSON");
        assert_eq!(
            prefix_value["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"],
            r#"resource.name.startsWith("projects/_/buckets/example-bucket/objects/tenant/\") || true || (\"") || api.getAttribute("storage.googleapis.com/objectListPrefix", "").startsWith("tenant/\") || true || (\"")"#
        );
    }

    #[test]
    fn preserves_prefix_semantics_without_normalization() {
        let prefix = "/leading//nested/";
        let json = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            prefix,
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        )
        .options_json()
        .expect("valid prefix must serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("options must be JSON");
        let expression = value["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]
            ["expression"]
            .as_str()
            .expect("condition must be a string");
        assert!(expression.contains("/objects//leading//nested/"));
        assert!(expression.ends_with(r#".startsWith("/leading//nested/")"#));
    }

    #[test]
    fn enforces_documented_access_boundary_size_limit() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_VIEWER;
        let at_limit = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "x".repeat(772),
            permissions,
        )
        .with_bucket_rule("aaa", permissions);
        let options = at_limit
            .options_json()
            .expect("2048-character access boundary must serialize");
        assert_eq!(
            access_boundary_characters(&options),
            MAX_ACCESS_BOUNDARY_CHARACTERS
        );

        let over_limit = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "x".repeat(773),
            permissions,
        )
        .with_bucket_rule("aaa", permissions);
        let err = over_limit
            .options_json()
            .expect_err("access boundary over 2048 characters must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    }

    #[test]
    fn accepts_ten_rules_within_the_documented_size_limit() {
        let mut grant = viewer_bucket_grant();
        for index in 1..MAX_ACCESS_BOUNDARY_RULES {
            grant = grant.with_bucket_rule(
                format!("bucket-{index}"),
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            );
        }

        let options: serde_json::Value = serde_json::from_str(
            &grant
                .options_json()
                .expect("documented maximums must serialize"),
        )
        .expect("options must be JSON");
        assert_eq!(
            options["accessBoundary"]["accessBoundaryRules"]
                .as_array()
                .expect("rules must be an array")
                .len(),
            MAX_ACCESS_BOUNDARY_RULES
        );
    }

    #[tokio::test]
    async fn rejects_invalid_grants_and_lifetime_before_sts_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source = source_token("source-token", Some(timestamp("2030-01-01T01:00:00Z")));
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());

        let mut invalid_grants = vec![
            CredentialAccessBoundaryGrant::for_bucket(
                "ab",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "UPPER",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "bucket/name",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "-bucket",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "bucket-",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "192.168.0.1",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "goog-reserved",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "g00gle-reserved",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "bucket..name",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "bucket-.name",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "bucket_name.example",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_bucket(
                "example-bucket",
                CredentialAccessBoundaryPermissions::default(),
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "x".repeat(1025),
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "界".repeat(342),
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "line\nbreak",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "\\".repeat(1024),
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "x".repeat(773),
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            )
            .with_bucket_rule("aaa", CredentialAccessBoundaryPermissions::OBJECT_VIEWER),
        ];

        let mut too_many = viewer_bucket_grant();
        for index in 1..=10 {
            too_many = too_many.with_bucket_rule(
                format!("bucket-{index}"),
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            );
        }
        invalid_grants.push(too_many);

        for grant in invalid_grants {
            let err = CredentialAccessBoundaryGranter::new(grant)
                .with_time(now)
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("invalid grant must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        let err = CredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
            .await
            .expect_err("caller-selected lifetime must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_incompatible_or_expiring_source_before_sts_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);

        let service_account = Credential::with_service_account(ServiceAccount {
            private_key: "source-private-key".to_string(),
            client_email: "source@example.iam.gserviceaccount.com".to_string(),
        });
        let mut mixed = source_token(
            "mixed-source-token",
            Some(timestamp("2030-01-01T01:00:00Z")),
        );
        mixed.service_account = Some(ServiceAccount {
            private_key: "mixed-source-private-key".to_string(),
            client_email: "mixed-source@example.iam.gserviceaccount.com".to_string(),
        });
        let empty_token = source_token("", Some(timestamp("2030-01-01T01:00:00Z")));
        let expiring_token = source_token("source-token", Some(timestamp("2030-01-01T00:00:05Z")));
        let unknown_expiration = source_token("unknown-expiration", None);

        for source in [
            service_account,
            mixed,
            empty_token,
            expiring_token,
            unknown_expiration,
        ] {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("incompatible source must fail");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            assert!(!format!("{err:?}").contains("source-private-key"));
            assert!(!format!("{err:?}").contains("mixed-source-private-key"));
            assert!(!format!("{err:?}").contains("mixed-source-token"));
            assert!(!format!("{err:?}").contains("source-token"));
            assert!(!format!("{err:?}").contains("unknown-expiration"));
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn derives_and_clamps_expiration_at_response_time() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:05Z");
        let source_expiry = timestamp("2030-01-01T00:10:00Z");
        let http = MockHttpSend::new([
            success_response("from-source-expiry", None),
            success_response("clamped-to-source", Some(3600)),
        ]);
        let ctx = Context::new().with_http_send(http);
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time);
        let source = source_token("source-token", Some(source_expiry));

        let inherited = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("missing expires_in must inherit source expiry");
        assert_eq!(output_token(&inherited).expires_at, Some(source_expiry));

        let clamped = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("output must clamp to source expiry");
        assert_eq!(output_token(&clamped).expires_at, Some(source_expiry));
    }

    #[tokio::test]
    async fn accepts_maximum_documented_access_token_lifetime() {
        let response_time = timestamp("2030-01-01T00:00:05Z");
        let http = MockHttpSend::new([success_response(
            "downscoped-token",
            Some(MAX_ACCESS_TOKEN_LIFETIME.as_secs()),
        )]);
        let output = CredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(timestamp("2030-01-01T00:00:00Z"))
            .with_time_after_request(response_time)
            .grant_credential(
                &Context::new().with_http_send(http),
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
    async fn rejects_expiration_timestamp_overflow() {
        let http = MockHttpSend::new([success_response("downscoped-token", Some(2))]);
        let err = CredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(timestamp("2030-01-01T00:00:00Z"))
            .with_time_after_request(timestamp("9999-12-30T21:59:59Z"))
            .grant_credential(
                &Context::new().with_http_send(http),
                &source_token("source-token", Some(timestamp("9999-12-30T22:00:00Z"))),
                None,
            )
            .await
            .expect_err("expiration timestamp overflow must fail without panicking");

        assert_eq!(err.kind(), ErrorKind::Unexpected);
    }

    #[tokio::test]
    async fn validates_source_and_output_after_sts_io() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:21Z");
        let http = MockHttpSend::new([
            success_response("downscoped-token", Some(3600)),
            success_response("too-short-for-signer", Some(10)),
        ]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time);

        let err = operation
            .grant_credential(
                &ctx,
                &source_token("expired-during-io", Some(timestamp("2030-01-01T00:00:21Z"))),
                None,
            )
            .await
            .expect_err("source expiry during I/O must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);

        let err = operation
            .grant_credential(
                &ctx,
                &source_token("long-lived-source", Some(timestamp("2030-01-01T01:00:00Z"))),
                None,
            )
            .await
            .expect_err("output without signer headroom must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rejects_malformed_success_responses_without_exposing_them() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let bodies = [
            br#"{}"#.as_slice(),
            br#"{"access_token":"","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#,
            br#"{"access_token":"response-secret","issued_token_type":"wrong","token_type":"Bearer","expires_in":3600}"#,
            br#"{"access_token":"response-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"MAC","expires_in":3600}"#,
            br#"{"access_token":"response-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":0}"#,
            br#"{"access_token":"response-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":43201}"#,
            br#"{"access_token":"response-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":-1}"#,
            br#"{"access_token":"response-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":"expiration-secret"}"#,
            br#"{"access_token":"response-secret","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":18446744073709551616}"#,
        ];
        let http = MockHttpSend::new(
            bodies
                .into_iter()
                .map(|body| response(http::StatusCode::OK, body.to_vec())),
        );
        let ctx = Context::new().with_http_send(http.clone());
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let source = source_token("source-secret", Some(timestamp("2030-01-01T01:00:00Z")));

        for _ in 0..bodies.len() {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("malformed response must fail");
            let debug = format!("{err:?}");
            assert_eq!(err.kind(), ErrorKind::Unexpected);
            assert!(!debug.contains("source-secret"));
            assert!(!debug.contains("response-secret"));
            assert!(!debug.contains("expiration-secret"));
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), bodies.len());
    }

    #[tokio::test]
    async fn maps_sts_errors_without_exposing_raw_response() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let cases = [
            (
                http::StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant","error_description":"source-secret"}"#,
                ErrorKind::CredentialInvalid,
                false,
            ),
            (
                http::StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_request","error_description":"raw-options-secret"}"#,
                ErrorKind::RequestInvalid,
                false,
            ),
            (
                http::StatusCode::FORBIDDEN,
                r#"{"error":"access_denied","error_description":"authorization-secret"}"#,
                ErrorKind::PermissionDenied,
                false,
            ),
            (
                http::StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"quota_exceeded","error_description":"retry later"}"#,
                ErrorKind::RateLimited,
                true,
            ),
            (
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"backend_error","error_description":"response-secret"}"#,
                ErrorKind::Unexpected,
                true,
            ),
        ];
        let http = MockHttpSend::new(
            cases
                .iter()
                .map(|(status, body, _, _)| response(*status, body.as_bytes().to_vec())),
        );
        let ctx = Context::new().with_http_send(http.clone());
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let source = source_token("source-secret", Some(timestamp("2030-01-01T01:00:00Z")));

        for (_, _, kind, retryable) in cases {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("STS error must fail");
            assert_eq!(err.kind(), kind);
            assert_eq!(err.is_retryable(), retryable);
            let debug = format!("{err:?}");
            for secret in [
                "source-secret",
                "raw-options-secret",
                "authorization-secret",
                "response-secret",
            ] {
                assert!(!debug.contains(secret));
            }
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn redacts_transport_errors_while_preserving_classification() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let err = operation
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
    }

    #[tokio::test]
    async fn core_granter_caches_only_source_and_preserves_isolation() {
        let now = Timestamp::now();
        let source_expiry = now + Duration::from_secs(2 * 60 * 60);
        let source = source_token("source-secret", Some(source_expiry));
        let (provider, provider_calls) = FixedCredentialProvider::new(source);
        let first_http = MockHttpSend::new([
            success_response("downscoped-1", Some(3600)),
            success_response("downscoped-2", Some(3600)),
            success_response("downscoped-3", Some(3600)),
            success_response("downscoped-provider-replaced", Some(3600)),
        ]);
        let second_http = MockHttpSend::new([success_response("downscoped-isolated", Some(3600))]);
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
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
            .expect("replacement operation must succeed");
        let (replacement_provider, replacement_provider_calls) =
            FixedCredentialProvider::new(source_token("replacement-source", Some(source_expiry)));
        let provider_replaced = granter
            .clone()
            .with_credential_provider(replacement_provider)
            .grant(None)
            .await
            .expect("replacement provider must succeed");
        let isolated = granter
            .with_context(Context::new().with_http_send(second_http.clone()))
            .grant(None)
            .await
            .expect("replacement context must succeed");

        assert_eq!(output_token(&first).access_token, "downscoped-1");
        assert_eq!(output_token(&second).access_token, "downscoped-2");
        assert_eq!(output_token(&replaced).access_token, "downscoped-3");
        assert_eq!(
            output_token(&provider_replaced).access_token,
            "downscoped-provider-replaced"
        );
        assert_eq!(output_token(&isolated).access_token, "downscoped-isolated");
        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
        assert_eq!(replacement_provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first_http.calls.load(Ordering::SeqCst), 4);
        assert_eq!(second_http.calls.load(Ordering::SeqCst), 1);

        let replacement_fields = form_fields(&first_http.requests()[2]);
        assert!(
            replacement_fields["options"].contains("inRole:roles/storage.objectCreator"),
            "replacement grant must use a distinct bound policy"
        );
        assert_eq!(
            form_fields(&first_http.requests()[3])["subject_token"],
            "replacement-source"
        );
    }

    #[tokio::test]
    async fn failed_reexchange_never_returns_previous_output() {
        let now = Timestamp::now();
        let source = source_token(
            "source-secret",
            Some(now + Duration::from_secs(2 * 60 * 60)),
        );
        let (provider, provider_calls) = FixedCredentialProvider::new(source);
        let http = MockHttpSend::new([
            success_response("first-downscoped-token", Some(3600)),
            response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"backend_error","error_description":"do not return stale token"}"#,
            ),
        ]);
        let granter = Granter::new(
            Context::new().with_http_send(http.clone()),
            provider,
            CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now),
        );

        let first = granter.grant(None).await.expect("first grant must succeed");
        assert_eq!(output_token(&first).access_token, "first-downscoped-token");
        let err = granter
            .grant(None)
            .await
            .expect_err("failed exchange must not return the previous output");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn granted_token_is_consumed_by_existing_google_signer() {
        let now = Timestamp::now();
        let http = MockHttpSend::new([success_response("downscoped-token", Some(3600))]);
        let operation = CredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let output = operation
            .grant_credential(
                &Context::new().with_http_send(http),
                &source_token("source-token", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect("grant must succeed");
        let (provider, _) = FixedCredentialProvider::new(output);
        let signer = Signer::new(Context::new(), provider, RequestSigner::new("storage"));
        let mut parts =
            http::Request::get("https://storage.googleapis.com/example-bucket/customer-a/object")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;

        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume downscoped token");
        assert_eq!(parts.headers[AUTHORIZATION], "Bearer downscoped-token");
        assert!(parts.headers[AUTHORIZATION].is_sensitive());
    }

    #[test]
    fn debug_redacts_policy_and_credential_material() {
        let grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "sensitive-bucket",
            "sensitive/prefix",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        );
        let operation = CredentialAccessBoundaryGranter::new(grant.clone());
        let credential = source_token("sensitive-token", Some(Timestamp::now()));
        let mock = MockHttpSend::new([]);
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
            (format!("{mock:?}"), "sensitive-token"),
            (format!("{captured:?}"), "sensitive-token"),
        ] {
            assert!(!debug.contains(secret));
        }
        assert_eq!(
            format!("{:?}", CredentialAccessBoundaryPermissions::OBJECT_ADMIN),
            "CredentialAccessBoundaryPermissions(REDACTED)"
        );
    }
}
