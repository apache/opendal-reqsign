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
use std::net::Ipv4Addr;
use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use reqsign_aws_core::constants::X_AMZ_CONTENT_SHA_256;
use reqsign_aws_core::signing::append_query_pairs;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SignRequest, SigningCredential};
use serde::Deserialize;

use crate::{Credential, EMPTY_STRING_SHA256, RequestSigner};

const GET_DATA_ACCESS_PATH: &str = "/v20180820/accessgrantsinstance/dataaccess";
const GET_DATA_ACCESS_HEADROOM: Duration = Duration::from_secs(10);
const MIN_DURATION_SECONDS: u64 = 900;
const MAX_DURATION_SECONDS: u64 = 43_200;
const MAX_TARGET_CHARACTERS: usize = 2_000;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_AUDIT_CONTEXT_CHARACTERS: usize = 2_048;

const X_AMZ_ACCOUNT_ID: &str = "x-amz-account-id";
const X_AMZ_CHECKSUM_CRC64NVME: &str = "x-amz-checksum-crc64nvme";
// GetDataAccess requires an HTTP payload checksum and always has an empty body.
const EMPTY_CRC64NVME_BASE64: &str = "AAAAAAAAAAA=";

/// Stable configuration identifying one regional S3 Access Grants instance.
///
/// S3 Access Grants has one instance per account and Region. The default
/// endpoint is the account-prefixed regional S3 Control endpoint. Use
/// [`Self::with_trusted_endpoint`] only when the replacement endpoint is trusted
/// to receive AWS authorization headers and an optional source session token.
/// Region validation checks endpoint syntax and does not guarantee that S3
/// Access Grants is available in that Region.
#[derive(Clone)]
pub struct S3AccessGrantsConfig {
    account_id: String,
    region: String,
    endpoint: Option<String>,
}

impl Debug for S3AccessGrantsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3AccessGrantsConfig")
            .finish_non_exhaustive()
    }
}

impl S3AccessGrantsConfig {
    /// Create configuration for the S3 Access Grants instance in an account and Region.
    pub fn new(account_id: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            region: region.into(),
            endpoint: None,
        }
    }

    /// Replace the default endpoint with an explicitly trusted HTTPS endpoint.
    ///
    /// The endpoint must be an origin without a path or query, and its first DNS
    /// label must be the configured account ID, for example
    /// `https://111122223333.s3-control.example.com`.
    pub fn with_trusted_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    fn validate(&self) -> Result<ValidatedConfig> {
        validate_account_id(&self.account_id)?;
        validate_region(&self.region)?;

        let endpoint = self.endpoint.clone().unwrap_or_else(|| {
            format!(
                "https://{}.s3-control.{}.{}",
                self.account_id,
                self.region,
                aws_dns_suffix(&self.region)
            )
        });
        let endpoint: Uri = endpoint
            .parse()
            .map_err(|_| Error::config_invalid("invalid S3 Access Grants endpoint"))?;
        if endpoint.scheme_str() != Some("https") {
            return Err(Error::config_invalid(
                "S3 Access Grants endpoint must use HTTPS",
            ));
        }
        if endpoint.path() != "/" || endpoint.query().is_some() {
            return Err(Error::config_invalid(
                "S3 Access Grants endpoint must not include a path or query",
            ));
        }
        let authority = endpoint
            .authority()
            .ok_or_else(|| Error::config_invalid("S3 Access Grants endpoint has no authority"))?;
        if authority.as_str().contains('@') {
            return Err(Error::config_invalid(
                "S3 Access Grants endpoint must not include user information",
            ));
        }
        let host = endpoint
            .host()
            .ok_or_else(|| Error::config_invalid("S3 Access Grants endpoint has no host"))?;
        if host.split('.').next() != Some(self.account_id.as_str()) {
            return Err(Error::config_invalid(
                "S3 Access Grants endpoint does not match the configured account",
            ));
        }

        Ok(ValidatedConfig {
            authority: authority.as_str().to_string(),
        })
    }
}

fn validate_account_id(account_id: &str) -> Result<()> {
    if account_id.len() != 12 || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::config_invalid(
            "S3 Access Grants account ID must contain exactly 12 digits",
        ));
    }
    Ok(())
}

fn validate_region(region: &str) -> Result<()> {
    let valid_length = (5..=64).contains(&region.len());
    let valid_characters = region
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let valid_edges = region
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && region.as_bytes().last().is_some_and(u8::is_ascii_digit);
    let valid_shape = region.matches('-').count() >= 2 && !region.contains("--");

    if !valid_length || !valid_characters || !valid_edges || !valid_shape {
        return Err(Error::config_invalid("S3 Access Grants Region is invalid"));
    }
    Ok(())
}

fn aws_dns_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else if region.starts_with("eusc-") {
        "amazonaws.eu"
    } else if region.starts_with("us-iso-") {
        "c2s.ic.gov"
    } else if region.starts_with("us-isob-") {
        "sc2s.sgov.gov"
    } else if region.starts_with("eu-isoe-") {
        "cloud.adc-e.uk"
    } else if region.starts_with("us-isof-") {
        "csp.hci.ic.gov"
    } else {
        "amazonaws.com"
    }
}

struct ValidatedConfig {
    authority: String,
}

#[derive(Clone, PartialEq, Eq)]
enum S3AccessGrantsTargetKind {
    Bucket,
    Prefix(String),
    Object(String),
}

/// A typed S3 bucket, prefix, or object target for `GetDataAccess`.
///
/// Prefix constructors append the S3 Access Grants wildcard internally.
/// Caller-provided prefixes cannot contain `*`, preventing a prefix target from
/// being widened by injecting wildcard syntax. Exact object targets preserve
/// literal `*` characters and are distinguished by `targetType=Object`. Values
/// are otherwise preserved exactly and are never normalized.
#[derive(Clone, PartialEq, Eq)]
pub struct S3AccessGrantsTarget {
    bucket: String,
    kind: S3AccessGrantsTargetKind,
}

impl Debug for S3AccessGrantsTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("S3AccessGrantsTarget(REDACTED)")
    }
}

impl S3AccessGrantsTarget {
    /// Target an entire general purpose S3 bucket.
    pub fn for_bucket(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            kind: S3AccessGrantsTargetKind::Bucket,
        }
    }

    /// Target every object whose key starts with a non-empty prefix.
    ///
    /// Include a trailing `/` when directory-like prefix semantics are desired.
    pub fn for_prefix(bucket: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            kind: S3AccessGrantsTargetKind::Prefix(prefix.into()),
        }
    }

    /// Target one exact, non-empty object key.
    pub fn for_object(bucket: impl Into<String>, object_key: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            kind: S3AccessGrantsTargetKind::Object(object_key.into()),
        }
    }

    fn validate(&self, account_id: &str, region: &str) -> Result<ValidatedTarget> {
        validate_bucket_name(&self.bucket, account_id, region)?;

        let (value, target_type) = match &self.kind {
            S3AccessGrantsTargetKind::Bucket => (format!("s3://{}", self.bucket), None),
            S3AccessGrantsTargetKind::Prefix(prefix) => {
                validate_object_key_component(prefix, "prefix", false)?;
                (format!("s3://{}/{prefix}*", self.bucket), None)
            }
            S3AccessGrantsTargetKind::Object(object_key) => {
                validate_object_key_component(object_key, "object key", true)?;
                (format!("s3://{}/{object_key}", self.bucket), Some("Object"))
            }
        };
        if value.chars().count() > MAX_TARGET_CHARACTERS {
            return Err(Error::request_invalid(
                "S3 Access Grants target exceeds the service size limit",
            ));
        }

        Ok(ValidatedTarget { value, target_type })
    }
}

fn validate_bucket_name(bucket: &str, account_id: &str, region: &str) -> Result<()> {
    let current_valid_length = (3..=63).contains(&bucket.len());
    let current_valid_characters = bucket
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte));
    let valid_edges = bucket
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    let reserved_prefix = ["xn--", "sthree-", "amzn-s3-demo-"]
        .iter()
        .any(|prefix| bucket.starts_with(prefix));
    let reserved_suffix = ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"]
        .iter()
        .any(|suffix| bucket.ends_with(suffix));
    let account_regional_suffix = format!("-{account_id}-{region}-an");
    let invalid_account_regional_name =
        bucket.ends_with("-an") && !bucket.ends_with(&account_regional_suffix);

    let current_name = current_valid_length
        && current_valid_characters
        && valid_edges
        && !bucket.contains("..")
        && bucket.parse::<Ipv4Addr>().is_err()
        && !reserved_prefix
        && !reserved_suffix
        && !invalid_account_regional_name;

    // Existing buckets created in us-east-1 before March 2018 can contain
    // uppercase letters and underscores and can be up to 255 characters long.
    // GetDataAccess references an existing resource, so it must not apply only
    // the current CreateBucket grammar.
    let legacy_us_east_name = region == "us-east-1"
        && (3..=255).contains(&bucket.len())
        && valid_edges
        && !bucket.contains("..")
        && bucket.parse::<Ipv4Addr>().is_err()
        && !reserved_prefix
        && !reserved_suffix
        && !invalid_account_regional_name
        && bucket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));

    if !current_name && !legacy_us_east_name {
        return Err(Error::request_invalid(
            "S3 Access Grants bucket name is invalid",
        ));
    }
    Ok(())
}

fn validate_object_key_component(value: &str, kind: &str, allow_wildcard: bool) -> Result<()> {
    let mut depth = 0usize;
    let relative_path_is_valid = value.split('/').all(|segment| match segment {
        ".." if depth == 0 => false,
        ".." => {
            depth -= 1;
            true
        }
        "" | "." => true,
        _ => {
            depth += 1;
            true
        }
    });

    if value.is_empty()
        || value.len() > MAX_OBJECT_KEY_BYTES
        || (!allow_wildcard && value.contains('*'))
        || !relative_path_is_valid
    {
        return Err(Error::request_invalid(format!(
            "S3 Access Grants {kind} is invalid"
        )));
    }
    Ok(())
}

struct ValidatedTarget {
    value: String,
    target_type: Option<&'static str>,
}

/// The permission requested from S3 Access Grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3AccessGrantsPermission {
    /// Read-only access.
    Read,
    /// Write-only access.
    Write,
    /// Read and write access.
    ReadWrite,
}

impl S3AccessGrantsPermission {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::ReadWrite => "READWRITE",
        }
    }
}

/// How tightly S3 Access Grants scopes the returned temporary credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3AccessGrantsPrivilege {
    /// Restrict the returned credential to the requested target.
    Minimal,
    /// Use the closest matching grant scope, which can be broader than the target.
    Default,
}

impl S3AccessGrantsPrivilege {
    fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::Default => "Default",
        }
    }
}

/// One complete, typed S3 Access Grants `GetDataAccess` authorization request.
///
/// Privilege is mandatory rather than silently defaulted. Callers therefore
/// explicitly opt in if [`S3AccessGrantsPrivilege::Default`] may return a scope
/// broader than the requested target.
#[derive(Clone)]
pub struct S3AccessGrantsGrant {
    target: S3AccessGrantsTarget,
    permission: S3AccessGrantsPermission,
    privilege: S3AccessGrantsPrivilege,
    audit_context: Option<String>,
}

impl Debug for S3AccessGrantsGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3AccessGrantsGrant")
            .field("target", &"REDACTED")
            .field("permission", &self.permission)
            .field("privilege", &self.privilege)
            .field(
                "audit_context",
                &self.audit_context.as_ref().map(|_| "REDACTED"),
            )
            .finish()
    }
}

impl S3AccessGrantsGrant {
    /// Create a complete grant for one target, permission, and explicit privilege.
    pub fn new(
        target: S3AccessGrantsTarget,
        permission: S3AccessGrantsPermission,
        privilege: S3AccessGrantsPrivilege,
    ) -> Self {
        Self {
            target,
            permission,
            privilege,
            audit_context: None,
        }
    }

    /// Attach an audit context that AWS records in CloudTrail.
    pub fn with_audit_context(mut self, audit_context: impl Into<String>) -> Self {
        self.audit_context = Some(audit_context.into());
        self
    }

    fn validate(&self, config: &S3AccessGrantsConfig) -> Result<ValidatedGrant> {
        let target = self.target.validate(&config.account_id, &config.region)?;
        let audit_context = self
            .audit_context
            .as_deref()
            .map(validate_audit_context)
            .transpose()?
            .map(str::to_string);

        Ok(ValidatedGrant {
            target,
            permission: self.permission.as_str(),
            privilege: self.privilege.as_str(),
            audit_context,
        })
    }
}

fn validate_audit_context(value: &str) -> Result<&str> {
    let characters = value.chars().count();
    let valid_characters = value.chars().all(|ch| {
        ch == '\t'
            || (('\u{20}'..='\u{d7ff}').contains(&ch))
            || (('\u{e000}'..='\u{fffd}').contains(&ch))
            || (('\u{10000}'..='\u{10ffff}').contains(&ch))
    });
    if characters == 0 || characters > MAX_AUDIT_CONTEXT_CHARACTERS || !valid_characters {
        return Err(Error::request_invalid(
            "S3 Access Grants audit context is invalid",
        ));
    }
    Ok(value)
}

struct ValidatedGrant {
    target: ValidatedTarget,
    permission: &'static str,
    privilege: &'static str,
    audit_context: Option<String>,
}

/// Grants temporary AWS credentials through S3 Access Grants `GetDataAccess`.
///
/// The granter binds one stable S3 Access Grants instance configuration and one
/// complete typed grant before it is passed to [`reqsign_core::Granter`]. It
/// signs `GetDataAccess` with the explicit source [`Credential`] through the
/// existing AWS SigV4 request signer and returns only the temporary credential
/// material issued by S3 Access Grants.
///
/// `None` lifetime uses the service default of one hour and omits
/// `durationSeconds`. An explicit lifetime must contain whole seconds in the
/// inclusive range from 15 minutes to 12 hours. The returned credential always
/// uses the authoritative absolute `Expiration` from the AWS response.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_aws_v4::{
///     DefaultCredentialProvider, S3AccessGrantsConfig, S3AccessGrantsGrant,
///     S3AccessGrantsGranter, S3AccessGrantsPermission, S3AccessGrantsPrivilege,
///     S3AccessGrantsTarget,
/// };
/// use reqsign_core::{Context, Granter};
/// use reqsign_http_send_reqwest::ReqwestHttpSend;
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let config = S3AccessGrantsConfig::new("111122223333", "us-east-2");
/// let grant = S3AccessGrantsGrant::new(
///     S3AccessGrantsTarget::for_prefix("example-bucket", "customer-a/"),
///     S3AccessGrantsPermission::Read,
///     S3AccessGrantsPrivilege::Minimal,
/// );
/// let credential = Granter::new(
///     Context::new().with_http_send(ReqwestHttpSend::default()),
///     DefaultCredentialProvider::new(),
///     S3AccessGrantsGranter::new(config, grant),
/// )
/// .grant(Some(Duration::from_secs(900)))
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct S3AccessGrantsGranter {
    config: S3AccessGrantsConfig,
    grant: S3AccessGrantsGrant,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for S3AccessGrantsGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3AccessGrantsGranter")
            .finish_non_exhaustive()
    }
}

impl S3AccessGrantsGranter {
    /// Create a granter for a bound instance configuration and typed grant.
    pub fn new(config: S3AccessGrantsConfig, grant: S3AccessGrantsGrant) -> Self {
        Self {
            config,
            grant,
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound grant while retaining the stable instance configuration.
    pub fn with_grant(mut self, grant: S3AccessGrantsGrant) -> Self {
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

    fn now_after_request(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time_after_request {
            return time;
        }
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self.time_after_request = Some(time);
        self
    }

    #[cfg(test)]
    fn with_time_after_request(mut self, time: Timestamp) -> Self {
        self.time_after_request = Some(time);
        self
    }

    fn duration_seconds(expires_in: Option<Duration>) -> Result<Option<u32>> {
        let Some(expires_in) = expires_in else {
            return Ok(None);
        };
        if expires_in.subsec_nanos() != 0
            || !(MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&expires_in.as_secs())
        {
            return Err(Error::request_invalid(
                "S3 Access Grants lifetime must contain whole seconds between 900 and 43200",
            ));
        }
        let seconds = u32::try_from(expires_in.as_secs()).map_err(|_| {
            Error::request_invalid(
                "S3 Access Grants lifetime must contain whole seconds between 900 and 43200",
            )
        })?;
        Ok(Some(seconds))
    }

    fn validate_source(&self, credential: &Credential, required_until: Timestamp) -> Result<()> {
        if credential.access_key_id.is_empty()
            || credential.secret_access_key.is_empty()
            || credential
                .session_token
                .as_ref()
                .is_some_and(String::is_empty)
        {
            return Err(Error::credential_invalid(
                "S3 Access Grants requires a complete AWS source credential",
            ));
        }
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "AWS source credential expires before GetDataAccess can complete",
            ));
        }
        Ok(())
    }

    fn build_request(
        &self,
        config: &ValidatedConfig,
        grant: ValidatedGrant,
        duration_seconds: Option<u32>,
    ) -> Result<Request<Bytes>> {
        let base_uri: Uri = format!("https://{}{}", config.authority, GET_DATA_ACCESS_PATH)
            .parse()
            .map_err(|_| {
                Error::request_invalid("failed to build S3 Access Grants request endpoint")
            })?;
        let mut query = vec![
            ("target".to_string(), grant.target.value),
            ("permission".to_string(), grant.permission.to_string()),
            ("privilege".to_string(), grant.privilege.to_string()),
        ];
        if let Some(duration_seconds) = duration_seconds {
            query.push(("durationSeconds".to_string(), duration_seconds.to_string()));
        }
        if let Some(target_type) = grant.target.target_type {
            query.push(("targetType".to_string(), target_type.to_string()));
        }
        if let Some(audit_context) = grant.audit_context {
            query.push(("auditContext".to_string(), audit_context));
        }
        let uri = append_query_pairs(&base_uri, &query).map_err(|_| {
            Error::request_invalid("failed to encode S3 Access Grants request query")
        })?;

        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(HOST, &config.authority)
            .header(X_AMZ_ACCOUNT_ID, &self.config.account_id)
            .header(X_AMZ_CONTENT_SHA_256, EMPTY_STRING_SHA256)
            .header(X_AMZ_CHECKSUM_CRC64NVME, EMPTY_CRC64NVME_BASE64)
            .body(Bytes::new())
            .map_err(|_| Error::request_invalid("failed to build S3 Access Grants request"))
    }

    async fn get_data_access(
        &self,
        ctx: &Context,
        credential: &Credential,
        config: &ValidatedConfig,
        grant: ValidatedGrant,
        duration_seconds: Option<u32>,
    ) -> Result<Credential> {
        let request = self.build_request(config, grant, duration_seconds)?;
        let (mut parts, body) = request.into_parts();
        let signer = RequestSigner::new("s3", &self.config.region).with_standard_session_token();
        #[cfg(test)]
        let signer = if let Some(time) = self.time {
            signer.with_time(time)
        } else {
            signer
        };
        signer
            .sign_request(ctx, &mut parts, Some(credential), None)
            .await?;
        let request = Request::from_parts(parts, body);

        let response = ctx.http_send(request).await.map_err(|err| {
            Error::new(
                err.kind(),
                "failed to send S3 Access Grants GetDataAccess request",
            )
            .with_context("operation: GetDataAccess")
            .set_retryable(err.is_retryable())
        })?;
        let status = response.status();
        let request_id = response_request_id(response.headers());
        let body = response.into_body();
        if status != StatusCode::OK {
            return Err(parse_get_data_access_error(
                status,
                &body,
                request_id.as_deref(),
            ));
        }

        let credential = parse_get_data_access_result(&body)?;
        let validated_at = self.now_after_request();
        if !credential.is_valid_at(validated_at + GET_DATA_ACCESS_HEADROOM) {
            return Err(Error::credential_invalid(
                "S3 Access Grants returned a credential that cannot satisfy the next signing operation",
            )
            .with_context("operation: GetDataAccess"));
        }
        Ok(credential)
    }
}

impl GrantCredential for S3AccessGrantsGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + GET_DATA_ACCESS_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let required_until = self.required_valid_until(credential, expires_in);
        self.validate_source(credential, required_until)?;
        let config = self.config.validate()?;
        let grant = self.grant.validate(&self.config)?;
        let duration_seconds = Self::duration_seconds(expires_in)?;

        self.get_data_access(ctx, credential, &config, grant, duration_seconds)
            .await
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetDataAccessResult {
    credentials: GetDataAccessCredentials,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetDataAccessCredentials {
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
    expiration: Option<String>,
}

fn parse_get_data_access_result(body: &[u8]) -> Result<Credential> {
    let body = std::str::from_utf8(body).map_err(|_| {
        Error::unexpected("failed to parse S3 Access Grants response")
            .with_context("operation: GetDataAccess")
    })?;
    let result: GetDataAccessResult = quick_xml::de::from_str(body).map_err(|_| {
        Error::unexpected("failed to parse S3 Access Grants response")
            .with_context("operation: GetDataAccess")
    })?;
    let credential_field = |value: Option<String>| {
        value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::credential_invalid(
                    "S3 Access Grants returned an incomplete temporary credential",
                )
                .with_context("operation: GetDataAccess")
            })
    };
    let access_key_id = credential_field(result.credentials.access_key_id)?;
    let secret_access_key = credential_field(result.credentials.secret_access_key)?;
    let session_token = credential_field(result.credentials.session_token)?;
    let expiration = credential_field(result.credentials.expiration)?;
    let expiration = expiration.parse().map_err(|_| {
        Error::unexpected("failed to parse S3 Access Grants credential expiration")
            .with_context("operation: GetDataAccess")
    })?;

    Ok(Credential {
        access_key_id,
        secret_access_key,
        session_token: Some(session_token),
        expires_in: Some(expiration),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AwsErrorResponse {
    code: Option<String>,
    request_id: Option<String>,
    error: Option<AwsErrorDetails>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AwsErrorDetails {
    code: Option<String>,
}

fn response_request_id(headers: &HeaderMap) -> Option<String> {
    ["x-amz-request-id", "x-amzn-requestid", "x-amzn-request-id"]
        .iter()
        .find_map(|name| headers.get(*name))
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_aws_identifier)
}

fn sanitize_aws_identifier(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return None;
    }
    Some(value.to_string())
}

fn parse_get_data_access_error(
    status: StatusCode,
    body: &[u8],
    header_request_id: Option<&str>,
) -> Error {
    let parsed = std::str::from_utf8(body)
        .ok()
        .and_then(|body| quick_xml::de::from_str::<AwsErrorResponse>(body).ok());
    let code = parsed.as_ref().and_then(|response| {
        response
            .code
            .as_deref()
            .or_else(|| response.error.as_ref()?.code.as_deref())
    });
    let recognized_code = code.filter(|code| {
        matches!(
            *code,
            "AccessDenied"
                | "Forbidden"
                | "UnauthorizedAccess"
                | "NoSuchAccessGrantError"
                | "StsNotAuthorizedError"
                | "ExpiredToken"
                | "InvalidAccessKeyId"
                | "InvalidToken"
                | "SignatureDoesNotMatch"
                | "TokenRefreshRequired"
                | "InvalidArgument"
                | "InvalidParameter"
                | "InvalidRequest"
                | "MalformedQueryString"
                | "MissingParameter"
                | "InvalidAccessGrant"
                | "StsPackedPolicyTooLargeError"
                | "StsValidationError"
                | "AccessGrantsInstanceNotExistsError"
                | "NoSuchAccessGrantsInstance"
                | "NoSuchAccessGrantsLocationError"
                | "SlowDown"
                | "Throttling"
                | "TooManyRequests"
                | "TooManyRequestsException"
                | "InternalError"
                | "InternalFailure"
                | "ServiceUnavailable"
        )
    });
    let mut error = match recognized_code {
        Some(
            "AccessDenied"
            | "Forbidden"
            | "UnauthorizedAccess"
            | "NoSuchAccessGrantError"
            | "StsNotAuthorizedError",
        ) => Error::permission_denied("S3 Access Grants GetDataAccess was denied"),
        Some(
            "ExpiredToken"
            | "InvalidAccessKeyId"
            | "InvalidToken"
            | "SignatureDoesNotMatch"
            | "TokenRefreshRequired",
        ) => Error::credential_invalid("AWS source credential was rejected by S3 Access Grants"),
        Some(
            "InvalidArgument"
            | "InvalidParameter"
            | "InvalidRequest"
            | "MalformedQueryString"
            | "MissingParameter"
            | "InvalidAccessGrant"
            | "StsPackedPolicyTooLargeError"
            | "StsValidationError",
        ) => Error::request_invalid("S3 Access Grants rejected the GetDataAccess request"),
        Some(
            "AccessGrantsInstanceNotExistsError"
            | "NoSuchAccessGrantsInstance"
            | "NoSuchAccessGrantsLocationError",
        ) => {
            Error::config_invalid("S3 Access Grants instance or registered location was not found")
        }
        Some("SlowDown" | "Throttling" | "TooManyRequests" | "TooManyRequestsException") => {
            Error::rate_limited("S3 Access Grants rate limit exceeded")
        }
        Some("InternalError" | "InternalFailure" | "ServiceUnavailable") => {
            Error::unexpected("S3 Access Grants service error").set_retryable(true)
        }
        _ => match status {
            StatusCode::UNAUTHORIZED => {
                Error::credential_invalid("AWS source credential was rejected by S3 Access Grants")
            }
            StatusCode::FORBIDDEN => {
                Error::permission_denied("S3 Access Grants GetDataAccess was denied")
            }
            StatusCode::NOT_FOUND => {
                Error::config_invalid("S3 Access Grants instance was not found")
            }
            StatusCode::TOO_MANY_REQUESTS => {
                Error::rate_limited("S3 Access Grants rate limit exceeded")
            }
            status if status.is_client_error() => {
                Error::request_invalid("S3 Access Grants rejected the GetDataAccess request")
            }
            status if status.is_server_error() => {
                Error::unexpected("S3 Access Grants service error").set_retryable(true)
            }
            _ => Error::unexpected("S3 Access Grants GetDataAccess failed"),
        },
    };
    error = error
        .with_context("operation: GetDataAccess")
        .with_context(format!("http_status: {status}"));
    if let Some(code) = recognized_code.and_then(sanitize_aws_identifier) {
        error = error.with_context(format!("error_code: {code}"));
    }
    let request_id = header_request_id
        .and_then(sanitize_aws_identifier)
        .or_else(|| {
            parsed
                .as_ref()?
                .request_id
                .as_deref()
                .and_then(sanitize_aws_identifier)
        });
    if let Some(request_id) = request_id {
        error = error.with_context(format!("request_id: {request_id}"));
    }
    error
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    };
    use aws_sigv4::sign::v4;
    use http::Response;
    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer};

    use super::*;

    const ACCOUNT_ID: &str = "111122223333";
    const REGION: &str = "us-east-2";
    const SOURCE_ACCESS_KEY: &str = "AKIDEXAMPLE";
    const SOURCE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const SOURCE_SESSION_TOKEN: &str = "SOURCE-SESSION-TOKEN";
    const REQUEST_TIME: &str = "2099-01-01T00:00:00Z";
    const RESPONSE_EXPIRATION: &str = "2099-01-01T01:00:00Z";

    #[derive(Clone)]
    struct CapturedRequest {
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    }

    struct MockState {
        requests: Vec<CapturedRequest>,
        responses: VecDeque<Response<Bytes>>,
    }

    #[derive(Clone)]
    struct MockHttpSend {
        state: Arc<Mutex<MockState>>,
    }

    impl Debug for MockHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockHttpSend").finish_non_exhaustive()
        }
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = Response<Bytes>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockState {
                    requests: Vec::new(),
                    responses: responses.into_iter().collect(),
                })),
            }
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.state.lock().expect("lock poisoned").requests.clone()
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
            let (parts, body) = request.into_parts();
            let mut state = self.state.lock().expect("lock poisoned");
            state.requests.push(CapturedRequest {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                body,
            });
            state
                .responses
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock response queue exhausted"))
        }
    }

    #[derive(Clone, Copy)]
    struct FailingHttpSend {
        kind: ErrorKind,
        retryable: bool,
    }

    impl Debug for FailingHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("FailingHttpSend").finish_non_exhaustive()
        }
    }

    impl HttpSend for FailingHttpSend {
        async fn http_send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>> {
            Err(Error::new(self.kind, "SENSITIVE TRANSPORT DETAIL").set_retryable(self.retryable))
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

    fn source_credential() -> Credential {
        Credential {
            access_key_id: SOURCE_ACCESS_KEY.to_string(),
            secret_access_key: SOURCE_SECRET_KEY.to_string(),
            session_token: Some(SOURCE_SESSION_TOKEN.to_string()),
            expires_in: Some(timestamp("2100-01-01T00:00:00Z")),
        }
    }

    fn config() -> S3AccessGrantsConfig {
        S3AccessGrantsConfig::new(ACCOUNT_ID, REGION)
    }

    fn minimal_read_grant(target: S3AccessGrantsTarget) -> S3AccessGrantsGrant {
        S3AccessGrantsGrant::new(
            target,
            S3AccessGrantsPermission::Read,
            S3AccessGrantsPrivilege::Minimal,
        )
    }

    fn operation(grant: S3AccessGrantsGrant) -> S3AccessGrantsGranter {
        S3AccessGrantsGranter::new(config(), grant).with_time(timestamp(REQUEST_TIME))
    }

    fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Bytes> {
        Response::builder()
            .status(status)
            .body(body.into())
            .expect("response must build")
    }

    fn success_response(
        access_key_id: &str,
        secret_access_key: &str,
        session_token: &str,
        expiration: &str,
    ) -> Response<Bytes> {
        response(
            StatusCode::OK,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<GetDataAccessResult xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/">
  <Credentials>
    <AccessKeyId>{access_key_id}</AccessKeyId>
    <SecretAccessKey>{secret_access_key}</SecretAccessKey>
    <SessionToken>{session_token}</SessionToken>
    <Expiration>{expiration}</Expiration>
  </Credentials>
  <MatchedGrantTarget>s3://sensitive-bucket/private/*</MatchedGrantTarget>
  <Grantee>
    <GranteeType>IAM</GranteeType>
    <GranteeIdentifier>arn:aws:iam::111122223333:role/sensitive</GranteeIdentifier>
  </Grantee>
</GetDataAccessResult>"#
            ),
        )
    }

    fn query_fields(uri: &Uri) -> BTreeMap<String, String> {
        form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect()
    }

    #[tokio::test]
    async fn sends_exact_get_data_access_request_and_sigv4_headers() {
        let http = MockHttpSend::new([success_response(
            "ASIAGRANTED",
            "granted-secret",
            "granted-session-token",
            RESPONSE_EXPIRATION,
        )]);
        let ctx = Context::new().with_http_send(http.clone());
        let grant = S3AccessGrantsGrant::new(
            S3AccessGrantsTarget::for_object("example-bucket", "customer/%tenant/file name.txt"),
            S3AccessGrantsPermission::ReadWrite,
            S3AccessGrantsPrivilege::Minimal,
        )
        .with_audit_context("job 1");

        let output = operation(grant)
            .grant_credential(&ctx, &source_credential(), Some(Duration::from_secs(900)))
            .await
            .expect("GetDataAccess must succeed");

        assert_eq!(output.access_key_id, "ASIAGRANTED");
        assert_eq!(output.secret_access_key, "granted-secret");
        assert_eq!(
            output.session_token.as_deref(),
            Some("granted-session-token")
        );
        assert_eq!(output.expires_in, Some(timestamp(RESPONSE_EXPIRATION)));
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.uri,
            concat!(
                "https://111122223333.s3-control.us-east-2.amazonaws.com",
                "/v20180820/accessgrantsinstance/dataaccess",
                "?auditContext=job%201",
                "&durationSeconds=900",
                "&permission=READWRITE",
                "&privilege=Minimal",
                "&target=s3%3A%2F%2Fexample-bucket%2Fcustomer%2F%25tenant%2Ffile%20name.txt",
                "&targetType=Object"
            )
            .parse::<Uri>()
            .expect("expected URI must parse")
        );
        assert!(request.body.is_empty());
        assert_eq!(
            request.headers[HOST],
            "111122223333.s3-control.us-east-2.amazonaws.com"
        );
        assert_eq!(request.headers[X_AMZ_ACCOUNT_ID], ACCOUNT_ID);
        assert_eq!(
            request.headers[X_AMZ_CONTENT_SHA_256],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            request.headers[X_AMZ_CHECKSUM_CRC64NVME],
            EMPTY_CRC64NVME_BASE64
        );
        assert_eq!(request.headers["x-amz-date"], "20990101T000000Z");
        assert_eq!(
            request.headers["x-amz-security-token"],
            SOURCE_SESSION_TOKEN
        );
        assert!(request.headers["x-amz-security-token"].is_sensitive());
        let authorization = request.headers[AUTHORIZATION]
            .to_str()
            .expect("authorization must be text");
        assert!(request.headers[AUTHORIZATION].is_sensitive());
        assert_eq!(
            authorization,
            concat!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/",
                "20990101/us-east-2/s3/aws4_request, ",
                "SignedHeaders=host;x-amz-account-id;x-amz-checksum-crc64nvme;",
                "x-amz-content-sha256;x-amz-date;x-amz-security-token, ",
                "Signature=ef6ea3a82f3b2c2ed42fbdebdfe549af",
                "ba9aeb8b34fe793a04f39b8274dde810"
            )
        );

        let mut reference = Request::builder()
            .method(Method::GET)
            .uri(request.uri.clone())
            .header(HOST, "111122223333.s3-control.us-east-2.amazonaws.com")
            .header(X_AMZ_ACCOUNT_ID, ACCOUNT_ID)
            .header(
                X_AMZ_CONTENT_SHA_256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .header(X_AMZ_CHECKSUM_CRC64NVME, EMPTY_CRC64NVME_BASE64)
            .body(Bytes::new())
            .expect("reference request must build");
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Double;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let identity = Credentials::new(
            SOURCE_ACCESS_KEY,
            SOURCE_SECRET_KEY,
            Some(SOURCE_SESSION_TOKEN.to_string()),
            None,
            "test",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(REGION)
            .name("s3")
            .time(timestamp(REQUEST_TIME).as_system_time())
            .settings(settings)
            .build()
            .expect("reference signing params must build");
        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                reference.method().as_str(),
                reference.uri().to_string(),
                reference.headers().iter().map(|(name, value)| {
                    (
                        name.as_str(),
                        value.to_str().expect("reference header must be text"),
                    )
                }),
                SignableBody::Bytes(&[]),
            )
            .expect("reference request must be signable"),
            &params.into(),
        )
        .expect("AWS SDK reference signing must succeed");
        let (instructions, _) = output.into_parts();
        instructions.apply_to_request_http1x(&mut reference);
        assert_eq!(reference.headers()[AUTHORIZATION], authorization);
        assert!(!request.headers.contains_key(CONTENT_TYPE));
    }

    #[tokio::test]
    async fn serializes_all_grant_dimensions_on_wire() {
        let cases = [
            (
                minimal_read_grant(S3AccessGrantsTarget::for_bucket("example-bucket")),
                None,
                "s3://example-bucket",
                "READ",
                "Minimal",
                None,
                None,
                None,
            ),
            (
                S3AccessGrantsGrant::new(
                    S3AccessGrantsTarget::for_prefix("example-bucket", "customer/"),
                    S3AccessGrantsPermission::Write,
                    S3AccessGrantsPrivilege::Default,
                ),
                Some(Duration::from_secs(43_200)),
                "s3://example-bucket/customer/*",
                "WRITE",
                "Default",
                None,
                Some("43200"),
                None,
            ),
            (
                S3AccessGrantsGrant::new(
                    S3AccessGrantsTarget::for_object("example-bucket", "customer/object*name"),
                    S3AccessGrantsPermission::ReadWrite,
                    S3AccessGrantsPrivilege::Minimal,
                )
                .with_audit_context("job😀"),
                Some(Duration::from_secs(900)),
                "s3://example-bucket/customer/object*name",
                "READWRITE",
                "Minimal",
                Some("Object"),
                Some("900"),
                Some("job😀"),
            ),
        ];

        for (
            grant,
            duration,
            target,
            permission,
            privilege,
            target_type,
            duration_seconds,
            audit_context,
        ) in cases
        {
            let http = MockHttpSend::new([success_response(
                "ASIAGRANTED",
                "granted-secret",
                "granted-token",
                RESPONSE_EXPIRATION,
            )]);
            let ctx = Context::new().with_http_send(http.clone());
            operation(grant)
                .grant_credential(&ctx, &source_credential(), duration)
                .await
                .expect("typed grant must serialize");

            let fields = query_fields(&http.requests()[0].uri);
            assert_eq!(fields["target"], target);
            assert_eq!(fields["permission"], permission);
            assert_eq!(fields["privilege"], privilege);
            assert_eq!(fields.get("targetType").map(String::as_str), target_type);
            assert_eq!(
                fields.get("durationSeconds").map(String::as_str),
                duration_seconds
            );
            assert_eq!(
                fields.get("auditContext").map(String::as_str),
                audit_context
            );
            if target_type == Some("Object") {
                let query = http.requests()[0]
                    .uri
                    .query()
                    .expect("object request must have a query")
                    .to_string();
                assert!(query.contains("object%2Aname"));
                assert!(query.contains("auditContext=job%F0%9F%98%80"));
            }
        }
    }

    #[tokio::test]
    async fn custom_endpoint_always_uses_standard_session_token_header() {
        for endpoint in [
            "https://111122223333.proxy--x-s3.example.com",
            "https://111122223333.s3express-proxy.example.com",
        ] {
            let http = MockHttpSend::new([success_response(
                "ASIAGRANTED",
                "granted-secret",
                "granted-token",
                RESPONSE_EXPIRATION,
            )]);
            let ctx = Context::new().with_http_send(http.clone());
            let granter = S3AccessGrantsGranter::new(
                config().with_trusted_endpoint(endpoint),
                minimal_read_grant(S3AccessGrantsTarget::for_bucket("example-bucket")),
            )
            .with_time(timestamp(REQUEST_TIME));
            granter
                .grant_credential(&ctx, &source_credential(), None)
                .await
                .expect("trusted custom endpoint must be signable");

            let request = &http.requests()[0];
            assert_eq!(
                request.headers["x-amz-security-token"],
                SOURCE_SESSION_TOKEN
            );
            assert!(!request.headers.contains_key("x-amz-s3session-token"));
            assert!(
                request.headers[AUTHORIZATION]
                    .to_str()
                    .expect("authorization must be text")
                    .contains("x-amz-security-token")
            );
        }
    }

    #[tokio::test]
    async fn supports_long_term_source_credentials() {
        let http = MockHttpSend::new([success_response(
            "ASIAGRANTED",
            "granted-secret",
            "granted-token",
            RESPONSE_EXPIRATION,
        )]);
        let ctx = Context::new().with_http_send(http.clone());
        let source = Credential {
            access_key_id: SOURCE_ACCESS_KEY.to_string(),
            secret_access_key: SOURCE_SECRET_KEY.to_string(),
            session_token: None,
            expires_in: None,
        };
        operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
            "example-bucket",
        )))
        .grant_credential(&ctx, &source, None)
        .await
        .expect("long-term source credential must be accepted");

        let request = &http.requests()[0];
        assert!(!request.headers.contains_key("x-amz-security-token"));
        assert!(!request.headers.contains_key("x-amz-s3session-token"));
    }

    #[test]
    fn resolves_current_aws_partition_endpoints() {
        for (region, authority) in [
            (
                "us-east-1",
                "111122223333.s3-control.us-east-1.amazonaws.com",
            ),
            (
                "us-gov-west-1",
                "111122223333.s3-control.us-gov-west-1.amazonaws.com",
            ),
            (
                "cn-north-1",
                "111122223333.s3-control.cn-north-1.amazonaws.com.cn",
            ),
            (
                "eusc-de-east-1",
                "111122223333.s3-control.eusc-de-east-1.amazonaws.eu",
            ),
            (
                "us-iso-east-1",
                "111122223333.s3-control.us-iso-east-1.c2s.ic.gov",
            ),
            (
                "us-isob-east-1",
                "111122223333.s3-control.us-isob-east-1.sc2s.sgov.gov",
            ),
            (
                "eu-isoe-west-1",
                "111122223333.s3-control.eu-isoe-west-1.cloud.adc-e.uk",
            ),
            (
                "us-isof-south-1",
                "111122223333.s3-control.us-isof-south-1.csp.hci.ic.gov",
            ),
        ] {
            let config = S3AccessGrantsConfig::new(ACCOUNT_ID, region)
                .validate()
                .expect("partition endpoint must validate");
            assert_eq!(config.authority, authority);
        }
    }

    #[tokio::test]
    async fn rejects_invalid_instance_configuration_before_io() {
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let grant = minimal_read_grant(S3AccessGrantsTarget::for_bucket("example-bucket"));
        let configs = [
            S3AccessGrantsConfig::new("111", REGION),
            S3AccessGrantsConfig::new(ACCOUNT_ID, "US-east-2"),
            S3AccessGrantsConfig::new(ACCOUNT_ID, REGION)
                .with_trusted_endpoint("http://111122223333.s3-control.example.com"),
            S3AccessGrantsConfig::new(ACCOUNT_ID, REGION)
                .with_trusted_endpoint("https://111122223333.s3-control.example.com/path"),
            S3AccessGrantsConfig::new(ACCOUNT_ID, REGION)
                .with_trusted_endpoint("https://999999999999.s3-control.example.com"),
            S3AccessGrantsConfig::new(ACCOUNT_ID, REGION)
                .with_trusted_endpoint("https://user@111122223333.s3-control.example.com"),
        ];

        for config in configs {
            let error = S3AccessGrantsGranter::new(config, grant.clone())
                .with_time(timestamp(REQUEST_TIME))
                .grant_credential(&ctx, &source_credential(), None)
                .await
                .expect_err("invalid configuration must fail");
            assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        }
        assert!(http.requests().is_empty());
    }

    #[test]
    fn serializes_typed_targets_permissions_and_privileges() {
        let bucket = S3AccessGrantsTarget::for_bucket("example-bucket")
            .validate(ACCOUNT_ID, REGION)
            .expect("bucket target must validate");
        assert_eq!(bucket.value, "s3://example-bucket");
        assert_eq!(bucket.target_type, None);

        let prefix = S3AccessGrantsTarget::for_prefix("example-bucket", "customer/")
            .validate(ACCOUNT_ID, REGION)
            .expect("prefix target must validate");
        assert_eq!(prefix.value, "s3://example-bucket/customer/*");
        assert_eq!(prefix.target_type, None);

        let object = S3AccessGrantsTarget::for_object("example-bucket", "customer/object")
            .validate(ACCOUNT_ID, REGION)
            .expect("object target must validate");
        assert_eq!(object.value, "s3://example-bucket/customer/object");
        assert_eq!(object.target_type, Some("Object"));

        assert_eq!(S3AccessGrantsPermission::Read.as_str(), "READ");
        assert_eq!(S3AccessGrantsPermission::Write.as_str(), "WRITE");
        assert_eq!(S3AccessGrantsPermission::ReadWrite.as_str(), "READWRITE");
        assert_eq!(S3AccessGrantsPrivilege::Minimal.as_str(), "Minimal");
        assert_eq!(S3AccessGrantsPrivilege::Default.as_str(), "Default");

        let account_regional = S3AccessGrantsTarget::for_bucket("data-111122223333-us-east-2-an")
            .validate(ACCOUNT_ID, REGION)
            .expect("matching account regional bucket must validate");
        assert_eq!(
            account_regional.value,
            "s3://data-111122223333-us-east-2-an"
        );
    }

    #[test]
    fn rejects_invalid_or_widening_target_inputs() {
        for bucket in [
            "ab",
            "Uppercase",
            "example..bucket",
            "192.0.2.1",
            "xn--bucket",
            "sthree-bucket",
            "amzn-s3-demo-bucket",
            "bucket-s3alias",
            "bucket--ol-s3",
            "bucket.mrap",
            "bucket--x-s3",
            "bucket--table-s3",
            "bucket-an",
        ] {
            let error = S3AccessGrantsTarget::for_bucket(bucket)
                .validate(ACCOUNT_ID, REGION)
                .err()
                .expect("invalid bucket must fail");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        }

        for target in [
            S3AccessGrantsTarget::for_prefix("example-bucket", ""),
            S3AccessGrantsTarget::for_object("example-bucket", ""),
            S3AccessGrantsTarget::for_prefix("example-bucket", "customer/*"),
            S3AccessGrantsTarget::for_object("example-bucket", "../private"),
            S3AccessGrantsTarget::for_prefix("example-bucket", "videos/../../private"),
            S3AccessGrantsTarget::for_object(
                "example-bucket",
                "x".repeat(MAX_OBJECT_KEY_BYTES + 1),
            ),
        ] {
            let error = target
                .validate(ACCOUNT_ID, REGION)
                .err()
                .expect("invalid key or prefix must fail");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        }

        let exact = S3AccessGrantsTarget::for_prefix("example-bucket", "/unicode/客户/?#%&=+/")
            .validate(ACCOUNT_ID, REGION)
            .expect("non-wildcard key characters must be preserved");
        assert_eq!(exact.value, "s3://example-bucket//unicode/客户/?#%&=+/*");

        let exact_with_asterisk =
            S3AccessGrantsTarget::for_object("example-bucket", "customer/object*name")
                .validate(ACCOUNT_ID, REGION)
                .expect("asterisk is literal for an exact object target");
        assert_eq!(
            exact_with_asterisk.value,
            "s3://example-bucket/customer/object*name"
        );
        assert_eq!(exact_with_asterisk.target_type, Some("Object"));

        let balanced_relative =
            S3AccessGrantsTarget::for_object("example-bucket", "videos/2014/../../video1.wmv")
                .validate(ACCOUNT_ID, REGION)
                .expect("balanced relative segments are valid S3 object keys");
        assert_eq!(
            balanced_relative.value,
            "s3://example-bucket/videos/2014/../../video1.wmv"
        );
    }

    #[test]
    fn accepts_documented_legacy_us_east_bucket_names() {
        for bucket in [
            "Legacy_Bucket".to_string(),
            format!("A{}Z", "_".repeat(253)),
        ] {
            let target = S3AccessGrantsTarget::for_bucket(bucket.clone())
                .validate(ACCOUNT_ID, "us-east-1")
                .expect("documented legacy us-east-1 bucket must validate");
            assert_eq!(target.value, format!("s3://{bucket}"));

            let error = S3AccessGrantsTarget::for_bucket(bucket)
                .validate(ACCOUNT_ID, REGION)
                .err()
                .expect("legacy grammar is limited to us-east-1");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        }
    }

    #[test]
    fn validates_audit_context_and_duration_semantics() {
        assert_eq!(
            S3AccessGrantsGranter::duration_seconds(None)
                .expect("service default must be accepted"),
            None
        );
        assert_eq!(
            S3AccessGrantsGranter::duration_seconds(Some(Duration::from_secs(900)))
                .expect("minimum must be accepted"),
            Some(900)
        );
        assert_eq!(
            S3AccessGrantsGranter::duration_seconds(Some(Duration::from_secs(43_200)))
                .expect("maximum must be accepted"),
            Some(43_200)
        );
        for duration in [
            Duration::from_secs(899),
            Duration::from_secs(43_201),
            Duration::from_nanos(900_000_000_001),
        ] {
            let error = S3AccessGrantsGranter::duration_seconds(Some(duration))
                .expect_err("invalid duration must fail");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        }

        assert_eq!(
            validate_audit_context("job\t客户😀").expect("valid context"),
            "job\t客户😀"
        );
        for context in ["", "line\nbreak", "control\u{1f}"] {
            let error =
                validate_audit_context(context).expect_err("invalid audit context must fail");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        }
        let too_long = "x".repeat(MAX_AUDIT_CONTEXT_CHARACTERS + 1);
        assert!(validate_audit_context(&too_long).is_err());
    }

    #[tokio::test]
    async fn service_default_omits_duration_and_prefix_omits_target_type() {
        let http = MockHttpSend::new([success_response(
            "ASIAGRANTED",
            "granted-secret",
            "granted-token",
            RESPONSE_EXPIRATION,
        )]);
        let ctx = Context::new().with_http_send(http.clone());
        operation(minimal_read_grant(S3AccessGrantsTarget::for_prefix(
            "example-bucket",
            "customer/",
        )))
        .grant_credential(&ctx, &source_credential(), None)
        .await
        .expect("service default lifetime must succeed");

        let fields = query_fields(&http.requests()[0].uri);
        assert_eq!(fields["target"], "s3://example-bucket/customer/*");
        assert!(!fields.contains_key("durationSeconds"));
        assert!(!fields.contains_key("targetType"));
    }

    #[test]
    fn parses_aws_errors_without_exposing_response_content() {
        let body = br#"<Error>
  <Code>AccessDenied</Code>
  <Message>target s3://sensitive-bucket/private/* uses SECRET-TOKEN</Message>
  <RequestId>request-123</RequestId>
</Error>"#;
        let error = parse_get_data_access_error(StatusCode::FORBIDDEN, body, None);
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(!error.is_retryable());
        assert!(
            error
                .context()
                .iter()
                .any(|value| value == "error_code: AccessDenied")
        );
        assert!(
            error
                .context()
                .iter()
                .any(|value| value == "request_id: request-123")
        );
        let debug = format!("{error:?}");
        assert!(!debug.contains("sensitive-bucket"));
        assert!(!debug.contains("SECRET-TOKEN"));
        assert!(!debug.contains("<Error>"));

        let throttled = parse_get_data_access_error(
            StatusCode::BAD_REQUEST,
            br#"<Error><Code>SlowDown</Code><Message>secret</Message></Error>"#,
            Some("header-request-id"),
        );
        assert_eq!(throttled.kind(), ErrorKind::RateLimited);
        assert!(throttled.is_retryable());

        let unavailable = parse_get_data_access_error(
            StatusCode::SERVICE_UNAVAILABLE,
            b"raw target and credential response",
            None,
        );
        assert_eq!(unavailable.kind(), ErrorKind::Unexpected);
        assert!(unavailable.is_retryable());
        assert!(!format!("{unavailable:?}").contains("raw target"));

        for (code, status, kind) in [
            (
                "NoSuchAccessGrantError",
                StatusCode::NOT_FOUND,
                ErrorKind::PermissionDenied,
            ),
            (
                "StsNotAuthorizedError",
                StatusCode::FORBIDDEN,
                ErrorKind::PermissionDenied,
            ),
            (
                "AccessGrantsInstanceNotExistsError",
                StatusCode::NOT_FOUND,
                ErrorKind::ConfigInvalid,
            ),
            (
                "StsPackedPolicyTooLargeError",
                StatusCode::BAD_REQUEST,
                ErrorKind::RequestInvalid,
            ),
        ] {
            let body = format!("<Error><Code>{code}</Code><Message>secret</Message></Error>");
            let error = parse_get_data_access_error(status, body.as_bytes(), None);
            assert_eq!(error.kind(), kind);
            assert!(
                error
                    .context()
                    .iter()
                    .any(|value| value == &format!("error_code: {code}"))
            );
            assert!(!format!("{error:?}").contains("secret"));
        }

        let unknown = parse_get_data_access_error(
            StatusCode::BAD_REQUEST,
            b"<Error><Code>AKIASECRETSHAPEDVALUE</Code></Error>",
            None,
        );
        assert_eq!(unknown.kind(), ErrorKind::RequestInvalid);
        assert!(
            unknown
                .context()
                .iter()
                .all(|value| !value.contains("AKIASECRETSHAPEDVALUE"))
        );
    }

    #[tokio::test]
    async fn parses_authoritative_expiration_and_rejects_post_io_expiry() {
        let authoritative = "2099-01-01T00:45:00+00:00";
        let http = MockHttpSend::new([success_response(
            "ASIAGRANTED",
            "granted-secret",
            "granted-token",
            authoritative,
        )]);
        let ctx = Context::new().with_http_send(http);
        let output = operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
            "example-bucket",
        )))
        .grant_credential(&ctx, &source_credential(), Some(Duration::from_secs(3_600)))
        .await
        .expect("credential response must parse");
        assert_eq!(output.expires_in, Some(timestamp("2099-01-01T00:45:00Z")));

        let http = MockHttpSend::new([success_response(
            "ASIAGRANTED",
            "granted-secret",
            "granted-token",
            "2099-01-01T00:00:10Z",
        )]);
        let ctx = Context::new().with_http_send(http);
        let error = operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
            "example-bucket",
        )))
        .with_time_after_request(timestamp(REQUEST_TIME))
        .grant_credential(&ctx, &source_credential(), None)
        .await
        .expect_err("credential without signer headroom must be rejected");
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    }

    #[tokio::test]
    async fn rejects_invalid_source_and_grant_before_io() {
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let valid_grant = minimal_read_grant(S3AccessGrantsTarget::for_bucket("example-bucket"));

        let mut sources = Vec::new();
        let mut empty_access_key = source_credential();
        empty_access_key.access_key_id.clear();
        sources.push(empty_access_key);
        let mut empty_secret = source_credential();
        empty_secret.secret_access_key.clear();
        sources.push(empty_secret);
        let mut empty_session_token = source_credential();
        empty_session_token.session_token = Some(String::new());
        sources.push(empty_session_token);
        let mut expiring = source_credential();
        expiring.expires_in = Some(timestamp(REQUEST_TIME) + GET_DATA_ACCESS_HEADROOM);
        sources.push(expiring);

        for source in sources {
            let error = operation(valid_grant.clone())
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("invalid source must fail");
            assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        }

        let invalid_grant =
            minimal_read_grant(S3AccessGrantsTarget::for_prefix("example-bucket", "*"));
        let error = operation(invalid_grant)
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect_err("invalid grant must fail");
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);

        let error = operation(valid_grant)
            .grant_credential(&ctx, &source_credential(), Some(Duration::from_secs(899)))
            .await
            .expect_err("invalid duration must fail");
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn preserves_transport_error_kind_and_retryability() {
        for (kind, retryable) in [
            (ErrorKind::ConfigInvalid, false),
            (ErrorKind::Unexpected, true),
        ] {
            let ctx = Context::new().with_http_send(FailingHttpSend { kind, retryable });
            let error = operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
                "example-bucket",
            )))
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect_err("transport failure must be returned");

            assert_eq!(error.kind(), kind);
            assert_eq!(error.is_retryable(), retryable);
            assert!(!format!("{error:?}").contains("SENSITIVE TRANSPORT DETAIL"));
        }
    }

    #[tokio::test]
    async fn returns_typed_aws_error_from_http_response() {
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("x-amz-request-id", "request-456")
            .body(Bytes::from_static(
                br#"<Error>
  <Code>AccessDenied</Code>
  <Message>s3://sensitive-target/private/*</Message>
</Error>"#,
            ))
            .expect("response must build");
        let http = MockHttpSend::new([response]);
        let ctx = Context::new().with_http_send(http.clone());
        let error = operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
            "example-bucket",
        )))
        .grant_credential(&ctx, &source_credential(), None)
        .await
        .expect_err("AWS service error must be returned");

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(
            error
                .context()
                .iter()
                .any(|value| value == "request_id: request-456")
        );
        assert!(!format!("{error:?}").contains("sensitive-target"));
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test]
    async fn malformed_success_response_is_redacted() {
        let body = br#"<GetDataAccessResult>
  <Credentials>
    <AccessKeyId>SENSITIVE-ACCESS-KEY</AccessKeyId>
    <SecretAccessKey>SENSITIVE-SECRET-KEY</SecretAccessKey>
    <SessionToken>SENSITIVE-SESSION-TOKEN</SessionToken>
    <Expiration>s3://sensitive-target/private/*</Expiration>
  </Credentials>
</GetDataAccessResult>"#;
        let http = MockHttpSend::new([response(StatusCode::OK, &body[..])]);
        let ctx = Context::new().with_http_send(http);
        let error = operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
            "example-bucket",
        )))
        .grant_credential(&ctx, &source_credential(), None)
        .await
        .expect_err("invalid expiration must fail");
        let debug = format!("{error:?}");
        assert!(!debug.contains("SENSITIVE-ACCESS-KEY"));
        assert!(!debug.contains("SENSITIVE-SECRET-KEY"));
        assert!(!debug.contains("SENSITIVE-SESSION-TOKEN"));
        assert!(!debug.contains("sensitive-target"));
    }

    #[test]
    fn rejects_missing_or_empty_temporary_credential_fields() {
        for credentials in [
            r#"
    <AccessKeyId></AccessKeyId>
    <SecretAccessKey>SENSITIVE-SECRET</SecretAccessKey>
    <SessionToken>SENSITIVE-TOKEN</SessionToken>
    <Expiration>2099-01-01T01:00:00Z</Expiration>"#,
            r#"
    <AccessKeyId>SENSITIVE-ACCESS</AccessKeyId>
    <SecretAccessKey>SENSITIVE-SECRET</SecretAccessKey>
    <Expiration>2099-01-01T01:00:00Z</Expiration>"#,
            r#"
    <AccessKeyId>SENSITIVE-ACCESS</AccessKeyId>
    <SecretAccessKey>SENSITIVE-SECRET</SecretAccessKey>
    <SessionToken>SENSITIVE-TOKEN</SessionToken>"#,
        ] {
            let body = format!(
                "<GetDataAccessResult><Credentials>{credentials}</Credentials></GetDataAccessResult>"
            );
            let error = parse_get_data_access_result(body.as_bytes())
                .expect_err("incomplete temporary credential must fail");
            assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
            let debug = format!("{error:?}");
            assert!(!debug.contains("SENSITIVE-ACCESS"));
            assert!(!debug.contains("SENSITIVE-SECRET"));
            assert!(!debug.contains("SENSITIVE-TOKEN"));
        }
    }

    #[test]
    fn debug_output_redacts_configuration_targets_and_credentials() {
        let target = S3AccessGrantsTarget::for_prefix("sensitive-bucket", "private/customer/");
        let grant = S3AccessGrantsGrant::new(
            target.clone(),
            S3AccessGrantsPermission::ReadWrite,
            S3AccessGrantsPrivilege::Default,
        )
        .with_audit_context("sensitive audit context");
        let config = S3AccessGrantsConfig::new("111122223333", "us-east-2")
            .with_trusted_endpoint("https://111122223333.sensitive-control.example.com");
        let granter = S3AccessGrantsGranter::new(config.clone(), grant.clone());
        let source = source_credential();

        let combined = format!("{target:?}\n{grant:?}\n{config:?}\n{granter:?}\n{source:?}");
        for secret in [
            "sensitive-bucket",
            "private/customer",
            "sensitive audit context",
            "sensitive-control",
            SOURCE_ACCESS_KEY,
            SOURCE_SECRET_KEY,
            SOURCE_SESSION_TOKEN,
        ] {
            assert!(!combined.contains(secret));
        }
        assert!(combined.contains("ReadWrite"));
        assert!(combined.contains("Default"));
    }

    #[tokio::test]
    async fn granted_credential_is_consumed_directly_by_existing_signer() {
        let http = MockHttpSend::new([success_response(
            "ASIAGRANTED",
            "granted-secret",
            "granted-session-token",
            RESPONSE_EXPIRATION,
        )]);
        let ctx = Context::new().with_http_send(http);
        let (source_provider, _) = FixedCredentialProvider::new(source_credential());
        let granted = Granter::new(
            ctx,
            source_provider,
            operation(minimal_read_grant(S3AccessGrantsTarget::for_object(
                "example-bucket",
                "customer/object.txt",
            ))),
        )
        .grant(Some(Duration::from_secs(900)))
        .await
        .expect("GetDataAccess must grant a credential");

        let (granted_provider, _) = FixedCredentialProvider::new(granted.clone());
        let signer = Signer::new(
            Context::new(),
            granted_provider,
            RequestSigner::new("s3", REGION).with_time(timestamp("2099-01-01T00:01:00Z")),
        );
        let mut parts =
            Request::get("https://example-bucket.s3.us-east-2.amazonaws.com/customer/object.txt")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume granted credential");

        assert!(
            parts.headers[AUTHORIZATION]
                .to_str()
                .expect("authorization must be text")
                .contains("Credential=ASIAGRANTED/20990101/us-east-2/s3/aws4_request")
        );
        assert_eq!(
            parts.headers["x-amz-security-token"],
            "granted-session-token"
        );
        assert_eq!(granted.expires_in, Some(timestamp(RESPONSE_EXPIRATION)));
    }

    #[tokio::test]
    async fn granter_never_caches_granted_output() {
        let http = MockHttpSend::new([
            success_response(
                "ASIAFIRST",
                "first-secret",
                "first-token",
                RESPONSE_EXPIRATION,
            ),
            success_response(
                "ASIASECOND",
                "second-secret",
                "second-token",
                RESPONSE_EXPIRATION,
            ),
        ]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let granter = Granter::new(
            ctx,
            source_provider,
            operation(minimal_read_grant(S3AccessGrantsTarget::for_bucket(
                "example-bucket",
            ))),
        );

        let first = granter.grant(None).await.expect("first grant must succeed");
        let second = granter
            .grant(None)
            .await
            .expect("second grant must succeed");

        assert_eq!(first.access_key_id, "ASIAFIRST");
        assert_eq!(second.access_key_id, "ASIASECOND");
        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.requests().len(), 2);
    }

    #[test]
    fn response_request_id_accepts_only_bounded_safe_identifiers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-request-id",
            "request-123".parse().expect("header must parse"),
        );
        assert_eq!(
            response_request_id(&headers).as_deref(),
            Some("request-123")
        );

        headers.insert(
            "x-amz-request-id",
            "target=s3://private".parse().expect("header must parse"),
        );
        assert_eq!(response_request_id(&headers), None);
    }
}
