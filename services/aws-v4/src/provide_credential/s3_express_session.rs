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

use crate::Credential;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode, Uri, header};
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, GrantCredential, ProvideCredential, ProvideCredentialDyn, Result, SignRequest,
    SigningCredential,
};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::time::Duration;

const CREATE_SESSION_OPERATION_HEADROOM: Duration = Duration::from_secs(10);

/// The permission mode of an S3 Express directory bucket session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3ExpressSessionMode {
    /// Allows `GetObject`, `HeadObject`, `ListObjectsV2`,
    /// `GetObjectAttributes`, `ListParts`, and `ListMultipartUploads`.
    ReadOnly,
    /// Allows all Zonal endpoint operations that use session credentials.
    ReadWrite,
}

impl S3ExpressSessionMode {
    /// Return the AWS wire value for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "ReadOnly",
            Self::ReadWrite => "ReadWrite",
        }
    }
}

impl FromStr for S3ExpressSessionMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ReadOnly" => Ok(Self::ReadOnly),
            "ReadWrite" => Ok(Self::ReadWrite),
            _ => Err(Error::config_invalid(
                "S3 Express session mode must be ReadOnly or ReadWrite",
            )),
        }
    }
}

/// An AWS partition supported by the S3 Express session endpoint model.
///
/// The partition is bound into [`S3ExpressSessionConfig`] so its DNS suffix
/// cannot be inferred incorrectly from a directory bucket at request time.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3ExpressSessionPartition {
    /// The standard `aws` partition.
    Aws,
    /// The `aws-cn` partition.
    AwsCn,
}

impl S3ExpressSessionPartition {
    /// Resolve a supported S3 Express session partition from an AWS Region.
    ///
    /// Regions in unsupported partitions are rejected before any credential or
    /// HTTP I/O.
    pub fn from_region(region: &str) -> Result<Self> {
        region_zone_prefix(region)?;
        let segments = region.split('-').collect::<Vec<_>>();
        match segments.as_slice() {
            ["cn", _, _] => Ok(Self::AwsCn),
            [prefix, _, _]
                if matches!(
                    *prefix,
                    "us" | "eu" | "ap" | "sa" | "ca" | "me" | "af" | "il" | "mx"
                ) =>
            {
                Ok(Self::Aws)
            }
            _ => Err(Error::config_invalid(
                "AWS Region belongs to an unsupported partition for S3 Express sessions",
            )),
        }
    }

    /// Return the AWS partition identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::AwsCn => "aws-cn",
        }
    }

    /// Return the partition DNS suffix used by S3 Express endpoints.
    pub fn dns_suffix(self) -> &'static str {
        match self {
            Self::Aws => "amazonaws.com",
            Self::AwsCn => "amazonaws.com.cn",
        }
    }
}

impl FromStr for S3ExpressSessionPartition {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "aws" => Ok(Self::Aws),
            "aws-cn" => Ok(Self::AwsCn),
            _ => Err(Error::config_invalid(
                "S3 Express session partition must be aws or aws-cn",
            )),
        }
    }
}

/// A complete S3 Express `CreateSession` authorization grant.
///
/// For AWS directory buckets, the source AWS principal must have
/// `s3express:CreateSession` permission for the bucket bound by
/// [`S3ExpressSessionConfig`]. A bucket or identity policy can use the
/// `s3express:SessionMode` condition key to limit which mode that principal may
/// grant. A compatible service defines its own authorization policy.
///
/// This grant does not override the directory bucket's encryption settings.
/// CreateSession therefore uses the bucket default, matching the compatibility
/// provider and AWS SDK guidance.
#[derive(Clone, Eq, PartialEq)]
pub struct S3ExpressSessionGrant {
    mode: S3ExpressSessionMode,
}

impl Debug for S3ExpressSessionGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ExpressSessionGrant")
            .finish_non_exhaustive()
    }
}

impl S3ExpressSessionGrant {
    /// Bind an explicit session mode.
    pub fn new(mode: S3ExpressSessionMode) -> Self {
        Self { mode }
    }

    /// Select the maximum session privilege allowed by service policy.
    ///
    /// This selection omits `x-amz-create-session-mode`. On AWS, S3 attempts a
    /// `ReadWrite` session first and falls back to `ReadOnly` when required by
    /// policy. It remains distinct from either explicit session mode.
    pub fn maximum_allowed() -> S3ExpressSessionGrantSelection {
        S3ExpressSessionGrantSelection::MaximumAllowed
    }

    /// Return the bound session mode.
    pub fn mode(&self) -> S3ExpressSessionMode {
        self.mode
    }
}

/// Selects how S3 Express determines the `CreateSession` permission mode.
///
/// Explicit grants send the corresponding `x-amz-create-session-mode` value.
/// [`Self::MaximumAllowed`] omits that header and delegates the final mode to
/// AWS policy evaluation.
#[non_exhaustive]
#[derive(Clone, Eq, PartialEq)]
pub enum S3ExpressSessionGrantSelection {
    /// Let the service create the session with the maximum privilege allowed by policy.
    MaximumAllowed,
    /// Request exactly the mode bound by the explicit grant.
    Explicit(S3ExpressSessionGrant),
}

impl S3ExpressSessionGrantSelection {
    /// Return the explicitly requested mode, or `None` for maximum-allowed.
    pub fn explicit_mode(&self) -> Option<S3ExpressSessionMode> {
        match self {
            Self::MaximumAllowed => None,
            Self::Explicit(grant) => Some(grant.mode()),
        }
    }

    fn mode_header_value(&self) -> Option<&'static str> {
        self.explicit_mode().map(S3ExpressSessionMode::as_str)
    }
}

impl Debug for S3ExpressSessionGrantSelection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ExpressSessionGrantSelection")
            .finish_non_exhaustive()
    }
}

impl From<S3ExpressSessionGrant> for S3ExpressSessionGrantSelection {
    fn from(grant: S3ExpressSessionGrant) -> Self {
        Self::Explicit(grant)
    }
}

/// Validated, stable S3 Express directory bucket configuration.
///
/// `bucket`, `zone_id`, `region`, and `partition` are bound together so the
/// Zonal endpoint can be constructed once and cannot drift between grants.
#[derive(Clone, Eq, PartialEq)]
pub struct S3ExpressSessionConfig {
    bucket: String,
    zone_id: String,
    region: String,
    partition: S3ExpressSessionPartition,
    endpoint: String,
}

impl Debug for S3ExpressSessionConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ExpressSessionConfig")
            .finish_non_exhaustive()
    }
}

impl S3ExpressSessionConfig {
    /// Resolve a directory bucket configuration from its bucket name and Region.
    ///
    /// The complete `base--zone-id--x-s3` bucket name is validated, the Zone ID
    /// is extracted from its suffix, and the partition is derived from `region`.
    /// Supplying the Region explicitly supports Local Zones and new Zone ID
    /// prefixes without relying on compatibility inference.
    pub fn from_bucket(bucket: impl Into<String>, region: impl Into<String>) -> Result<Self> {
        let bucket = bucket.into();
        let region = region.into();
        let zone_id = zone_id_from_bucket(&bucket)?;
        let partition = S3ExpressSessionPartition::from_region(&region)?;
        Self::new(bucket, zone_id, region, partition)
    }

    /// Create and validate a directory bucket configuration.
    ///
    /// `bucket` must include the exact `--{zone_id}--x-s3` suffix. `zone_id`
    /// must belong to `region` according to the AWS Zone ID prefix convention,
    /// and `region` must belong to `partition`.
    pub fn new(
        bucket: impl Into<String>,
        zone_id: impl Into<String>,
        region: impl Into<String>,
        partition: S3ExpressSessionPartition,
    ) -> Result<Self> {
        let bucket = bucket.into();
        let zone_id = zone_id.into();
        let region = region.into();

        validate_directory_bucket_name(&bucket)?;
        validate_zone_id(&zone_id)?;
        let expected_zone_id = zone_id_from_bucket(&bucket)?;
        if expected_zone_id != zone_id {
            return Err(Error::config_invalid(
                "S3 Express directory bucket suffix does not match the configured Zone ID",
            ));
        }

        let expected_partition = S3ExpressSessionPartition::from_region(&region)?;
        if expected_partition != partition {
            return Err(Error::config_invalid(
                "AWS Region does not belong to the configured S3 Express session partition",
            ));
        }

        let zone_prefix = region_zone_prefix(&region)?;
        if zone_id.split('-').next() != Some(zone_prefix.as_str()) {
            return Err(Error::config_invalid(
                "S3 Express Zone ID does not match the configured AWS Region",
            ));
        }

        let endpoint = format!(
            "https://{bucket}.s3express-{zone_id}.{region}.{}",
            partition.dns_suffix()
        );
        Ok(Self {
            bucket,
            zone_id,
            region,
            partition,
            endpoint,
        })
    }

    /// Return the directory bucket name.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Return the AWS Zone ID.
    pub fn zone_id(&self) -> &str {
        &self.zone_id
    }

    /// Return the AWS Region.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Return the AWS partition.
    pub fn partition(&self) -> S3ExpressSessionPartition {
        self.partition
    }

    /// Return the HTTPS Zonal endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Clone)]
enum S3ExpressSessionEndpointConfig {
    Aws(S3ExpressSessionConfig),
    Custom {
        // A custom service identifies the bucket through its configured
        // authority, but the granter still retains the caller's bucket binding.
        _bucket: String,
        region: String,
        endpoint: String,
        authority: String,
    },
}

impl S3ExpressSessionEndpointConfig {
    fn custom(
        bucket: impl Into<String>,
        region: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Result<Self> {
        let bucket = bucket.into();
        if bucket.is_empty() {
            return Err(Error::config_invalid(
                "S3 Express custom endpoint requires a bucket",
            ));
        }

        let region = region.into();
        validate_custom_signing_region(&region)?;

        let endpoint: Uri = endpoint
            .into()
            .parse()
            .map_err(|_| Error::config_invalid("invalid S3 Express custom endpoint"))?;
        if endpoint.scheme_str() != Some("https") {
            return Err(Error::config_invalid(
                "S3 Express custom endpoint must use HTTPS",
            ));
        }
        if endpoint.path() != "/" || endpoint.query().is_some() {
            return Err(Error::config_invalid(
                "S3 Express custom endpoint must not include a path or query",
            ));
        }
        let authority = endpoint
            .authority()
            .ok_or_else(|| Error::config_invalid("S3 Express custom endpoint has no authority"))?;
        if authority.as_str().contains('@') {
            return Err(Error::config_invalid(
                "S3 Express custom endpoint must not include user information",
            ));
        }
        let host = endpoint
            .host()
            .ok_or_else(|| Error::config_invalid("S3 Express custom endpoint has no host"))?;
        if host.is_empty() {
            return Err(Error::config_invalid(
                "S3 Express custom endpoint has no host",
            ));
        }

        let authority = authority.as_str().to_string();
        Ok(Self::Custom {
            _bucket: bucket,
            region,
            endpoint: format!("https://{authority}"),
            authority,
        })
    }

    fn region(&self) -> &str {
        match self {
            Self::Aws(config) => &config.region,
            Self::Custom { region, .. } => region,
        }
    }

    fn endpoint(&self) -> &str {
        match self {
            Self::Aws(config) => &config.endpoint,
            Self::Custom { endpoint, .. } => endpoint,
        }
    }

    fn authority(&self) -> &str {
        match self {
            Self::Aws(config) => config
                .endpoint
                .strip_prefix("https://")
                .expect("validated endpoint must use HTTPS"),
            Self::Custom { authority, .. } => authority,
        }
    }

    fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }
}

/// Grants expiration-aware credentials for one S3 Express directory bucket or
/// one caller-configured compatible endpoint.
///
/// The source credential authorizes `s3express:CreateSession` and is used only
/// to sign the issuance request. The output contains only the independently
/// usable access key, secret access key, S3 session token, and exact expiration
/// returned by S3. Every call performs a new `CreateSession`; granted outputs
/// are never cached.
///
/// S3 fixes the session lifetime at five minutes and does not expose a lifetime
/// request parameter. Call [`reqsign_core::Granter::grant`] with `None`.
///
/// # Example
///
/// ```no_run
/// use reqsign_aws_v4::{
///     DefaultCredentialProvider, S3ExpressSessionConfig, S3ExpressSessionGrant,
///     S3ExpressSessionGranter,
/// };
/// use reqsign_core::{Context, Granter};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = S3ExpressSessionConfig::from_bucket(
///     "my-bucket--usw2-az1--x-s3",
///     "us-west-2",
/// )?;
/// let grant = S3ExpressSessionGrant::maximum_allowed();
/// let granter = Granter::new(
///     Context::new(),
///     DefaultCredentialProvider::new(),
///     S3ExpressSessionGranter::new(config, grant),
/// );
///
/// let credential = granter.grant(None).await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct S3ExpressSessionGranter {
    config: S3ExpressSessionEndpointConfig,
    grant: S3ExpressSessionGrantSelection,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for S3ExpressSessionGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ExpressSessionGranter")
            .finish_non_exhaustive()
    }
}

impl S3ExpressSessionGranter {
    /// Create a granter with stable bucket configuration and a mode selection.
    pub fn new(
        config: S3ExpressSessionConfig,
        grant: impl Into<S3ExpressSessionGrantSelection>,
    ) -> Self {
        Self {
            config: S3ExpressSessionEndpointConfig::Aws(config),
            grant: grant.into(),
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Create a granter for a compatible service at a custom HTTPS endpoint.
    ///
    /// This path deliberately bypasses AWS directory-bucket name, Zone ID,
    /// partition, and DNS derivation rules. The endpoint must already route
    /// `CreateSession` to `bucket`; reqsign sends the exact configured authority
    /// and does not add the bucket to the request target. `region` is used
    /// verbatim in the SigV4 credential scope.
    ///
    /// # Security
    ///
    /// The endpoint receives AWS `Authorization` material and, when the source
    /// credential is temporary, its `x-amz-security-token`. Reqsign validates
    /// endpoint syntax but cannot determine whether the configured service is
    /// authorized to receive those credentials or implements `CreateSession`.
    ///
    /// # Example
    ///
    /// ```
    /// use reqsign_aws_v4::{
    ///     S3ExpressSessionGrant, S3ExpressSessionGranter, S3ExpressSessionMode,
    /// };
    ///
    /// # fn example() -> reqsign_core::Result<()> {
    /// let granter = S3ExpressSessionGranter::new_with_custom_endpoint(
    ///     "compatible-bucket",
    ///     "custom-region-1",
    ///     "https://sessions.example.com",
    ///     S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadWrite),
    /// )?;
    /// # let _ = granter;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_with_custom_endpoint(
        bucket: impl Into<String>,
        region: impl Into<String>,
        endpoint: impl Into<String>,
        grant: impl Into<S3ExpressSessionGrantSelection>,
    ) -> Result<Self> {
        Ok(Self {
            config: S3ExpressSessionEndpointConfig::custom(bucket, region, endpoint)?,
            grant: grant.into(),
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            time_after_request: None,
        })
    }

    /// Replace the bound mode selection while retaining the stable bucket configuration.
    pub fn with_grant(mut self, grant: impl Into<S3ExpressSessionGrantSelection>) -> Self {
        self.grant = grant.into();
        self
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    #[cfg(test)]
    fn with_time_after_request(mut self, time: Timestamp) -> Self {
        self.time_after_request = Some(time);
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

    fn validate_request(
        &self,
        source: &Credential,
        expires_in: Option<Duration>,
    ) -> Result<Timestamp> {
        if expires_in.is_some() {
            return Err(Error::request_invalid(
                "S3 Express CreateSession does not support a caller-selected lifetime",
            ));
        }
        if source.session_token.as_ref().is_some_and(String::is_empty) {
            return Err(Error::credential_invalid(
                "AWS source credential contains an empty session token",
            ));
        }

        let required_valid_until = self.now() + CREATE_SESSION_OPERATION_HEADROOM;
        if !source.is_valid_at(required_valid_until) {
            return Err(Error::credential_invalid(
                "AWS source credential is not usable through the CreateSession request deadline",
            ));
        }
        Ok(required_valid_until)
    }

    async fn create_session(&self, ctx: &Context, source: &Credential) -> Result<Credential> {
        let authority = self.config.authority();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(format!("{}/?session", self.config.endpoint()))
            .header(header::HOST, authority)
            .header("x-amz-content-sha256", crate::EMPTY_STRING_SHA256);
        if let Some(mode) = self.grant.mode_header_value() {
            request = request.header("x-amz-create-session-mode", mode);
        }
        let request = request.body(Bytes::new()).map_err(|e| {
            Error::request_invalid("failed to build S3 Express CreateSession request")
                .with_source(e)
        })?;

        let (mut parts, body) = request.into_parts();
        let mut signing_source = source.clone();
        if let Some(token) = signing_source.session_token.take() {
            let mut value = HeaderValue::from_str(&token).map_err(|_| {
                Error::credential_invalid(
                    "AWS source credential session token is not a valid HTTP header value",
                )
            })?;
            value.set_sensitive(true);
            parts.headers.insert("x-amz-security-token", value);
        }

        let signer = crate::RequestSigner::new("s3express", self.config.region());
        #[cfg(test)]
        let signer = if let Some(time) = self.time {
            signer.with_time(time)
        } else {
            signer
        };
        signer
            .sign_request(ctx, &mut parts, Some(&signing_source), None)
            .await?;

        let response = ctx
            .http_send(Request::from_parts(parts, body))
            .await
            .map_err(|err| {
                if self.config.is_custom() {
                    Error::new(
                        err.kind(),
                        "failed to send S3 Express CreateSession request",
                    )
                    .with_context("operation: CreateSession")
                    .set_retryable(err.is_retryable())
                } else {
                    err
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(create_session_status_error(status));
        }

        parse_create_session_response(response.body(), self.now_after_request())
    }
}

impl GrantCredential for S3ExpressSessionGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + CREATE_SESSION_OPERATION_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        self.validate_request(credential, expires_in)?;
        self.create_session(ctx, credential).await
    }
}

/// S3 Express fixed-flow credential provider.
///
/// This compatibility API loads its source through [`ProvideCredential`] and
/// creates a `ReadWrite` session on every call. New explicit credential-vending
/// flows should use [`S3ExpressSessionGranter`] through
/// [`reqsign_core::Granter`].
pub struct S3ExpressSessionProvider {
    bucket: String,
    region: Option<String>,
    base_provider: Box<dyn ProvideCredentialDyn<Credential = Credential>>,
}

impl Debug for S3ExpressSessionProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ExpressSessionProvider")
            .finish_non_exhaustive()
    }
}

impl S3ExpressSessionProvider {
    /// Create a fixed `ReadWrite` session provider for a directory bucket.
    ///
    /// The legacy constructor infers the Region from well-known AWS Zone ID
    /// prefixes. Use [`S3ExpressSessionProvider::with_region`] when the Zone is
    /// new or belongs to a Local Zone that the compatibility inference does not
    /// recognize.
    pub fn new(
        bucket: impl Into<String>,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: None,
            base_provider: Box::new(provider),
        }
    }

    /// Bind the AWS Region instead of using compatibility inference.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    fn operation(&self) -> Result<S3ExpressSessionGranter> {
        let zone_id = zone_id_from_bucket(&self.bucket)?;
        let region = match &self.region {
            Some(region) => region.clone(),
            None => infer_region_from_zone_id(&zone_id).ok_or_else(|| {
                Error::config_invalid(
                    "cannot infer AWS Region from S3 Express Zone ID; use with_region",
                )
            })?,
        };
        let config = S3ExpressSessionConfig::from_bucket(&self.bucket, region)?;
        Ok(S3ExpressSessionGranter::new(
            config,
            S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadWrite),
        ))
    }
}

impl ProvideCredential for S3ExpressSessionProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Validate fixed configuration before the source provider can perform I/O.
        let operation = self.operation()?;
        let source = self
            .base_provider
            .provide_credential_dyn(ctx)
            .await?
            .ok_or_else(|| {
                Error::credential_invalid(
                    "S3 Express CreateSession requires an AWS source credential",
                )
            })?;
        Ok(Some(operation.grant_credential(ctx, &source, None).await?))
    }
}

#[derive(Deserialize)]
#[serde(rename = "CreateSessionResult", rename_all = "PascalCase")]
struct CreateSessionResponse {
    credentials: SessionCredentials,
}

impl Debug for CreateSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateSessionResponse")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SessionCredentials {
    session_token: String,
    secret_access_key: String,
    access_key_id: String,
    expiration: String,
}

impl Debug for SessionCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCredentials").finish_non_exhaustive()
    }
}

fn parse_create_session_response(body: &[u8], validated_at: Timestamp) -> Result<Credential> {
    let body = std::str::from_utf8(body)
        .map_err(|_| Error::unexpected("S3 Express CreateSession response is not valid UTF-8"))?;
    let response: CreateSessionResponse = quick_xml::de::from_str(body)
        .map_err(|_| Error::unexpected("failed to parse S3 Express CreateSession response"))?;
    let credentials = response.credentials;

    if credentials.access_key_id.is_empty()
        || credentials.secret_access_key.is_empty()
        || credentials.session_token.is_empty()
    {
        return Err(Error::credential_invalid(
            "S3 Express CreateSession returned incomplete credentials",
        ));
    }
    let expiration = credentials.expiration.parse().map_err(|_| {
        Error::credential_invalid(
            "S3 Express CreateSession returned an invalid credential expiration",
        )
    })?;
    let credential = Credential {
        access_key_id: credentials.access_key_id,
        secret_access_key: credentials.secret_access_key,
        session_token: Some(credentials.session_token),
        expires_in: Some(expiration),
    };
    if !credential.is_valid_at(validated_at) {
        return Err(Error::credential_invalid(
            "S3 Express CreateSession returned credentials that are no longer usable",
        ));
    }
    Ok(credential)
}

fn create_session_status_error(status: StatusCode) -> Error {
    let error = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Error::permission_denied(
            "S3 Express CreateSession was not authorized for the source AWS credential",
        ),
        StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("S3 Express CreateSession was rate limited")
        }
        status if status.is_server_error() => {
            Error::unexpected("S3 Express CreateSession service failed").set_retryable(true)
        }
        _ => Error::unexpected("S3 Express CreateSession request failed"),
    };
    error.with_context(format!("status: {}", status.as_u16()))
}

fn validate_custom_signing_region(region: &str) -> Result<()> {
    let valid_length = (1..=64).contains(&region.len());
    let valid_characters = region
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
    let valid_edges = region
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && region
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid_length || !valid_characters || !valid_edges {
        return Err(Error::config_invalid(
            "invalid S3 Express custom endpoint signing Region",
        ));
    }
    Ok(())
}

fn validate_directory_bucket_name(bucket: &str) -> Result<()> {
    if !(3..=63).contains(&bucket.len())
        || !bucket
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !bucket
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(Error::config_invalid(
            "invalid S3 Express directory bucket name",
        ));
    }
    if ["xn--", "sthree-", "amzn-s3-demo-"]
        .iter()
        .any(|prefix| bucket.starts_with(prefix))
    {
        return Err(Error::config_invalid(
            "S3 Express directory bucket uses a reserved prefix",
        ));
    }
    zone_id_from_bucket(bucket)?;
    Ok(())
}

fn zone_id_from_bucket(bucket: &str) -> Result<String> {
    let without_suffix = bucket.strip_suffix("--x-s3").ok_or_else(|| {
        Error::config_invalid("S3 Express directory bucket must end with --{zone-id}--x-s3")
    })?;
    let (base, zone_id) = without_suffix.rsplit_once("--").ok_or_else(|| {
        Error::config_invalid("S3 Express directory bucket must include a base name and Zone ID")
    })?;
    if base.is_empty() || zone_id.is_empty() {
        return Err(Error::config_invalid(
            "S3 Express directory bucket must include a base name and Zone ID",
        ));
    }
    Ok(zone_id.to_string())
}

fn validate_zone_id(zone_id: &str) -> Result<()> {
    let segments = zone_id.split('-').collect::<Vec<_>>();
    let valid_segments = segments.len() >= 2
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
    let valid_az = segments.last().is_some_and(|segment| {
        segment.strip_prefix("az").is_some_and(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    if !valid_segments || !valid_az {
        return Err(Error::config_invalid("invalid S3 Express AWS Zone ID"));
    }
    Ok(())
}

fn region_zone_prefix(region: &str) -> Result<String> {
    let segments = region.split('-').collect::<Vec<_>>();
    if segments.len() < 3
        || !segments[..segments.len() - 1].iter().all(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_lowercase())
        })
        || !segments.last().is_some_and(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(Error::config_invalid("invalid AWS Region"));
    }

    let mut prefix = segments[0].to_string();
    for segment in &segments[1..segments.len() - 1] {
        prefix.push_str(match *segment {
            "northeast" => "ne",
            "northwest" => "nw",
            "southeast" => "se",
            "southwest" => "sw",
            value => &value[..1],
        });
    }
    prefix.push_str(segments.last().expect("validated Region has a suffix"));
    Ok(prefix)
}

fn infer_region_from_zone_id(zone_id: &str) -> Option<String> {
    let prefix = zone_id.split('-').next()?;
    let region = match prefix {
        "use1" => "us-east-1",
        "use2" => "us-east-2",
        "usw1" => "us-west-1",
        "usw2" => "us-west-2",
        "afs1" => "af-south-1",
        "ape1" => "ap-east-1",
        "apne1" => "ap-northeast-1",
        "apne2" => "ap-northeast-2",
        "apne3" => "ap-northeast-3",
        "aps1" => "ap-south-1",
        "aps2" => "ap-south-2",
        "apse1" => "ap-southeast-1",
        "apse2" => "ap-southeast-2",
        "apse3" => "ap-southeast-3",
        "apse4" => "ap-southeast-4",
        "apse5" => "ap-southeast-5",
        "apse7" => "ap-southeast-7",
        "cac1" => "ca-central-1",
        "euc1" => "eu-central-1",
        "euc2" => "eu-central-2",
        "eun1" => "eu-north-1",
        "eus1" => "eu-south-1",
        "eus2" => "eu-south-2",
        "euw1" => "eu-west-1",
        "euw2" => "eu-west-2",
        "euw3" => "eu-west-3",
        "ilc1" => "il-central-1",
        "mec1" => "me-central-1",
        "mes1" => "me-south-1",
        "mxc1" => "mx-central-1",
        "sae1" => "sa-east-1",
        "cnn1" => "cn-north-1",
        "cnnw1" => "cn-northwest-1",
        _ => return None,
    };
    Some(region.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_credential_types::Credentials as AwsCredentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    };
    use aws_sigv4::sign::v4;
    use http::{HeaderMap, Response, Uri};
    use reqsign_core::{
        ErrorKind, Granter, HttpSend, ProvideCredential, Signer, SigningCredential,
    };
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FixedCredentialProvider {
        credential: Option<Credential>,
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
                    credential: Some(credential),
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
            Ok(self.credential.clone())
        }
    }

    #[derive(Clone)]
    struct CapturedRequest {
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CapturedRequest")
                .field("method", &self.method)
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone)]
    struct MockHttpSend {
        responses: Arc<Mutex<VecDeque<Response<Bytes>>>>,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Debug for MockHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockHttpSend").finish_non_exhaustive()
        }
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = Response<Bytes>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                requests: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn request(&self, index: usize) -> CapturedRequest {
            self.requests.lock().expect("lock poisoned")[index].clone()
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
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
                .ok_or_else(|| Error::unexpected("mock response queue exhausted"))
        }
    }

    #[derive(Clone)]
    struct FailingHttpSend;

    impl Debug for FailingHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FailingHttpSend").finish_non_exhaustive()
        }
    }

    impl HttpSend for FailingHttpSend {
        async fn http_send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>> {
            Err(Error::unexpected(
                "transport failed for https://sensitive-session.example.com using AKIDEXAMPLE, wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, and source-session-token",
            )
            .set_retryable(true))
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must parse")
    }

    fn source_credential() -> Credential {
        Credential {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("source-session-token".to_string()),
            expires_in: None,
        }
    }

    fn sign_with_aws_sdk(request: &CapturedRequest, region: &str, source: &Credential) -> String {
        let mut reference = Request::builder()
            .method(request.method.clone())
            .uri(request.uri.clone())
            .header(header::HOST, request.headers[header::HOST].clone())
            .header(
                "x-amz-content-sha256",
                request.headers["x-amz-content-sha256"].clone(),
            );
        if let Some(mode) = request.headers.get("x-amz-create-session-mode") {
            reference = reference.header("x-amz-create-session-mode", mode.clone());
        }
        let mut reference = reference
            .body(request.body.clone())
            .expect("AWS SDK reference request must build");
        let identity = AwsCredentials::new(
            source.access_key_id.clone(),
            source.secret_access_key.clone(),
            source.session_token.clone(),
            None,
            "reqsign-s3-express-test",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Double;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name("s3express")
            .time(timestamp("2030-01-01T00:00:00Z").as_system_time())
            .settings(settings)
            .build()
            .expect("AWS SDK reference signing parameters must build");
        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                reference.method().as_str(),
                reference.uri().to_string(),
                reference.headers().iter().map(|(name, value)| {
                    (
                        name.as_str(),
                        value
                            .to_str()
                            .expect("AWS SDK reference header must be text"),
                    )
                }),
                SignableBody::Bytes(reference.body()),
            )
            .expect("AWS SDK reference request must be signable"),
            &params.into(),
        )
        .expect("AWS SDK reference signing must succeed");
        let (instructions, _) = output.into_parts();
        instructions.apply_to_request_http1x(&mut reference);
        reference.headers()[header::AUTHORIZATION]
            .to_str()
            .expect("AWS SDK authorization must be ASCII")
            .to_string()
    }

    fn config() -> S3ExpressSessionConfig {
        S3ExpressSessionConfig::new(
            "example--usw2-az1--x-s3",
            "usw2-az1",
            "us-west-2",
            S3ExpressSessionPartition::Aws,
        )
        .expect("configuration must be valid")
    }

    fn success_response(
        access_key_id: &str,
        secret_access_key: &str,
        session_token: &str,
        expiration: &str,
    ) -> Response<Bytes> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <CreateSessionResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Credentials>\
             <SessionToken>{session_token}</SessionToken>\
             <SecretAccessKey>{secret_access_key}</SecretAccessKey>\
             <AccessKeyId>{access_key_id}</AccessKeyId>\
             <Expiration>{expiration}</Expiration>\
             </Credentials>\
             </CreateSessionResult>"
        );
        Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::from(body))
            .expect("response must build")
    }

    fn operation(
        mode: S3ExpressSessionMode,
        now: Timestamp,
        responses: impl IntoIterator<Item = Response<Bytes>>,
    ) -> (S3ExpressSessionGranter, Context, MockHttpSend) {
        operation_with_config(config(), mode, now, responses)
    }

    fn operation_with_config(
        config: S3ExpressSessionConfig,
        mode: S3ExpressSessionMode,
        now: Timestamp,
        responses: impl IntoIterator<Item = Response<Bytes>>,
    ) -> (S3ExpressSessionGranter, Context, MockHttpSend) {
        operation_with_selection(config, S3ExpressSessionGrant::new(mode), now, responses)
    }

    fn operation_with_selection(
        config: S3ExpressSessionConfig,
        grant: impl Into<S3ExpressSessionGrantSelection>,
        now: Timestamp,
        responses: impl IntoIterator<Item = Response<Bytes>>,
    ) -> (S3ExpressSessionGranter, Context, MockHttpSend) {
        let http = MockHttpSend::new(responses);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = S3ExpressSessionGranter::new(config, grant).with_time(now);
        (operation, ctx, http)
    }

    fn operation_with_custom_endpoint(
        mode: S3ExpressSessionMode,
        now: Timestamp,
        responses: impl IntoIterator<Item = Response<Bytes>>,
    ) -> (S3ExpressSessionGranter, Context, MockHttpSend) {
        operation_with_custom_selection(S3ExpressSessionGrant::new(mode), now, responses)
    }

    fn operation_with_custom_selection(
        grant: impl Into<S3ExpressSessionGrantSelection>,
        now: Timestamp,
        responses: impl IntoIterator<Item = Response<Bytes>>,
    ) -> (S3ExpressSessionGranter, Context, MockHttpSend) {
        let http = MockHttpSend::new(responses);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = S3ExpressSessionGranter::new_with_custom_endpoint(
            "compatible-bucket",
            "custom-region-1",
            "https://sessions.example.com:8443/",
            grant,
        )
        .expect("custom endpoint configuration must be valid")
        .with_time(now);
        (operation, ctx, http)
    }

    #[test]
    fn resolves_configuration_from_bucket_and_region() {
        let config = S3ExpressSessionConfig::from_bucket("example--usw2-az1--x-s3", "us-west-2")
            .expect("standard AWS configuration must resolve");
        assert_eq!(config.bucket(), "example--usw2-az1--x-s3");
        assert_eq!(config.zone_id(), "usw2-az1");
        assert_eq!(config.region(), "us-west-2");
        assert_eq!(config.partition(), S3ExpressSessionPartition::Aws);
        assert_eq!(
            config.endpoint(),
            "https://example--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com"
        );

        let explicit = S3ExpressSessionConfig::new(
            "example--usw2-az1--x-s3",
            "usw2-az1",
            "us-west-2",
            S3ExpressSessionPartition::Aws,
        )
        .expect("explicit constructor must remain available");
        assert_eq!(config, explicit);

        let china =
            S3ExpressSessionConfig::from_bucket("example--cnn1-pkx1-az1--x-s3", "cn-north-1")
                .expect("AWS China configuration must resolve");
        assert_eq!(china.zone_id(), "cnn1-pkx1-az1");
        assert_eq!(china.partition(), S3ExpressSessionPartition::AwsCn);
        assert_eq!(
            china.endpoint(),
            "https://example--cnn1-pkx1-az1--x-s3.s3express-cnn1-pkx1-az1.cn-north-1.amazonaws.com.cn"
        );
    }

    #[test]
    fn explicit_region_supports_local_zones_and_new_zone_prefixes() {
        let local_zone =
            S3ExpressSessionConfig::from_bucket("example--usw2-lax1-az1--x-s3", "us-west-2")
                .expect("Local Zone configuration must resolve");
        assert_eq!(local_zone.zone_id(), "usw2-lax1-az1");

        assert_eq!(infer_region_from_zone_id("apse6-az1"), None);
        let new_zone =
            S3ExpressSessionConfig::from_bucket("example--apse6-az1--x-s3", "ap-southeast-6")
                .expect("explicit Region must not depend on compatibility inference");
        assert_eq!(new_zone.zone_id(), "apse6-az1");
        assert_eq!(new_zone.region(), "ap-southeast-6");
        assert_eq!(
            new_zone.endpoint(),
            "https://example--apse6-az1--x-s3.s3express-apse6-az1.ap-southeast-6.amazonaws.com"
        );
    }

    #[test]
    fn validates_complete_directory_bucket_name() {
        let max_length = format!("{}--usw2-az1--x-s3", "a".repeat(47));
        assert_eq!(max_length.len(), 63);
        S3ExpressSessionConfig::from_bucket(max_length, "us-west-2")
            .expect("63-character directory bucket name must be accepted");
        S3ExpressSessionConfig::from_bucket("a--usw2-az1--x-s3", "us-west-2")
            .expect("one-character base name must be accepted");

        let too_long = format!("{}--usw2-az1--x-s3", "a".repeat(48));
        assert_eq!(too_long.len(), 64);
        let invalid_buckets = [
            "general-purpose-bucket".to_string(),
            "--usw2-az1--x-s3".to_string(),
            "example----x-s3".to_string(),
            "-example--usw2-az1--x-s3".to_string(),
            "UPPER--usw2-az1--x-s3".to_string(),
            "example_name--usw2-az1--x-s3".to_string(),
            "example.name--usw2-az1--x-s3".to_string(),
            "xn--name--usw2-az1--x-s3".to_string(),
            "sthree-name--usw2-az1--x-s3".to_string(),
            "sthree-configurator--usw2-az1--x-s3".to_string(),
            "amzn-s3-demo-name--usw2-az1--x-s3".to_string(),
            "example--usw2--x-s3".to_string(),
            "example--usw2--az1--x-s3".to_string(),
            "example--USW2-az1--x-s3".to_string(),
            "example--usw2-zone1--x-s3".to_string(),
            "example--usw2-az--x-s3".to_string(),
            "example--usw2-azx--x-s3".to_string(),
            too_long,
        ];
        for bucket in invalid_buckets {
            assert_eq!(
                S3ExpressSessionConfig::from_bucket(bucket, "us-west-2")
                    .expect_err("invalid directory bucket name must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }
    }

    #[test]
    fn validates_explicit_region_and_zone_match() {
        for (bucket, region) in [
            ("example--use1-az1--x-s3", "us-west-2"),
            ("example--cnn1-az1--x-s3", "us-west-2"),
            ("example--usw2-az1--x-s3", "cn-north-1"),
            ("example--usw2-az1--x-s3", "US-WEST-2"),
            ("example--usw2-az1--x-s3", "us-west"),
            ("example--usw2-az1--x-s3", "us-west-x"),
            ("example--usgw1-az1--x-s3", "us-gov-west-1"),
        ] {
            assert_eq!(
                S3ExpressSessionConfig::from_bucket(bucket, region)
                    .expect_err("invalid Region or Zone/Region mismatch must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }
    }

    #[test]
    fn validates_typed_mode_partition_and_configuration() {
        let maximum_allowed = S3ExpressSessionGrant::maximum_allowed();
        assert_eq!(maximum_allowed.explicit_mode(), None);
        let explicit_read_only: S3ExpressSessionGrantSelection =
            S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadOnly).into();
        assert_eq!(
            explicit_read_only.explicit_mode(),
            Some(S3ExpressSessionMode::ReadOnly)
        );
        assert_eq!(
            "ReadOnly".parse::<S3ExpressSessionMode>().unwrap(),
            S3ExpressSessionMode::ReadOnly
        );
        assert_eq!(
            "ReadWrite".parse::<S3ExpressSessionMode>().unwrap(),
            S3ExpressSessionMode::ReadWrite
        );
        assert_eq!(
            "read-write"
                .parse::<S3ExpressSessionMode>()
                .expect_err("wire modes are case sensitive")
                .kind(),
            ErrorKind::ConfigInvalid
        );
        assert_eq!(
            "aws".parse::<S3ExpressSessionPartition>().unwrap(),
            S3ExpressSessionPartition::Aws
        );
        assert_eq!(
            "aws-cn".parse::<S3ExpressSessionPartition>().unwrap(),
            S3ExpressSessionPartition::AwsCn
        );
        assert_eq!(
            S3ExpressSessionPartition::from_region("us-west-2").unwrap(),
            S3ExpressSessionPartition::Aws
        );
        assert_eq!(
            S3ExpressSessionPartition::from_region("cn-north-1").unwrap(),
            S3ExpressSessionPartition::AwsCn
        );
        assert_eq!(S3ExpressSessionPartition::Aws.as_str(), "aws");
        assert_eq!(
            S3ExpressSessionPartition::AwsCn.dns_suffix(),
            "amazonaws.com.cn"
        );
        for value in ["aws-us-gov", "aws-eusc", "AWS"] {
            assert_eq!(
                value
                    .parse::<S3ExpressSessionPartition>()
                    .expect_err("unsupported partition must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }
        for region in ["us-gov-west-1", "eusc-de-east-1", "US-WEST-2"] {
            assert_eq!(
                S3ExpressSessionPartition::from_region(region)
                    .expect_err("unsupported or malformed partition Region must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }

        let config = config();
        assert_eq!(config.bucket(), "example--usw2-az1--x-s3");
        assert_eq!(config.zone_id(), "usw2-az1");
        assert_eq!(config.region(), "us-west-2");
        assert_eq!(config.partition(), S3ExpressSessionPartition::Aws);
        assert_eq!(
            config.endpoint(),
            "https://example--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com"
        );

        let local_zone = S3ExpressSessionConfig::new(
            "example--usw2-lax1-az1--x-s3",
            "usw2-lax1-az1",
            "us-west-2",
            S3ExpressSessionPartition::Aws,
        )
        .expect("Local Zone IDs must be supported");
        assert_eq!(local_zone.zone_id(), "usw2-lax1-az1");

        let china = S3ExpressSessionConfig::new(
            "example--cnn1-pkx1-az1--x-s3",
            "cnn1-pkx1-az1",
            "cn-north-1",
            S3ExpressSessionPartition::AwsCn,
        )
        .expect("AWS China Local Zone configuration must be supported");
        assert_eq!(china.partition(), S3ExpressSessionPartition::AwsCn);
        assert_eq!(
            china.endpoint(),
            "https://example--cnn1-pkx1-az1--x-s3.s3express-cnn1-pkx1-az1.cn-north-1.amazonaws.com.cn"
        );

        for (bucket, zone_id, region, partition) in [
            (
                "general-purpose-bucket",
                "usw2-az1",
                "us-west-2",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "UPPER--usw2-az1--x-s3",
                "usw2-az1",
                "us-west-2",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "xn--name--usw2-az1--x-s3",
                "usw2-az1",
                "us-west-2",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "example--usw2-az1--x-s3",
                "use1-az4",
                "us-west-2",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "example--usw2-zone1--x-s3",
                "usw2-zone1",
                "us-west-2",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "example--usw2-az1--x-s3",
                "usw2-az1",
                "us-east-1",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "example--usw2-az1--x-s3",
                "usw2-az1",
                "US-WEST-2",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "example--cnn1-pkx1-az1--x-s3",
                "cnn1-pkx1-az1",
                "cn-north-1",
                S3ExpressSessionPartition::Aws,
            ),
            (
                "example--usw2-az1--x-s3",
                "usw2-az1",
                "us-west-2",
                S3ExpressSessionPartition::AwsCn,
            ),
            (
                "example--usgw1-az1--x-s3",
                "usgw1-az1",
                "us-gov-west-1",
                S3ExpressSessionPartition::Aws,
            ),
        ] {
            assert_eq!(
                S3ExpressSessionConfig::new(bucket, zone_id, region, partition)
                    .expect_err("invalid fixed configuration must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }
    }

    #[test]
    fn validates_explicit_custom_endpoint_configuration() {
        S3ExpressSessionGranter::new_with_custom_endpoint(
            "compatible-bucket",
            "custom-region-1",
            "https://sessions.example.com:8443/",
            S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadWrite),
        )
        .expect("custom endpoint configuration must be valid");

        assert_eq!(
            S3ExpressSessionConfig::new(
                "compatible-bucket",
                "custom-zone-1",
                "custom-region-1",
                S3ExpressSessionPartition::Aws,
            )
            .expect_err("the standard AWS constructor must remain strict")
            .kind(),
            ErrorKind::ConfigInvalid
        );
    }

    fn assert_standard_create_session_request(request: &CapturedRequest) {
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.uri,
            "https://example--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com/?session"
                .parse::<Uri>()
                .unwrap()
        );
        assert!(request.body.is_empty());
        assert_eq!(
            request.headers[header::HOST],
            "example--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com"
        );
        assert_eq!(
            request.headers["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(request.headers["x-amz-date"], "20300101T000000Z");
        assert_eq!(
            request.headers["x-amz-security-token"],
            "source-session-token"
        );
        assert!(request.headers["x-amz-security-token"].is_sensitive());
        assert!(!request.headers.contains_key("x-amz-s3session-token"));
        assert!(request.headers[header::AUTHORIZATION].is_sensitive());
    }

    #[tokio::test]
    async fn builds_and_signs_exact_maximum_allowed_create_session_request() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation_with_selection(
            config(),
            S3ExpressSessionGrant::maximum_allowed(),
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );

        let output = operation
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect("maximum-allowed CreateSession must succeed");
        assert_eq!(output.expires_in, Some(timestamp("2030-01-01T00:05:00Z")));

        let request = http.request(0);
        assert_standard_create_session_request(&request);
        assert!(!request.headers.contains_key("x-amz-create-session-mode"));
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/us-west-2/s3express/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=3ae2a693a57537e21f96c0bb753071ff58c7398cd4df5ddf1f772ba059cdf0b2"
        );
        assert_eq!(
            sign_with_aws_sdk(&request, "us-west-2", &source_credential()),
            authorization
        );
    }

    #[tokio::test]
    async fn builds_and_signs_exact_read_only_create_session_request() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation(
            S3ExpressSessionMode::ReadOnly,
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );

        let output = operation
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect("CreateSession must succeed");
        assert_eq!(output.access_key_id, "session-access-key");
        assert_eq!(output.secret_access_key, "session-secret-key");
        assert_eq!(
            output.session_token.as_deref(),
            Some("granted-session-token")
        );
        assert_eq!(output.expires_in, Some(timestamp("2030-01-01T00:05:00Z")));

        let request = http.request(0);
        assert_standard_create_session_request(&request);
        assert_eq!(request.headers["x-amz-create-session-mode"], "ReadOnly");
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/us-west-2/s3express/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-create-session-mode;x-amz-date;x-amz-security-token, Signature=8bced65039aee22da12f49209a59ab8890db30e8d49889c09943697d684ddc1d"
        );
        assert_eq!(
            sign_with_aws_sdk(&request, "us-west-2", &source_credential()),
            authorization
        );
    }

    #[tokio::test]
    async fn builds_and_signs_exact_read_write_create_session_request() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation(
            S3ExpressSessionMode::ReadWrite,
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );

        let output = operation
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect("ReadWrite CreateSession must succeed");
        assert_eq!(output.expires_in, Some(timestamp("2030-01-01T00:05:00Z")));

        let request = http.request(0);
        assert_standard_create_session_request(&request);
        assert_eq!(request.headers["x-amz-create-session-mode"], "ReadWrite");
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/us-west-2/s3express/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-create-session-mode;x-amz-date;x-amz-security-token, Signature=93753ad279dc7f13295350a3ad9bc2d643a3972bd9e1d52caa65fd1716e00374"
        );
        assert_eq!(
            sign_with_aws_sdk(&request, "us-west-2", &source_credential()),
            authorization
        );
    }

    #[tokio::test]
    async fn builds_and_signs_exact_aws_china_create_session_request() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let config = S3ExpressSessionConfig::new(
            "example--cnn1-pkx1-az1--x-s3",
            "cnn1-pkx1-az1",
            "cn-north-1",
            S3ExpressSessionPartition::AwsCn,
        )
        .expect("AWS China configuration must be valid");
        let (operation, ctx, http) = operation_with_config(
            config,
            S3ExpressSessionMode::ReadOnly,
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );

        operation
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect("AWS China CreateSession must succeed");

        let request = http.request(0);
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.uri,
            "https://example--cnn1-pkx1-az1--x-s3.s3express-cnn1-pkx1-az1.cn-north-1.amazonaws.com.cn/?session"
                .parse::<Uri>()
                .unwrap()
        );
        assert_eq!(
            request.headers[header::HOST],
            "example--cnn1-pkx1-az1--x-s3.s3express-cnn1-pkx1-az1.cn-north-1.amazonaws.com.cn"
        );
        assert_eq!(
            request.headers["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(request.headers["x-amz-create-session-mode"], "ReadOnly");
        assert_eq!(request.headers["x-amz-date"], "20300101T000000Z");
        assert_eq!(
            request.headers["x-amz-security-token"],
            "source-session-token"
        );
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/cn-north-1/s3express/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-create-session-mode;x-amz-date;x-amz-security-token, Signature=48449b573534252c610bc8a20a8c76017039bb6c59b56120d41bbdae44fb47a3"
        );
        assert_eq!(
            sign_with_aws_sdk(&request, "cn-north-1", &source_credential()),
            authorization
        );
    }

    #[tokio::test]
    async fn builds_and_signs_exact_custom_endpoint_request_with_temporary_source() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation_with_custom_endpoint(
            S3ExpressSessionMode::ReadOnly,
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );
        let source = source_credential();

        operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("custom endpoint CreateSession must succeed");

        let request = http.request(0);
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.uri,
            "https://sessions.example.com:8443/?session"
                .parse::<Uri>()
                .unwrap()
        );
        assert!(request.body.is_empty());
        assert_eq!(request.headers[header::HOST], "sessions.example.com:8443");
        assert_eq!(request.headers["x-amz-create-session-mode"], "ReadOnly");
        assert_eq!(
            request.headers["x-amz-security-token"],
            "source-session-token"
        );
        assert!(request.headers["x-amz-security-token"].is_sensitive());
        assert!(!request.headers.contains_key("x-amz-s3session-token"));
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/custom-region-1/s3express/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-create-session-mode;x-amz-date;x-amz-security-token, Signature=27e3fd0b349ab99b6e629e8b0c741b3c88bfbef1cb4fbbf491c461df213a0dbe"
        );
        assert_eq!(
            sign_with_aws_sdk(&request, "custom-region-1", &source),
            authorization
        );
    }

    #[tokio::test]
    async fn custom_endpoint_supports_maximum_allowed_selection() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation_with_custom_selection(
            S3ExpressSessionGrant::maximum_allowed(),
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );
        let source = source_credential();

        operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("maximum-allowed custom endpoint CreateSession must succeed");

        let request = http.request(0);
        assert_eq!(
            request.uri,
            "https://sessions.example.com:8443/?session"
                .parse::<Uri>()
                .unwrap()
        );
        assert!(!request.headers.contains_key("x-amz-create-session-mode"));
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert!(authorization.contains("/custom-region-1/s3express/aws4_request"));
        assert!(!authorization.contains("x-amz-create-session-mode"));
        assert_eq!(
            sign_with_aws_sdk(&request, "custom-region-1", &source),
            authorization
        );
    }

    #[tokio::test]
    async fn signs_custom_endpoint_request_with_long_term_source() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation_with_custom_endpoint(
            S3ExpressSessionMode::ReadWrite,
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2030-01-01T00:05:00Z",
            )],
        );
        let source = Credential {
            session_token: None,
            ..source_credential()
        };

        operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("long-term source credential must sign the custom endpoint request");

        let request = http.request(0);
        assert!(!request.headers.contains_key("x-amz-security-token"));
        assert!(!request.headers.contains_key("x-amz-s3session-token"));
        let authorization = request.headers[header::AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/custom-region-1/s3express/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-create-session-mode;x-amz-date, Signature=47ba9abd7e57001176a0c0f77fecd54f1d5c71b680fddeae5549548cf85e1d72"
        );
        assert_eq!(
            sign_with_aws_sdk(&request, "custom-region-1", &source),
            authorization
        );
    }

    #[test]
    fn parses_credentials_and_exact_expiration() {
        let body = success_response(
            "session-access-key",
            "session-secret-key",
            "session-token",
            "2030-01-01T00:05:00Z",
        )
        .into_body();
        let credential = parse_create_session_response(&body, timestamp("2030-01-01T00:00:01Z"))
            .expect("valid response must parse");
        assert_eq!(credential.access_key_id, "session-access-key");
        assert_eq!(credential.secret_access_key, "session-secret-key");
        assert_eq!(credential.session_token.as_deref(), Some("session-token"));
        assert_eq!(
            credential.expires_in,
            Some(timestamp("2030-01-01T00:05:00Z"))
        );
        assert!(credential.is_valid_at(timestamp("2030-01-01T00:04:59Z")));
        assert!(!credential.is_valid_at(timestamp("2030-01-01T00:05:00Z")));
    }

    #[test]
    fn rejects_malformed_incomplete_and_expired_responses_without_leaking_them() {
        let validated_at = timestamp("2030-01-01T00:05:00Z");
        let responses = [
            b"<not-create-session>raw-response-secret</not-create-session>".to_vec(),
            success_response(
                "",
                "sensitive-secret-key",
                "sensitive-session-token",
                "2030-01-01T00:06:00Z",
            )
            .into_body()
            .to_vec(),
            success_response(
                "sensitive-access-key",
                "sensitive-secret-key",
                "sensitive-session-token",
                "not-a-timestamp",
            )
            .into_body()
            .to_vec(),
            success_response(
                "sensitive-access-key",
                "sensitive-secret-key",
                "sensitive-session-token",
                "2030-01-01T00:05:00Z",
            )
            .into_body()
            .to_vec(),
        ];

        for response in responses {
            let err = parse_create_session_response(&response, validated_at)
                .expect_err("unusable response must fail closed");
            let debug = format!("{err:?}");
            for secret in [
                "raw-response-secret",
                "sensitive-access-key",
                "sensitive-secret-key",
                "sensitive-session-token",
                "not-a-timestamp",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn rejects_invalid_lifetime_and_source_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (operation, ctx, http) = operation(S3ExpressSessionMode::ReadWrite, now, []);

        let err = operation
            .grant_credential(&ctx, &source_credential(), Some(Duration::from_secs(300)))
            .await
            .expect_err("CreateSession lifetime is service fixed");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);

        for source in [
            Credential::default(),
            Credential {
                session_token: Some(String::new()),
                ..source_credential()
            },
            Credential {
                expires_in: Some(now + Duration::from_secs(10)),
                ..source_credential()
            },
        ] {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("invalid AWS source credential must fail before I/O");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_invalid_custom_endpoint_configuration_before_provider_io() {
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let invalid = [
            (
                "",
                "custom-region-1",
                "https://sensitive-session.example.com",
            ),
            (
                "compatible-bucket",
                "",
                "https://sensitive-session.example.com",
            ),
            (
                "compatible-bucket",
                "custom/region",
                "https://sensitive-session.example.com",
            ),
            (
                "compatible-bucket",
                "custom-region-1",
                "sensitive-session.example.com",
            ),
            (
                "compatible-bucket",
                "custom-region-1",
                "http://sensitive-session.example.com",
            ),
            ("compatible-bucket", "custom-region-1", "https:///"),
            (
                "compatible-bucket",
                "custom-region-1",
                "https://user@sensitive-session.example.com",
            ),
            (
                "compatible-bucket",
                "custom-region-1",
                "https://sensitive-session.example.com/create-session",
            ),
            (
                "compatible-bucket",
                "custom-region-1",
                "https://sensitive-session.example.com?secret=query",
            ),
            ("compatible-bucket", "custom-region-1", "https://:8443"),
        ];

        for (bucket, region, endpoint) in invalid {
            let result: Result<()> = async {
                let operation = S3ExpressSessionGranter::new_with_custom_endpoint(
                    bucket,
                    region,
                    endpoint,
                    S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadWrite),
                )?;
                Granter::new(ctx.clone(), source_provider.clone(), operation)
                    .grant(None)
                    .await?;
                Ok(())
            }
            .await;
            let err = result.expect_err("invalid custom endpoint configuration must fail");
            assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
            let rendered = format!("{err}\n{err:?}");
            for sensitive in [
                "compatible-bucket",
                "custom-region-1",
                "sensitive-session",
                "secret=query",
            ] {
                assert!(!rendered.contains(sensitive));
            }
        }

        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_output_that_expires_during_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let completed_at = timestamp("2030-01-01T00:05:00Z");
        let (operation, ctx, http) = operation(
            S3ExpressSessionMode::ReadWrite,
            now,
            [success_response(
                "session-access-key",
                "session-secret-key",
                "session-token",
                "2030-01-01T00:05:00Z",
            )],
        );
        let operation = operation.with_time_after_request(completed_at);

        let err = operation
            .grant_credential(&ctx, &source_credential(), None)
            .await
            .expect_err("credential expired at I/O completion must be rejected");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn errors_redact_raw_response_and_session_material() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let denied = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Bytes::from_static(
                b"<Error><Message>raw-response-secret</Message></Error>",
            ))
            .unwrap();
        let (operation, ctx, http) = operation(S3ExpressSessionMode::ReadWrite, now, [denied]);
        let source = source_credential();

        let err = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect_err("denied CreateSession must fail");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        let request = http.request(0);
        let response = CreateSessionResponse {
            credentials: SessionCredentials {
                session_token: "sensitive-session-token".to_string(),
                secret_access_key: "sensitive-secret-key".to_string(),
                access_key_id: "sensitive-access-key".to_string(),
                expiration: "sensitive-expiration".to_string(),
            },
        };
        let provider = S3ExpressSessionProvider::new(
            "sensitive-bucket--usw2-az1--x-s3",
            FixedCredentialProvider::new(source.clone()).0,
        );
        let resolved_config = S3ExpressSessionConfig::from_bucket(
            "resolved-sensitive-bucket--usw2-az1--x-s3",
            "us-west-2",
        )
        .expect("sensitive configuration must resolve");
        let resolution_err = S3ExpressSessionConfig::from_bucket(
            "mismatched-sensitive-bucket--use1-az1--x-s3",
            "us-west-2",
        )
        .expect_err("mismatched sensitive configuration must fail");

        for (debug, secret) in [
            (format!("{:?}", config()), "example--usw2-az1--x-s3"),
            (format!("{resolved_config:?}"), "resolved-sensitive-bucket"),
            (format!("{resolution_err:?}"), "mismatched-sensitive-bucket"),
            (
                format!(
                    "{:?}",
                    S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadWrite)
                ),
                "ReadWrite",
            ),
            (
                format!(
                    "{:?}",
                    S3ExpressSessionGrantSelection::from(S3ExpressSessionGrant::new(
                        S3ExpressSessionMode::ReadWrite
                    ))
                ),
                "ReadWrite",
            ),
            (format!("{operation:?}"), "example--usw2-az1--x-s3"),
            (format!("{provider:?}"), "sensitive-bucket"),
            (format!("{source:?}"), "source-session-token"),
            (format!("{request:?}"), "source-session-token"),
            (format!("{response:?}"), "sensitive-session-token"),
            (format!("{response:?}"), "sensitive-secret-key"),
            (format!("{response:?}"), "sensitive-access-key"),
            (format!("{response:?}"), "sensitive-expiration"),
            (format!("{err:?}"), "raw-response-secret"),
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[tokio::test]
    async fn custom_endpoint_debug_and_transport_errors_are_redacted() {
        let operation = S3ExpressSessionGranter::new_with_custom_endpoint(
            "sensitive-compatible-bucket",
            "sensitive-region-1",
            "https://sensitive-session.example.com",
            S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadWrite),
        )
        .expect("custom endpoint configuration must be valid")
        .with_time(timestamp("2030-01-01T00:00:00Z"));
        let source = source_credential();
        let ctx = Context::new().with_http_send(FailingHttpSend);

        let err = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect_err("transport failure must be sanitized");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());
        assert_eq!(err.context(), &["operation: CreateSession"]);

        let combined = format!("{operation:?}\n{source:?}\n{err:?}");
        for sensitive in [
            "sensitive-compatible-bucket",
            "sensitive-region-1",
            "sensitive-session.example.com",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "source-session-token",
        ] {
            assert!(!combined.contains(sensitive));
        }
    }

    #[test]
    fn classifies_create_session_status_errors_for_retry() {
        for (status, kind, retryable) in [
            (StatusCode::FORBIDDEN, ErrorKind::PermissionDenied, false),
            (StatusCode::TOO_MANY_REQUESTS, ErrorKind::RateLimited, true),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorKind::Unexpected,
                true,
            ),
            (StatusCode::SERVICE_UNAVAILABLE, ErrorKind::Unexpected, true),
            (StatusCode::BAD_REQUEST, ErrorKind::Unexpected, false),
        ] {
            let err = create_session_status_error(status);
            assert_eq!(err.kind(), kind);
            assert_eq!(err.is_retryable(), retryable);
            assert_eq!(err.context(), &[format!("status: {}", status.as_u16())]);
        }
    }

    #[tokio::test]
    async fn preserves_fixed_flow_provider_compatibility() {
        let response = success_response(
            "session-access-key",
            "session-secret-key",
            "session-token",
            "2099-01-01T00:05:00Z",
        );
        let http = MockHttpSend::new([response]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let provider = S3ExpressSessionProvider::new("example--usw2-az1--x-s3", source_provider);

        let output = provider
            .provide_credential(&ctx)
            .await
            .expect("compatibility provider must succeed")
            .expect("compatibility provider must return a credential");
        assert_eq!(output.access_key_id, "session-access-key");
        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        let request = http.request(0);
        assert_eq!(request.headers["x-amz-create-session-mode"], "ReadWrite");
        assert_eq!(
            request.uri.authority().unwrap().as_str(),
            "example--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com"
        );
    }

    #[tokio::test]
    async fn compatibility_provider_uses_explicit_region_for_new_zone_prefix() {
        let response = success_response(
            "session-access-key",
            "session-secret-key",
            "session-token",
            "2099-01-01T00:05:00Z",
        );
        let http = MockHttpSend::new([response]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let provider = S3ExpressSessionProvider::new("example--apse6-az1--x-s3", source_provider)
            .with_region("ap-southeast-6");

        provider
            .provide_credential(&ctx)
            .await
            .expect("explicit Region compatibility provider must succeed")
            .expect("compatibility provider must return a credential");

        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            http.request(0).uri.authority().unwrap().as_str(),
            "example--apse6-az1--x-s3.s3express-apse6-az1.ap-southeast-6.amazonaws.com"
        );
    }

    #[tokio::test]
    async fn compatibility_provider_resolves_aws_china_partition() {
        let response = success_response(
            "session-access-key",
            "session-secret-key",
            "session-token",
            "2099-01-01T00:05:00Z",
        );
        let http = MockHttpSend::new([response]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let provider =
            S3ExpressSessionProvider::new("example--cnn1-pkx1-az1--x-s3", source_provider);

        provider
            .provide_credential(&ctx)
            .await
            .expect("AWS China compatibility provider must succeed")
            .expect("AWS China compatibility provider must return a credential");

        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        let request = http.request(0);
        assert_eq!(
            request.uri.authority().unwrap().as_str(),
            "example--cnn1-pkx1-az1--x-s3.s3express-cnn1-pkx1-az1.cn-north-1.amazonaws.com.cn"
        );
        assert!(
            request.headers[header::AUTHORIZATION]
                .to_str()
                .expect("authorization must be ASCII")
                .contains("/cn-north-1/s3express/aws4_request")
        );
    }

    #[tokio::test]
    async fn provider_validates_configuration_before_loading_source() {
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let provider = S3ExpressSessionProvider::new("invalid-bucket", source_provider);

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("invalid fixed configuration must fail");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_rejects_unsupported_partition_before_loading_source() {
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let provider = S3ExpressSessionProvider::new("example--usgw1-az1--x-s3", source_provider)
            .with_region("us-gov-west-1");

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("unsupported S3 Express partition must fail");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_rejects_zone_region_mismatch_before_loading_source() {
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let provider = S3ExpressSessionProvider::new("example--use1-az1--x-s3", source_provider)
            .with_region("us-west-2");

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("Zone/Region mismatch must fail before source loading");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn granter_never_caches_outputs_and_existing_signer_consumes_them() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let response = || {
            success_response(
                "session-access-key",
                "session-secret-key",
                "granted-session-token",
                "2099-01-01T00:05:00Z",
            )
        };
        let http = MockHttpSend::new([response(), response()]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation =
            S3ExpressSessionGranter::new(config(), S3ExpressSessionGrant::maximum_allowed())
                .with_time(now);
        let (source_provider, source_calls) = FixedCredentialProvider::new(source_credential());
        let granter = Granter::new(ctx, source_provider, operation);

        let output = granter.grant(None).await.expect("first grant must succeed");
        granter
            .grant(None)
            .await
            .expect("second grant must issue another session");
        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert!(
            !http
                .request(0)
                .headers
                .contains_key("x-amz-create-session-mode")
        );
        assert!(
            !http
                .request(1)
                .headers
                .contains_key("x-amz-create-session-mode")
        );

        let (output_provider, _) = FixedCredentialProvider::new(output);
        let signer = Signer::new(
            Context::new(),
            output_provider,
            crate::RequestSigner::new("s3express", "us-west-2"),
        );
        let mut parts = Request::get(
            "https://example--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com/object",
        )
        .body(())
        .unwrap()
        .into_parts()
        .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("existing AWS signer must consume granted credentials");

        assert_eq!(
            parts.headers["x-amz-s3session-token"],
            "granted-session-token"
        );
        assert!(parts.headers["x-amz-s3session-token"].is_sensitive());
        assert!(!parts.headers.contains_key("x-amz-security-token"));
        assert!(parts.headers.contains_key(header::AUTHORIZATION));
    }
}
