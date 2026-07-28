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
use crate::constants::AZURE_QUERY_ENCODE_SET;
use crate::user_delegation::{
    MAX_USER_DELEGATION_KEY_LIFETIME, UserDelegationKey, UserDelegationKeyCache,
    UserDelegationKeyRequest, UserDelegationSasResource, UserDelegationSharedAccessSignature,
    ceil_to_wire_second, floor_to_wire_second, get_user_delegation_key, user_delegation_key_covers,
};
use percent_encoding::percent_encode;
use reqsign_core::hash::hex_sha256;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::ops::{BitOr, BitOrAssign};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const USER_DELEGATION_SERVICE_VERSION: &str = "2020-12-06";
const MAX_USER_DELEGATION_LIFETIME: Duration = MAX_USER_DELEGATION_KEY_LIFETIME;
const BEARER_TOKEN_OPERATION_HEADROOM: Duration = Duration::from_secs(20);

/// Permissions that can be granted by an Azure Storage user delegation SAS.
///
/// Combining values with `|` produces the canonical Azure permission order.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct UserDelegationSasPermissions(u16);

impl UserDelegationSasPermissions {
    /// Read resource data and metadata.
    pub const READ: Self = Self(1 << 0);
    /// Add blocks to an append blob.
    pub const ADD: Self = Self(1 << 1);
    /// Create blobs or directories.
    pub const CREATE: Self = Self(1 << 2);
    /// Write resource data and metadata.
    pub const WRITE: Self = Self(1 << 3);
    /// Delete resources.
    pub const DELETE: Self = Self(1 << 4);
    /// Delete a blob version.
    pub const DELETE_VERSION: Self = Self(1 << 5);
    /// Permanently delete a blob snapshot or version.
    pub const PERMANENT_DELETE: Self = Self(1 << 6);
    /// List blobs or directory entries.
    pub const LIST: Self = Self(1 << 7);
    /// Read or write blob index tags.
    pub const TAGS: Self = Self(1 << 8);
    /// Find blobs by tags within a container.
    pub const FILTER_BY_TAGS: Self = Self(1 << 9);
    /// Move a blob or directory.
    pub const MOVE: Self = Self(1 << 10);
    /// Read system properties or POSIX ACLs.
    pub const EXECUTE: Self = Self(1 << 11);
    /// Set the owner or owning group for hierarchical namespace resources.
    pub const OWNERSHIP: Self = Self(1 << 12);
    /// Set POSIX permissions or ACLs for hierarchical namespace resources.
    pub const PERMISSIONS: Self = Self(1 << 13);
    /// Set an immutability policy or legal hold.
    pub const SET_IMMUTABILITY_POLICY: Self = Self(1 << 14);

    /// Return whether no permission is selected.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return whether all permissions in `other` are selected.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn is_subset_of(self, allowed: Self) -> bool {
        self.0 & !allowed.0 == 0
    }

    fn as_canonical_string(self) -> String {
        [
            (Self::READ, 'r'),
            (Self::ADD, 'a'),
            (Self::CREATE, 'c'),
            (Self::WRITE, 'w'),
            (Self::DELETE, 'd'),
            (Self::DELETE_VERSION, 'x'),
            (Self::PERMANENT_DELETE, 'y'),
            (Self::LIST, 'l'),
            (Self::TAGS, 't'),
            (Self::FILTER_BY_TAGS, 'f'),
            (Self::MOVE, 'm'),
            (Self::EXECUTE, 'e'),
            (Self::OWNERSHIP, 'o'),
            (Self::PERMISSIONS, 'p'),
            (Self::SET_IMMUTABILITY_POLICY, 'i'),
        ]
        .into_iter()
        .filter_map(|(permission, symbol)| self.contains(permission).then_some(symbol))
        .collect()
    }
}

impl Debug for UserDelegationSasPermissions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserDelegationSasPermissions(REDACTED)")
    }
}

impl BitOr for UserDelegationSasPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for UserDelegationSasPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Protocol restriction embedded in a user delegation SAS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SasProtocol {
    /// Require HTTPS for every request that uses the SAS.
    #[default]
    Https,
    /// Permit either HTTPS or HTTP.
    HttpsAndHttp,
}

impl SasProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::HttpsAndHttp => "https,http",
        }
    }
}

#[derive(Clone)]
enum UserDelegationSasGrantResource {
    Container {
        container: String,
    },
    Blob {
        container: String,
        blob: String,
    },
    PathPrefix {
        container: String,
        path_prefix: String,
    },
}

/// A typed Azure Storage resource and permission grant for user delegation SAS.
///
/// Resource names are logical, percent-decoded Azure names. Path prefixes map
/// to Azure's directory/prefix SAS resource (`sr=d`) and therefore require a
/// hierarchical-namespace or otherwise prefix-capable storage account.
#[derive(Clone)]
pub struct UserDelegationSasGrant {
    resource: UserDelegationSasGrantResource,
    permissions: UserDelegationSasPermissions,
}

impl Debug for UserDelegationSasGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserDelegationSasGrant")
            .finish_non_exhaustive()
    }
}

impl UserDelegationSasGrant {
    /// Grant access to a container.
    pub fn for_container(
        container: impl Into<String>,
        permissions: UserDelegationSasPermissions,
    ) -> Self {
        Self {
            resource: UserDelegationSasGrantResource::Container {
                container: container.into(),
            },
            permissions,
        }
    }

    /// Grant access to one exact blob.
    ///
    /// The percent-decoded blob name must contain at most 1,024 Unicode
    /// scalar values.
    pub fn for_blob(
        container: impl Into<String>,
        blob: impl Into<String>,
        permissions: UserDelegationSasPermissions,
    ) -> Self {
        Self {
            resource: UserDelegationSasGrantResource::Blob {
                container: container.into(),
                blob: blob.into(),
            },
            permissions,
        }
    }

    /// Grant access to one non-empty directory or path prefix.
    ///
    /// The prefix must be a relative, slash-separated path without a leading
    /// slash, trailing slash, empty segment, `.` segment, or `..` segment.
    /// It may contain at most 61 segments after accounting for the storage
    /// account and container segments in Azure's hierarchical-namespace limit.
    pub fn for_path_prefix(
        container: impl Into<String>,
        path_prefix: impl Into<String>,
        permissions: UserDelegationSasPermissions,
    ) -> Self {
        Self {
            resource: UserDelegationSasGrantResource::PathPrefix {
                container: container.into(),
                path_prefix: path_prefix.into(),
            },
            permissions,
        }
    }

    fn validate(&self) -> Result<ValidatedGrant> {
        if self.permissions.is_empty() {
            return Err(Error::request_invalid(
                "user delegation SAS permissions must not be empty",
            ));
        }

        let resource = match &self.resource {
            UserDelegationSasGrantResource::Container { container } => {
                validate_container(container)?;
                let allowed = UserDelegationSasPermissions::READ
                    | UserDelegationSasPermissions::ADD
                    | UserDelegationSasPermissions::CREATE
                    | UserDelegationSasPermissions::WRITE
                    | UserDelegationSasPermissions::DELETE
                    | UserDelegationSasPermissions::DELETE_VERSION
                    | UserDelegationSasPermissions::LIST
                    | UserDelegationSasPermissions::TAGS
                    | UserDelegationSasPermissions::FILTER_BY_TAGS
                    | UserDelegationSasPermissions::MOVE
                    | UserDelegationSasPermissions::EXECUTE
                    | UserDelegationSasPermissions::SET_IMMUTABILITY_POLICY
                    | UserDelegationSasPermissions::OWNERSHIP
                    | UserDelegationSasPermissions::PERMISSIONS;
                validate_permissions(self.permissions, allowed)?;
                UserDelegationSasResource::Container {
                    container: container.clone(),
                }
            }
            UserDelegationSasGrantResource::Blob { container, blob } => {
                validate_container(container)?;
                validate_blob(blob)?;
                let allowed = UserDelegationSasPermissions::READ
                    | UserDelegationSasPermissions::ADD
                    | UserDelegationSasPermissions::CREATE
                    | UserDelegationSasPermissions::WRITE
                    | UserDelegationSasPermissions::DELETE
                    | UserDelegationSasPermissions::DELETE_VERSION
                    | UserDelegationSasPermissions::PERMANENT_DELETE
                    | UserDelegationSasPermissions::LIST
                    | UserDelegationSasPermissions::TAGS
                    | UserDelegationSasPermissions::MOVE
                    | UserDelegationSasPermissions::EXECUTE
                    | UserDelegationSasPermissions::SET_IMMUTABILITY_POLICY
                    | UserDelegationSasPermissions::OWNERSHIP
                    | UserDelegationSasPermissions::PERMISSIONS;
                validate_permissions(self.permissions, allowed)?;
                UserDelegationSasResource::Blob {
                    container: container.clone(),
                    blob: blob.clone(),
                }
            }
            UserDelegationSasGrantResource::PathPrefix {
                container,
                path_prefix,
            } => {
                validate_container(container)?;
                let depth = validate_path_prefix(path_prefix)?;
                let allowed = UserDelegationSasPermissions::READ
                    | UserDelegationSasPermissions::ADD
                    | UserDelegationSasPermissions::CREATE
                    | UserDelegationSasPermissions::WRITE
                    | UserDelegationSasPermissions::DELETE
                    | UserDelegationSasPermissions::LIST
                    | UserDelegationSasPermissions::MOVE
                    | UserDelegationSasPermissions::EXECUTE
                    | UserDelegationSasPermissions::OWNERSHIP
                    | UserDelegationSasPermissions::PERMISSIONS;
                validate_permissions(self.permissions, allowed)?;
                UserDelegationSasResource::Directory {
                    container: container.clone(),
                    path: path_prefix.clone(),
                    depth,
                }
            }
        };

        Ok(ValidatedGrant {
            resource,
            permissions: self.permissions.as_canonical_string(),
        })
    }
}

struct ValidatedGrant {
    resource: UserDelegationSasResource,
    permissions: String,
}

fn validate_permissions(
    permissions: UserDelegationSasPermissions,
    allowed: UserDelegationSasPermissions,
) -> Result<()> {
    if !permissions.is_subset_of(allowed) {
        return Err(Error::request_invalid(
            "user delegation SAS permissions are not supported for the selected resource",
        ));
    }
    Ok(())
}

fn validate_account(account: &str) -> Result<()> {
    if !(3..=24).contains(&account.len())
        || !account
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
    {
        return Err(Error::config_invalid(
            "Azure storage account name must be 3-24 lowercase ASCII letters or digits",
        ));
    }
    Ok(())
}

fn validate_container(container: &str) -> Result<()> {
    if matches!(container, "$root" | "$web" | "$logs") {
        return Ok(());
    }
    if !(3..=63).contains(&container.len())
        || !container
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
        || !container
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !container
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || container.contains("--")
    {
        return Err(Error::request_invalid(
            "invalid Azure Blob Storage container name",
        ));
    }
    Ok(())
}

fn validate_blob(blob: &str) -> Result<()> {
    if blob.is_empty()
        || blob.chars().count() > 1024
        || blob.starts_with('/')
        || blob
            .chars()
            .any(|value| value.is_control() || value == '\\')
    {
        return Err(Error::request_invalid(
            "blob name must be a non-empty relative percent-decoded path",
        ));
    }
    Ok(())
}

fn validate_path_prefix(path_prefix: &str) -> Result<usize> {
    validate_blob(path_prefix)?;
    if path_prefix.ends_with('/') {
        return Err(Error::request_invalid(
            "path prefix must not end with a slash",
        ));
    }
    let segments = path_prefix.split('/').collect::<Vec<_>>();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err(Error::request_invalid(
            "path prefix contains an empty or ambiguous segment",
        ));
    }
    if segments.len() > 61 {
        return Err(Error::request_invalid(
            "path prefix exceeds the Azure hierarchical namespace segment limit",
        ));
    }
    Ok(segments.len())
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct UserDelegationKeyCacheKey {
    account: String,
    endpoint: String,
    source_authority: String,
    service_version: &'static str,
}

#[derive(Clone)]
struct ParsedEndpoint {
    scheme: String,
    authority: String,
    identity: String,
}

struct OperationTimes {
    now: Timestamp,
    start: Option<Timestamp>,
    expiry: Timestamp,
    key_start: Timestamp,
    key_expiry: Timestamp,
}

/// Grants expiration-aware Azure Storage user delegation SAS credentials.
///
/// The source credential must be [`Credential::BearerToken`]. Clones and
/// values produced with [`UserDelegationSasGranter::with_grant`] share a
/// source-aware user delegation key cache. The cache is partitioned by account,
/// endpoint, source bearer authority, and service version, and is bounded to a
/// fixed number of live entries. No singleflight behavior is promised.
///
/// Azure SAS wire timestamps have whole-second precision. Explicit start times
/// are rounded forward, expirations are rounded backward, and the returned
/// credential expiration exactly matches the signed `se` value.
#[derive(Clone)]
pub struct UserDelegationSasGranter {
    account: String,
    endpoint: String,
    grant: UserDelegationSasGrant,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: SasProtocol,
    key_cache: Arc<Mutex<UserDelegationKeyCache<UserDelegationKeyCacheKey>>>,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for UserDelegationSasGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserDelegationSasGranter")
            .finish_non_exhaustive()
    }
}

impl UserDelegationSasGranter {
    /// Create a granter for an Azure storage account and typed grant.
    ///
    /// The default service endpoint is
    /// `https://{account}.blob.core.windows.net`.
    pub fn new(account: impl Into<String>, grant: UserDelegationSasGrant) -> Self {
        let account = account.into();
        Self {
            endpoint: format!("https://{account}.blob.core.windows.net"),
            account,
            grant,
            start: None,
            ip: None,
            protocol: SasProtocol::Https,
            key_cache: Arc::new(Mutex::new(UserDelegationKeyCache::default())),
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound grant while retaining the shared user delegation key cache.
    pub fn with_grant(mut self, grant: UserDelegationSasGrant) -> Self {
        self.grant = grant;
        self
    }

    /// Replace the HTTPS Blob service endpoint with an explicitly trusted authority.
    ///
    /// The source Bearer token is sent to this endpoint. The caller must trust
    /// the endpoint to receive that credential. It must have no path or query,
    /// and its first DNS label must equal the configured storage account name.
    pub fn with_trusted_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Set an optional SAS start time.
    pub fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    /// Restrict the SAS to one IPv4 address or inclusive IPv4 range.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Set the protocol restriction embedded in the SAS.
    pub fn with_protocol(mut self, protocol: SasProtocol) -> Self {
        self.protocol = protocol;
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

    fn parse_endpoint(&self) -> Result<ParsedEndpoint> {
        validate_account(&self.account)?;
        let uri: http::Uri = self.endpoint.parse().map_err(|e| {
            Error::config_invalid("invalid Azure Blob service endpoint").with_source(e)
        })?;
        if uri.scheme_str() != Some("https") {
            return Err(Error::config_invalid(
                "Azure user delegation key endpoint must use HTTPS",
            ));
        }
        if uri.path() != "/" || uri.query().is_some() {
            return Err(Error::config_invalid(
                "Azure Blob service endpoint must not include a path or query",
            ));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| Error::config_invalid("Azure Blob service endpoint has no authority"))?;
        let host = uri
            .host()
            .ok_or_else(|| Error::config_invalid("Azure Blob service endpoint has no host"))?;
        if host.split('.').next() != Some(self.account.as_str()) {
            return Err(Error::config_invalid(
                "Azure Blob service endpoint does not match the storage account",
            ));
        }

        Ok(ParsedEndpoint {
            scheme: "https".to_string(),
            authority: authority.as_str().to_string(),
            identity: format!("https://{}", authority.as_str()),
        })
    }

    fn operation_times(&self, expires_in: Option<Duration>) -> Result<OperationTimes> {
        let expires_in = expires_in.ok_or_else(|| {
            Error::request_invalid("Azure user delegation SAS requires an explicit lifetime")
        })?;
        if expires_in.is_zero() || expires_in > MAX_USER_DELEGATION_LIFETIME {
            return Err(Error::request_invalid(
                "Azure user delegation SAS lifetime must be greater than zero and at most seven days",
            ));
        }

        let now = self.now();
        let expiry = floor_to_wire_second(now + expires_in)?;
        if expiry <= now {
            return Err(Error::request_invalid(
                "Azure user delegation SAS lifetime does not reach a future wire timestamp",
            ));
        }
        let start = self.start.map(ceil_to_wire_second).transpose()?;
        if start.is_some_and(|start| start >= expiry) {
            return Err(Error::request_invalid(
                "Azure user delegation SAS start time must be before its expiration",
            ));
        }

        let key_start = floor_to_wire_second(start.map_or(now, |start| start.min(now)))?;
        let key_expiry = key_start + MAX_USER_DELEGATION_LIFETIME;
        if expiry > key_expiry {
            return Err(Error::request_invalid(
                "Azure user delegation SAS interval exceeds the seven-day user delegation key limit",
            ));
        }

        Ok(OperationTimes {
            now,
            start,
            expiry,
            key_start,
            key_expiry,
        })
    }

    fn validate_ip(&self) -> Result<()> {
        let Some(ip) = &self.ip else {
            return Ok(());
        };
        if let Some((start, end)) = ip.split_once('-') {
            let start = Ipv4Addr::from_str(start)
                .map_err(|_| Error::request_invalid("invalid SAS IPv4 range"))?;
            let end = Ipv4Addr::from_str(end)
                .map_err(|_| Error::request_invalid("invalid SAS IPv4 range"))?;
            if u32::from(start) > u32::from(end) {
                return Err(Error::request_invalid(
                    "SAS IPv4 range start must not exceed its end",
                ));
            }
        } else {
            Ipv4Addr::from_str(ip)
                .map_err(|_| Error::request_invalid("invalid SAS IPv4 address"))?;
        }
        Ok(())
    }

    fn cache_key(
        &self,
        endpoint: &ParsedEndpoint,
        bearer_token: &str,
    ) -> UserDelegationKeyCacheKey {
        UserDelegationKeyCacheKey {
            account: self.account.clone(),
            endpoint: endpoint.identity.clone(),
            source_authority: hex_sha256(bearer_token.as_bytes()),
            service_version: USER_DELEGATION_SERVICE_VERSION,
        }
    }

    fn key_covers(
        key: &UserDelegationKey,
        times: &OperationTimes,
        current_time: Timestamp,
    ) -> bool {
        let effective_start = times.start.unwrap_or(times.now);
        user_delegation_key_covers(
            key,
            effective_start,
            times.expiry,
            current_time,
            USER_DELEGATION_SERVICE_VERSION,
        )
    }

    fn cached_key(
        &self,
        cache_key: &UserDelegationKeyCacheKey,
        times: &OperationTimes,
    ) -> Option<UserDelegationKey> {
        self.key_cache
            .lock()
            .expect("lock poisoned")
            .find_cloned(cache_key, |key| Self::key_covers(key, times, times.now))
    }
}

impl GrantCredential for UserDelegationSasGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        let now = self.now();
        let Credential::BearerToken { token, .. } = credential else {
            return now + BEARER_TOKEN_OPERATION_HEADROOM;
        };
        let Ok(endpoint) = self.parse_endpoint() else {
            return now + BEARER_TOKEN_OPERATION_HEADROOM;
        };
        let Ok(times) = self.operation_times(expires_in) else {
            return now + BEARER_TOKEN_OPERATION_HEADROOM;
        };
        let cache_key = self.cache_key(&endpoint, token);
        if self.cached_key(&cache_key, &times).is_some() {
            now
        } else {
            now + BEARER_TOKEN_OPERATION_HEADROOM
        }
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let Credential::BearerToken { token, .. } = credential else {
            return Err(Error::credential_invalid(
                "Azure user delegation SAS requires a bearer token source credential",
            ));
        };

        let endpoint = self.parse_endpoint()?;
        let grant = self.grant.validate()?;
        self.validate_ip()?;
        let times = self.operation_times(expires_in)?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Azure bearer token expires before the user delegation key request can complete",
            ));
        }

        let cache_key = self.cache_key(&endpoint, token);
        let cached = self.cached_key(&cache_key, &times);
        let (key, fetched) = if let Some(key) = cached {
            (key, false)
        } else {
            let required_until = self.now() + BEARER_TOKEN_OPERATION_HEADROOM;
            if !credential.is_valid_at(required_until) {
                return Err(Error::credential_invalid(
                    "Azure bearer token expires before the user delegation key request can complete",
                ));
            }
            let key = get_user_delegation_key(
                ctx,
                UserDelegationKeyRequest {
                    scheme: &endpoint.scheme,
                    authority: &endpoint.authority,
                    bearer_token: token,
                    start: times.key_start,
                    expiry: times.key_expiry,
                    service_version: USER_DELEGATION_SERVICE_VERSION,
                    now: times.now,
                },
            )
            .await?;
            (key, true)
        };

        let after_io = if fetched {
            self.now_after_request()
        } else {
            self.now()
        };
        if times.expiry <= after_io {
            return Err(Error::request_invalid(
                "Azure user delegation SAS expired before granting completed",
            ));
        }
        if !Self::key_covers(&key, &times, after_io) {
            return Err(Error::credential_invalid(
                "Azure user delegation key does not cover the requested SAS interval",
            ));
        }

        let mut signer = UserDelegationSharedAccessSignature::new(
            self.account.clone(),
            key.clone(),
            grant.resource,
            grant.permissions,
            times.expiry,
        )
        .with_protocol(self.protocol.as_str());
        if let Some(start) = times.start {
            signer = signer.with_start(start);
        }
        if let Some(ip) = &self.ip {
            signer = signer.with_ip(ip);
        }

        let pairs = signer.token().map_err(|e| {
            Error::unexpected("failed to generate Azure user delegation SAS").with_source(e)
        })?;
        let token = encode_query_pairs(&pairs);
        let output = Credential::with_sas_token_expires_at(&token, times.expiry);
        if !output.is_valid_at(after_io) {
            return Err(Error::credential_invalid(
                "granted Azure user delegation SAS is not currently usable",
            ));
        }

        if fetched {
            let mut cache = self.key_cache.lock().expect("lock poisoned");
            cache.insert(cache_key, key, after_io);
        }

        Ok(output)
    }
}

fn encode_query_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode(key.as_bytes(), &AZURE_QUERY_ENCODE_SET),
                percent_encode(value.as_bytes(), &AZURE_QUERY_ENCODE_SET)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RequestSigner, StaticCredentialProvider};
    use bytes::Bytes;
    use percent_encoding::percent_decode_str;
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        method: http::Method,
        uri: String,
        version: Option<String>,
        date: Option<String>,
        content_type: Option<String>,
        authorization: Option<String>,
        authorization_sensitive: bool,
        body: String,
    }

    #[derive(Clone)]
    struct MockUserDelegationHttpSend {
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        responses: Arc<Mutex<VecDeque<String>>>,
    }

    impl Debug for MockUserDelegationHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockUserDelegationHttpSend")
                .field("calls", &self.calls.load(Ordering::SeqCst))
                .finish_non_exhaustive()
        }
    }

    impl MockUserDelegationHttpSend {
        fn new(responses: impl IntoIterator<Item = String>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            }
        }
    }

    impl HttpSend for MockUserDelegationHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let authorization = req.headers().get(http::header::AUTHORIZATION);
            self.requests
                .lock()
                .expect("lock poisoned")
                .push(CapturedRequest {
                    method: req.method().clone(),
                    uri: req.uri().to_string(),
                    version: req
                        .headers()
                        .get("x-ms-version")
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string),
                    date: req
                        .headers()
                        .get("x-ms-date")
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string),
                    content_type: req
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string),
                    authorization: authorization
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string),
                    authorization_sensitive: authorization
                        .is_some_and(http::HeaderValue::is_sensitive),
                    body: String::from_utf8_lossy(req.body()).into_owned(),
                });

            let body = self
                .responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("missing mock user delegation key response"))?;
            Ok(http::Response::builder()
                .status(200)
                .body(Bytes::from(body))
                .expect("mock response must build"))
        }
    }

    #[derive(Clone)]
    struct FixedCredentialProvider(Credential);

    impl Debug for FixedCredentialProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FixedCredentialProvider")
                .finish_non_exhaustive()
        }
    }

    impl ProvideCredential for FixedCredentialProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(Some(self.0.clone()))
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must parse")
    }

    fn delegation_key_response(
        signed_start: Timestamp,
        signed_expiry: Timestamp,
        oid: &str,
        tid: &str,
        value: &str,
    ) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <UserDelegationKey>\
             <SignedOid>{oid}</SignedOid>\
             <SignedTid>{tid}</SignedTid>\
             <SignedStart>{}</SignedStart>\
             <SignedExpiry>{}</SignedExpiry>\
             <SignedService>b</SignedService>\
             <SignedVersion>{USER_DELEGATION_SERVICE_VERSION}</SignedVersion>\
             <Value>{value}</Value>\
             </UserDelegationKey>",
            signed_start.format_rfc3339_zulu(),
            signed_expiry.format_rfc3339_zulu(),
        )
    }

    fn bearer(token: &str) -> Credential {
        Credential::with_bearer_token(token, None)
    }

    fn output_parts(credential: &Credential) -> (&str, Timestamp) {
        match credential {
            Credential::SasToken {
                token,
                expires_at: Some(expires_at),
            } => (token, *expires_at),
            other => panic!("expected expiring SAS token, got {other:?}"),
        }
    }

    fn query_value(token: &str, key: &str) -> Option<String> {
        token.split('&').find_map(|element| {
            let (candidate, value) = element.split_once('=')?;
            (candidate == key).then(|| {
                percent_decode_str(value)
                    .decode_utf8()
                    .expect("query value must be UTF-8")
                    .into_owned()
            })
        })
    }

    fn blob_grant(path: &str, permissions: UserDelegationSasPermissions) -> UserDelegationSasGrant {
        UserDelegationSasGrant::for_blob("container", path, permissions)
    }

    #[test]
    fn serializes_permissions_in_azure_canonical_order() {
        let common = UserDelegationSasPermissions::READ
            | UserDelegationSasPermissions::ADD
            | UserDelegationSasPermissions::CREATE
            | UserDelegationSasPermissions::WRITE
            | UserDelegationSasPermissions::DELETE
            | UserDelegationSasPermissions::DELETE_VERSION
            | UserDelegationSasPermissions::TAGS
            | UserDelegationSasPermissions::MOVE
            | UserDelegationSasPermissions::EXECUTE
            | UserDelegationSasPermissions::OWNERSHIP
            | UserDelegationSasPermissions::PERMISSIONS
            | UserDelegationSasPermissions::SET_IMMUTABILITY_POLICY;
        let container = UserDelegationSasGrant::for_container(
            "container",
            common
                | UserDelegationSasPermissions::LIST
                | UserDelegationSasPermissions::FILTER_BY_TAGS,
        )
        .validate()
        .expect("container permissions must be valid");
        assert_eq!(container.permissions, "racwdxltfmeopi");

        let blob = blob_grant(
            "blob",
            common
                | UserDelegationSasPermissions::PERMANENT_DELETE
                | UserDelegationSasPermissions::LIST,
        )
        .validate()
        .expect("blob permissions must be valid");
        assert_eq!(blob.permissions, "racwdxyltmeopi");

        assert!(
            blob_grant("blob", UserDelegationSasPermissions::FILTER_BY_TAGS)
                .validate()
                .is_err()
        );
    }

    #[tokio::test]
    async fn grants_real_user_delegation_protocol_shape() {
        let now = timestamp("2022-03-01T08:12:34Z");
        let key_expiry = now + MAX_USER_DELEGATION_LIFETIME;
        let http = MockUserDelegationHttpSend::new([delegation_key_response(
            now, key_expiry, "oid", "tid", "a2V5",
        )]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = UserDelegationSasGranter::new(
            "account",
            blob_grant(
                "path/to/blob name.txt",
                UserDelegationSasPermissions::WRITE | UserDelegationSasPermissions::READ,
            ),
        )
        .with_time(now);

        let output = operation
            .grant_credential(
                &ctx,
                &bearer("source-bearer-secret"),
                Some(Duration::from_secs(300)),
            )
            .await
            .expect("grant must succeed");

        let requests = http.requests.lock().expect("lock poisoned");
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, http::Method::POST);
        assert_eq!(
            request.uri,
            "https://account.blob.core.windows.net/?restype=service&comp=userdelegationkey"
        );
        assert_eq!(request.version.as_deref(), Some("2020-12-06"));
        assert_eq!(
            request.date.as_deref(),
            Some("Tue, 01 Mar 2022 08:12:34 GMT")
        );
        assert_eq!(request.content_type.as_deref(), Some("application/xml"));
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer source-bearer-secret")
        );
        assert!(request.authorization_sensitive);
        assert_eq!(
            request.body,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>2022-03-01T08:12:34Z</Start><Expiry>2022-03-08T08:12:34Z</Expiry></KeyInfo>"
        );

        let (token, expires_at) = output_parts(&output);
        assert_eq!(expires_at, timestamp("2022-03-01T08:17:34Z"));
        assert_eq!(query_value(token, "sv").as_deref(), Some("2020-12-06"));
        assert_eq!(
            query_value(token, "se").as_deref(),
            Some("2022-03-01T08:17:34Z")
        );
        assert_eq!(query_value(token, "sp").as_deref(), Some("rw"));
        assert_eq!(query_value(token, "sr").as_deref(), Some("b"));
        assert_eq!(query_value(token, "spr").as_deref(), Some("https"));
        assert_eq!(
            query_value(token, "sig").as_deref(),
            Some("aoHQpVbSMBC3EY94Aw7g2XFUZxtqh48MWBZLxq32Q6g=")
        );
        assert!(!token.contains("source-bearer-secret"));
    }

    #[tokio::test]
    async fn normalizes_fractional_bounds_to_exact_wire_times() {
        let now = timestamp("2030-01-01T00:00:00.500Z");
        let key_start = timestamp("2030-01-01T00:00:00Z");
        let key_expiry = timestamp("2030-01-08T00:00:00Z");
        let http = MockUserDelegationHttpSend::new([delegation_key_response(
            key_start, key_expiry, "oid", "tid", "a2V5",
        )]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = UserDelegationSasGranter::new(
            "account",
            blob_grant("blob", UserDelegationSasPermissions::READ),
        )
        .with_time(now);
        let source = bearer("source");

        let output = operation
            .grant_credential(&ctx, &source, Some(MAX_USER_DELEGATION_LIFETIME))
            .await
            .expect("the exact seven-day bound must remain representable");
        let (token, expires_at) = output_parts(&output);
        assert_eq!(expires_at, key_expiry);
        assert_eq!(
            query_value(token, "se").as_deref(),
            Some("2030-01-08T00:00:00Z")
        );

        let output = operation
            .clone()
            .with_start(timestamp("2030-01-01T00:00:00.750Z"))
            .grant_credential(&ctx, &source, Some(Duration::from_millis(2_500)))
            .await
            .expect("fractional bounds must use the cached key");
        let (token, expires_at) = output_parts(&output);
        assert_eq!(expires_at, timestamp("2030-01-01T00:00:03Z"));
        assert_eq!(
            query_value(token, "st").as_deref(),
            Some("2030-01-01T00:00:01Z")
        );
        assert_eq!(
            query_value(token, "se").as_deref(),
            Some("2030-01-01T00:00:03Z")
        );

        let err = operation
            .grant_credential(&ctx, &source, Some(Duration::from_millis(400)))
            .await
            .expect_err("a lifetime without a future wire second must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            http.requests.lock().expect("lock poisoned")[0].body,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>2030-01-01T00:00:00Z</Start><Expiry>2030-01-08T00:00:00Z</Expiry></KeyInfo>"
        );
    }

    #[tokio::test]
    async fn core_granter_output_is_consumed_by_existing_signer() {
        let now = Timestamp::now();
        let http = MockUserDelegationHttpSend::new([delegation_key_response(
            now,
            now + MAX_USER_DELEGATION_LIFETIME,
            "oid",
            "tid",
            "a2V5",
        )]);
        let ctx = Context::new().with_http_send(http);
        let operation = UserDelegationSasGranter::new(
            "account",
            blob_grant("path/to/blob.txt", UserDelegationSasPermissions::READ),
        )
        .with_time(now);
        let granter = Granter::new(
            ctx,
            StaticCredentialProvider::new_bearer_token("source-token"),
            operation,
        );
        let output = granter
            .grant(Some(Duration::from_secs(300)))
            .await
            .expect("core granter must return a usable SAS credential");
        let (token, _) = output_parts(&output);
        let token = token.to_string();

        let signer = Signer::new(
            Context::new(),
            FixedCredentialProvider(output),
            RequestSigner::new(),
        );
        let mut parts = http::Request::get(
            "https://account.blob.core.windows.net/container/path/to/blob.txt?existing=%2F",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume granted credential");

        assert_eq!(
            parts.uri.to_string(),
            format!(
                "https://account.blob.core.windows.net/container/path/to/blob.txt?existing=%2F&{token}"
            )
        );
        assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
    }

    #[tokio::test]
    async fn rejects_non_bearer_source_variants_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockUserDelegationHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = UserDelegationSasGranter::new(
            "account",
            blob_grant("blob", UserDelegationSasPermissions::READ),
        )
        .with_time(now);

        for source in [
            Credential::with_shared_key("account", "a2V5"),
            Credential::with_sas_token("sv=2020-12-06&sig=secret"),
        ] {
            let err = operation
                .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("non-bearer source must be rejected");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validates_lifetime_and_post_io_expiration() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let key_expiry = now + MAX_USER_DELEGATION_LIFETIME;
        let http = MockUserDelegationHttpSend::new([delegation_key_response(
            now, key_expiry, "oid", "tid", "a2V5",
        )]);
        let ctx = Context::new().with_http_send(http.clone());
        let base = UserDelegationSasGranter::new(
            "account",
            blob_grant("blob", UserDelegationSasPermissions::READ),
        )
        .with_time(now);
        let source = bearer("source-secret");

        for lifetime in [
            None,
            Some(Duration::ZERO),
            Some(MAX_USER_DELEGATION_LIFETIME + Duration::from_secs(1)),
        ] {
            let err = base
                .grant_credential(&ctx, &source, lifetime)
                .await
                .expect_err("invalid lifetime must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);

        let err = base
            .clone()
            .with_start(now + Duration::from_secs(61))
            .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
            .await
            .expect_err("start at or after expiry must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);

        let err = base
            .clone()
            .with_start(now - Duration::from_secs(60))
            .grant_credential(&ctx, &source, Some(MAX_USER_DELEGATION_LIFETIME))
            .await
            .expect_err("SAS interval outside key lifetime must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);

        let slow = base.with_time_after_request(now + Duration::from_secs(300));
        let err = slow
            .grant_credential(&ctx, &source, Some(Duration::from_secs(300)))
            .await
            .expect_err("SAS expired during I/O must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert!(!format!("{err:?}").contains("source-secret"));
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shares_and_partitions_user_delegation_key_cache() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let key_expiry = now + MAX_USER_DELEGATION_LIFETIME;
        let response = || delegation_key_response(now, key_expiry, "oid", "tid", "a2V5");
        let http = MockUserDelegationHttpSend::new([response(), response(), response()]);
        let ctx = Context::new().with_http_send(http.clone());
        let first = UserDelegationSasGranter::new(
            "account",
            blob_grant("first", UserDelegationSasPermissions::READ),
        )
        .with_time(now);
        let second = first
            .clone()
            .with_grant(blob_grant("second", UserDelegationSasPermissions::WRITE));

        let first_output = first
            .grant_credential(&ctx, &bearer("source-a"), Some(Duration::from_secs(300)))
            .await
            .expect("first grant must fetch a key");
        let second_output = second
            .grant_credential(&ctx, &bearer("source-a"), Some(Duration::from_secs(300)))
            .await
            .expect("bound clone must share the key");
        assert_ne!(
            output_parts(&first_output).0,
            output_parts(&second_output).0
        );
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);

        second
            .grant_credential(&ctx, &bearer("source-b"), Some(Duration::from_secs(300)))
            .await
            .expect("different source authority must fetch a key");
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);

        second
            .with_trusted_endpoint("https://account.blob.core.windows.net:444")
            .grant_credential(&ctx, &bearer("source-a"), Some(Duration::from_secs(300)))
            .await
            .expect("different endpoint must fetch a key");
        assert_eq!(http.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn expires_user_delegation_key_cache_by_requested_interval() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let first_key_expiry = now + Duration::from_secs(600);
        let later = now + Duration::from_secs(400);
        let http = MockUserDelegationHttpSend::new([
            delegation_key_response(now, first_key_expiry, "oid", "tid", "a2V5"),
            delegation_key_response(
                later,
                later + MAX_USER_DELEGATION_LIFETIME,
                "oid",
                "tid",
                "a2V5",
            ),
        ]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation = UserDelegationSasGranter::new(
            "account",
            blob_grant("blob", UserDelegationSasPermissions::READ),
        )
        .with_time(now);

        operation
            .grant_credential(&ctx, &bearer("source"), Some(Duration::from_secs(300)))
            .await
            .expect("first key must cover short grant");
        operation
            .clone()
            .with_time(later)
            .grant_credential(&ctx, &bearer("source"), Some(Duration::from_secs(300)))
            .await
            .expect("insufficient cached key must be replaced");

        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn encodes_container_blob_and_path_prefix_bounds() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let key_expiry = now + MAX_USER_DELEGATION_LIFETIME;
        let response = || delegation_key_response(now, key_expiry, "oid", "tid", "a2V5");
        let http = MockUserDelegationHttpSend::new([response(), response(), response()]);
        let ctx = Context::new().with_http_send(http.clone());
        let source = bearer("source");

        let container = UserDelegationSasGranter::new(
            "account",
            UserDelegationSasGrant::for_container(
                "container",
                UserDelegationSasPermissions::LIST
                    | UserDelegationSasPermissions::READ
                    | UserDelegationSasPermissions::FILTER_BY_TAGS,
            ),
        )
        .with_time(now);
        let output = container
            .grant_credential(&ctx, &source, Some(Duration::from_secs(300)))
            .await
            .expect("container grant must succeed");
        let token = output_parts(&output).0;
        assert_eq!(query_value(token, "sr").as_deref(), Some("c"));
        assert_eq!(query_value(token, "sp").as_deref(), Some("rlf"));
        assert_eq!(query_value(token, "sdd"), None);

        let prefix = UserDelegationSasGranter::new(
            "account",
            UserDelegationSasGrant::for_path_prefix(
                "container",
                "dir name/part%2Fvalue",
                UserDelegationSasPermissions::LIST | UserDelegationSasPermissions::READ,
            ),
        )
        .with_time(now);
        let output = prefix
            .grant_credential(&ctx, &source, Some(Duration::from_secs(300)))
            .await
            .expect("path prefix grant must succeed");
        let token = output_parts(&output).0;
        assert_eq!(query_value(token, "sr").as_deref(), Some("d"));
        assert_eq!(query_value(token, "sdd").as_deref(), Some("2"));
        assert_eq!(query_value(token, "sp").as_deref(), Some("rl"));
        assert_eq!(
            query_value(token, "sig").as_deref(),
            Some("sD5AzbOySNQNewoyR+FPzp8mY4Q+PzxTbbZo7SCAR78=")
        );

        let blob = UserDelegationSasGranter::new(
            "account",
            blob_grant(
                "blob",
                UserDelegationSasPermissions::DELETE
                    | UserDelegationSasPermissions::READ
                    | UserDelegationSasPermissions::WRITE,
            ),
        )
        .with_protocol(SasProtocol::HttpsAndHttp)
        .with_time(now);
        let output = blob
            .grant_credential(&ctx, &source, Some(Duration::from_secs(300)))
            .await
            .expect("blob grant must succeed");
        let token = output_parts(&output).0;
        assert_eq!(query_value(token, "sr").as_deref(), Some("b"));
        assert_eq!(query_value(token, "sp").as_deref(), Some("rwd"));
        assert_eq!(query_value(token, "spr").as_deref(), Some("https,http"));
    }

    #[tokio::test]
    async fn rejects_scope_widening_and_invalid_permissions_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockUserDelegationHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let source = bearer("source");

        for prefix in ["", "/", "///", "/prefix", "prefix/", "a//b", ".", ".."] {
            let operation = UserDelegationSasGranter::new(
                "account",
                UserDelegationSasGrant::for_path_prefix(
                    "container",
                    prefix,
                    UserDelegationSasPermissions::READ,
                ),
            )
            .with_time(now);
            let err = operation
                .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("ambiguous prefix must fail closed");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        for grant in [
            UserDelegationSasGrant::for_blob(
                "container",
                "x".repeat(1025),
                UserDelegationSasPermissions::READ,
            ),
            UserDelegationSasGrant::for_path_prefix(
                "container",
                (0..62)
                    .map(|index| format!("segment-{index}"))
                    .collect::<Vec<_>>()
                    .join("/"),
                UserDelegationSasPermissions::READ,
            ),
        ] {
            let err = UserDelegationSasGranter::new("account", grant)
                .with_time(now)
                .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("out-of-range Azure resource name must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        let empty_permissions = UserDelegationSasGranter::new(
            "account",
            blob_grant("blob", UserDelegationSasPermissions::default()),
        )
        .with_time(now);
        assert_eq!(
            empty_permissions
                .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("empty permissions must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );

        let blob_filter = UserDelegationSasGranter::new(
            "account",
            blob_grant("blob", UserDelegationSasPermissions::FILTER_BY_TAGS),
        )
        .with_time(now);
        assert_eq!(
            blob_filter
                .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("blob filter-by-tags permission must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validates_account_endpoint_and_ip_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockUserDelegationHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let source = bearer("source");
        let grant = blob_grant("blob", UserDelegationSasPermissions::READ);

        for operation in [
            UserDelegationSasGranter::new("UPPER", grant.clone()),
            UserDelegationSasGranter::new("account", grant.clone())
                .with_trusted_endpoint("http://account.blob.core.windows.net"),
            UserDelegationSasGranter::new("account", grant.clone())
                .with_trusted_endpoint("https://other.blob.core.windows.net"),
            UserDelegationSasGranter::new("account", grant.clone())
                .with_trusted_endpoint("https://account.blob.core.windows.net/path"),
            UserDelegationSasGranter::new("account", grant.clone())
                .with_trusted_endpoint("https://account.blob.core.windows.net?x=1"),
            UserDelegationSasGranter::new("account", grant.clone()).with_ip("2001:db8::1"),
            UserDelegationSasGranter::new("account", grant).with_ip("192.0.2.2-192.0.2.1"),
        ] {
            let err = operation
                .with_time(now)
                .grant_credential(&ctx, &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("invalid authority configuration must fail");
            assert!(matches!(
                err.kind(),
                ErrorKind::ConfigInvalid | ErrorKind::RequestInvalid
            ));
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn debug_redacts_grant_policy_credentials_and_key_material() {
        let grant = UserDelegationSasGrant::for_path_prefix(
            "sensitive-container",
            "sensitive/path",
            UserDelegationSasPermissions::READ | UserDelegationSasPermissions::WRITE,
        );
        let operation = UserDelegationSasGranter::new("secretaccount", grant.clone());
        let credential =
            Credential::with_sas_token_expires_at("sv=secret&sig=secret", Timestamp::now());
        let key = UserDelegationKey {
            signed_oid: "sensitive-object-id".to_string(),
            signed_tid: "sensitive-tenant-id".to_string(),
            signed_start: Timestamp::now(),
            signed_expiry: Timestamp::now() + Duration::from_secs(60),
            signed_service: "b".to_string(),
            signed_version: USER_DELEGATION_SERVICE_VERSION.to_string(),
            value: "sensitive-signing-key".to_string(),
        };

        for (debug, secret) in [
            (format!("{grant:?}"), "sensitive-container"),
            (format!("{operation:?}"), "secretaccount"),
            (format!("{credential:?}"), "sv=secret&sig=secret"),
            (format!("{key:?}"), "sensitive-signing-key"),
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
