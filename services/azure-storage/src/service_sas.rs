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
use crate::user_delegation_sas::SasProtocol;
use percent_encoding::percent_encode;
use reqsign_core::hash;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::ops::{BitOr, BitOrAssign};
use std::time::Duration;

const SERVICE_SAS_VERSION: &str = "2020-12-06";
const BLOB_SERVICE: &str = "blob";
const STORAGE_ACCOUNT_KEY_LENGTH: usize = 64;
const SUPPORTED_SERVICE_SAS_VERSIONS: &[&str] = &[
    "2020-12-06",
    "2021-02-12",
    "2021-04-10",
    "2021-06-08",
    "2021-08-06",
    "2021-10-04",
    "2021-12-02",
    "2022-11-02",
    "2023-01-03",
    "2023-05-03",
    "2023-08-03",
    "2023-11-03",
    "2024-02-04",
    "2024-05-04",
    "2024-08-04",
    "2024-11-04",
    "2025-01-05",
    "2025-05-05",
    "2025-07-05",
    "2025-11-05",
    "2026-02-06",
    "2026-04-06",
    "2026-06-06",
    "2026-10-06",
];

/// Resource level for Azure Blob Storage Service SAS.
#[derive(Clone, PartialEq, Eq)]
pub enum ServiceSasResource {
    /// A container resource.
    Container { container: String },
    /// A blob resource.
    Blob { container: String, blob: String },
}

impl Debug for ServiceSasResource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceSasResource(REDACTED)")
    }
}

impl ServiceSasResource {
    /// Build a resource from a request path.
    ///
    /// The input path must be percent-decoded.
    pub fn from_path_percent_decoded(path: &str) -> Result<Self> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let mut segments = path.split('/').filter(|v| !v.is_empty());

        let container = segments
            .next()
            .ok_or_else(|| Error::request_invalid("missing container in path"))?
            .to_string();

        let rest = segments.collect::<Vec<_>>();
        if rest.is_empty() {
            Ok(ServiceSasResource::Container { container })
        } else {
            Ok(ServiceSasResource::Blob {
                container,
                blob: rest.join("/"),
            })
        }
    }

    pub(crate) fn signed_resource(&self) -> &'static str {
        match self {
            ServiceSasResource::Container { .. } => "c",
            ServiceSasResource::Blob { .. } => "b",
        }
    }

    pub(crate) fn canonicalized_resource(&self, account: &str) -> String {
        match self {
            ServiceSasResource::Container { container } => {
                format!("/{BLOB_SERVICE}/{account}/{container}")
            }
            ServiceSasResource::Blob { container, blob } => {
                format!("/{BLOB_SERVICE}/{account}/{container}/{blob}")
            }
        }
    }
}

/// Permissions for a container-scoped Blob Storage Service SAS.
///
/// Combining values with `|` produces Azure's canonical permission order.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceSasContainerPermissions(u16);

impl ServiceSasContainerPermissions {
    /// Read blobs in the container.
    pub const READ: Self = Self(1 << 0);
    /// Add blocks to append blobs.
    pub const ADD: Self = Self(1 << 1);
    /// Create blobs.
    pub const CREATE: Self = Self(1 << 2);
    /// Write blob data and metadata.
    pub const WRITE: Self = Self(1 << 3);
    /// Delete blobs.
    pub const DELETE: Self = Self(1 << 4);
    /// Delete blob versions.
    pub const DELETE_VERSION: Self = Self(1 << 5);
    /// Permanently delete blob snapshots or versions.
    pub const PERMANENT_DELETE: Self = Self(1 << 6);
    /// List blobs.
    pub const LIST: Self = Self(1 << 7);
    /// Read or write blob index tags.
    pub const TAGS: Self = Self(1 << 8);
    /// Find blobs by index tags.
    pub const FILTER_BY_TAGS: Self = Self(1 << 9);
    /// Move blobs in hierarchical-namespace accounts.
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

impl Debug for ServiceSasContainerPermissions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceSasContainerPermissions(REDACTED)")
    }
}

impl BitOr for ServiceSasContainerPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ServiceSasContainerPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Permissions for a blob-scoped Blob Storage Service SAS.
///
/// Combining values with `|` produces Azure's canonical permission order.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceSasBlobPermissions(u16);

impl ServiceSasBlobPermissions {
    /// Read the blob.
    pub const READ: Self = Self(1 << 0);
    /// Add blocks to an append blob.
    pub const ADD: Self = Self(1 << 1);
    /// Create the blob.
    pub const CREATE: Self = Self(1 << 2);
    /// Write blob data and metadata.
    pub const WRITE: Self = Self(1 << 3);
    /// Delete the blob.
    pub const DELETE: Self = Self(1 << 4);
    /// Delete a blob version.
    pub const DELETE_VERSION: Self = Self(1 << 5);
    /// Permanently delete a blob snapshot or version.
    pub const PERMANENT_DELETE: Self = Self(1 << 6);
    /// Read or write blob index tags.
    pub const TAGS: Self = Self(1 << 7);
    /// Move the blob in hierarchical-namespace accounts.
    pub const MOVE: Self = Self(1 << 8);
    /// Read system properties or POSIX ACLs.
    pub const EXECUTE: Self = Self(1 << 9);
    /// Set the owner or owning group for hierarchical namespace resources.
    pub const OWNERSHIP: Self = Self(1 << 10);
    /// Set POSIX permissions or ACLs for hierarchical namespace resources.
    pub const PERMISSIONS: Self = Self(1 << 11);
    /// Set an immutability policy or legal hold.
    pub const SET_IMMUTABILITY_POLICY: Self = Self(1 << 12);

    /// Return whether no permission is selected.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return whether all permissions in `other` are selected.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
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
            (Self::TAGS, 't'),
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

impl Debug for ServiceSasBlobPermissions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceSasBlobPermissions(REDACTED)")
    }
}

impl BitOr for ServiceSasBlobPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ServiceSasBlobPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone)]
enum ServiceSasGrantResource {
    Container {
        container: String,
        permissions: ServiceSasContainerPermissions,
    },
    Blob {
        container: String,
        blob: String,
        permissions: ServiceSasBlobPermissions,
    },
}

/// One complete, typed Blob Storage Service SAS grant.
#[derive(Clone)]
pub struct ServiceSasGrant {
    resource: ServiceSasGrantResource,
}

impl Debug for ServiceSasGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasGrant").finish_non_exhaustive()
    }
}

impl ServiceSasGrant {
    /// Grant permissions over one container and its blobs.
    pub fn for_container(
        container: impl Into<String>,
        permissions: ServiceSasContainerPermissions,
    ) -> Self {
        Self {
            resource: ServiceSasGrantResource::Container {
                container: container.into(),
                permissions,
            },
        }
    }

    /// Grant permissions over one exact blob.
    pub fn for_blob(
        container: impl Into<String>,
        blob: impl Into<String>,
        permissions: ServiceSasBlobPermissions,
    ) -> Self {
        Self {
            resource: ServiceSasGrantResource::Blob {
                container: container.into(),
                blob: blob.into(),
                permissions,
            },
        }
    }

    fn validate(&self) -> Result<ValidatedGrant> {
        match &self.resource {
            ServiceSasGrantResource::Container {
                container,
                permissions,
            } => {
                validate_container(container)?;
                if permissions.is_empty() {
                    return Err(Error::request_invalid(
                        "Azure Service SAS container permissions must not be empty",
                    ));
                }
                Ok(ValidatedGrant {
                    resource: ServiceSasResource::Container {
                        container: container.clone(),
                    },
                    permissions: permissions.as_canonical_string(),
                })
            }
            ServiceSasGrantResource::Blob {
                container,
                blob,
                permissions,
            } => {
                validate_container(container)?;
                validate_blob(blob)?;
                if permissions.is_empty() {
                    return Err(Error::request_invalid(
                        "Azure Service SAS blob permissions must not be empty",
                    ));
                }
                Ok(ValidatedGrant {
                    resource: ServiceSasResource::Blob {
                        container: container.clone(),
                        blob: blob.clone(),
                    },
                    permissions: permissions.as_canonical_string(),
                })
            }
        }
    }
}

struct ValidatedGrant {
    resource: ServiceSasResource,
    permissions: String,
}

impl Debug for ValidatedGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedGrant").finish_non_exhaustive()
    }
}

/// One IPv4 address or inclusive IPv4 range for an Azure SAS.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SasIpRange {
    start: Ipv4Addr,
    end: Option<Ipv4Addr>,
}

impl SasIpRange {
    /// Restrict requests to one IPv4 address.
    pub const fn address(address: Ipv4Addr) -> Self {
        Self {
            start: address,
            end: None,
        }
    }

    /// Restrict requests to an inclusive IPv4 range.
    pub fn range(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self> {
        if u32::from(start) > u32::from(end) {
            return Err(Error::request_invalid(
                "SAS IPv4 range start must not exceed its end",
            ));
        }
        Ok(Self {
            start,
            end: Some(end),
        })
    }

    fn as_string(self) -> String {
        self.end.map_or_else(
            || self.start.to_string(),
            |end| format!("{}-{end}", self.start),
        )
    }
}

impl From<Ipv4Addr> for SasIpRange {
    fn from(value: Ipv4Addr) -> Self {
        Self::address(value)
    }
}

impl Debug for SasIpRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SasIpRange(REDACTED)")
    }
}

/// Azure Storage service version used to authorize a Service SAS.
///
/// This type accepts documented Azure Storage versions from `2020-12-06`
/// onward, whose Blob Storage Service SAS string-to-sign includes the signed
/// encryption-scope field. Unknown future versions are rejected until their
/// wire contract is understood by this crate.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceSasVersion(String);

impl ServiceSasVersion {
    /// Validate and create a supported Azure Storage service version.
    pub fn new(version: impl Into<String>) -> Result<Self> {
        let version = version.into();
        if !SUPPORTED_SERVICE_SAS_VERSIONS.contains(&version.as_str()) {
            return Err(Error::config_invalid(
                "Azure Service SAS version is not supported by this signer",
            ));
        }
        Ok(Self(version))
    }

    /// Return the service version in Azure wire format.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ServiceSasVersion {
    fn default() -> Self {
        Self(SERVICE_SAS_VERSION.to_string())
    }
}

impl Debug for ServiceSasVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ServiceSasVersion").field(&self.0).finish()
    }
}

/// Stable configuration for locally generating one Blob Storage Service SAS.
#[derive(Clone)]
pub struct ServiceSasConfig {
    account: String,
    start: Option<Timestamp>,
    ip: Option<SasIpRange>,
    protocol: SasProtocol,
    version: ServiceSasVersion,
}

impl Debug for ServiceSasConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasConfig").finish_non_exhaustive()
    }
}

impl ServiceSasConfig {
    /// Create configuration bound to one Azure storage account.
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            start: None,
            ip: None,
            protocol: SasProtocol::Https,
            version: ServiceSasVersion::default(),
        }
    }

    /// Set an optional SAS start time.
    ///
    /// The rounded wire value must not be later than the time of granting,
    /// because the returned credential must be immediately usable.
    pub fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    /// Restrict the SAS to an IPv4 address or inclusive range.
    pub fn with_ip(mut self, ip: SasIpRange) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the protocol restriction embedded in the SAS.
    pub fn with_protocol(mut self, protocol: SasProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the Azure Storage service version embedded in the SAS.
    pub fn with_version(mut self, version: ServiceSasVersion) -> Self {
        self.version = version;
        self
    }

    fn validate(&self) -> Result<ValidatedConfig> {
        validate_account(&self.account)?;
        Ok(ValidatedConfig {
            account: self.account.clone(),
            start: self.start,
            ip: self.ip.map(SasIpRange::as_string),
            protocol: self.protocol,
            version: self.version.clone(),
        })
    }
}

struct ValidatedConfig {
    account: String,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: SasProtocol,
    version: ServiceSasVersion,
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
        || blob
            .chars()
            .any(|value| value.is_control() || value == '\\')
    {
        return Err(Error::request_invalid(
            "blob name must be a non-empty percent-decoded name without control characters or backslashes",
        ));
    }
    Ok(())
}

/// Service SAS generator using Shared Key.
///
/// Reference: <https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas>
pub struct ServiceSharedAccessSignature {
    account: String,
    key: String,

    resource: ServiceSasResource,
    permissions: String,
    expiry: Timestamp,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: Option<String>,
    version: String,
}

impl ServiceSharedAccessSignature {
    /// Create a Service SAS signer.
    pub fn new(
        account: String,
        key: String,
        resource: ServiceSasResource,
        permissions: String,
        expiry: Timestamp,
    ) -> Self {
        Self {
            account,
            key,
            resource,
            permissions,
            expiry,
            start: None,
            ip: None,
            protocol: None,
            version: SERVICE_SAS_VERSION.to_string(),
        }
    }

    /// Set the start time.
    pub fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    /// Set the IP restriction.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Set the allowed protocol.
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Set the service version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    fn string_to_sign(&self) -> String {
        [
            self.permissions.clone(),
            self.start
                .map_or_else(String::new, Timestamp::format_rfc3339_zulu),
            self.expiry.format_rfc3339_zulu(),
            self.resource.canonicalized_resource(&self.account),
            String::new(), // signed identifier
            self.ip.clone().unwrap_or_default(),
            self.protocol.clone().unwrap_or_default(),
            self.version.clone(),
            self.resource.signed_resource().to_string(),
            String::new(), // snapshot time
            String::new(), // encryption scope
            String::new(), // rscc
            String::new(), // rscd
            String::new(), // rsce
            String::new(), // rscl
            String::new(), // rsct
        ]
        .join("\n")
    }

    fn signature_with_decoded_key(&self, decoded_key: &[u8]) -> String {
        hash::base64_hmac_sha256(decoded_key, self.string_to_sign().as_bytes())
    }

    fn token_with_decoded_key(&self, decoded_key: &[u8]) -> Vec<(String, String)> {
        let mut elements: Vec<(String, String)> = vec![
            ("sv".to_string(), self.version.to_string()),
            ("se".to_string(), self.expiry.format_rfc3339_zulu()),
            ("sp".to_string(), self.permissions.to_string()),
            (
                "sr".to_string(),
                self.resource.signed_resource().to_string(),
            ),
        ];

        if let Some(start) = &self.start {
            elements.push(("st".to_string(), start.format_rfc3339_zulu()))
        }
        if let Some(ip) = &self.ip {
            elements.push(("sip".to_string(), ip.to_string()))
        }
        if let Some(protocol) = &self.protocol {
            elements.push(("spr".to_string(), protocol.to_string()))
        }

        elements.push((
            "sig".to_string(),
            self.signature_with_decoded_key(decoded_key),
        ));

        elements
    }

    /// Generate SAS query parameters.
    pub fn token(&self) -> Result<Vec<(String, String)>> {
        let decoded_key = hash::base64_decode(&self.key)?;
        Ok(self.token_with_decoded_key(&decoded_key))
    }
}

pub(crate) fn encode_query_pairs(pairs: &[(String, String)]) -> String {
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

struct OperationTimes {
    now: Timestamp,
    start: Option<Timestamp>,
    expiry: Timestamp,
}

/// Grants expiration-aware Azure Blob Storage Service SAS credentials.
///
/// The source credential must be [`Credential::SharedKey`] for exactly the
/// account bound in [`ServiceSasConfig`], with a Base64-encoded 512-bit Azure
/// account key. Service SAS generation is local and performs no network I/O.
/// `expires_in` must be explicit and non-zero. Azure wire timestamps have
/// whole-second precision: explicit start times are rounded forward,
/// expirations are rounded backward, and the returned credential expiration
/// exactly matches the signed `se` value.
#[derive(Clone)]
pub struct ServiceSasGranter {
    config: ServiceSasConfig,
    grant: ServiceSasGrant,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    time_after_generation: Option<Timestamp>,
}

impl Debug for ServiceSasGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasGranter").finish_non_exhaustive()
    }
}

impl ServiceSasGranter {
    /// Create a granter for a bound account configuration and typed grant.
    pub fn new(config: ServiceSasConfig, grant: ServiceSasGrant) -> Self {
        Self {
            config,
            grant,
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            time_after_generation: None,
        }
    }

    /// Replace the bound resource and permission grant.
    pub fn with_grant(mut self, grant: ServiceSasGrant) -> Self {
        self.grant = grant;
        self
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    #[cfg(test)]
    fn with_time_after_generation(mut self, time: Timestamp) -> Self {
        self.time_after_generation = Some(time);
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn now_after_generation(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time_after_generation {
            return time;
        }
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn operation_times(
        &self,
        start: Option<Timestamp>,
        expires_in: Option<Duration>,
    ) -> Result<OperationTimes> {
        let expires_in = expires_in.ok_or_else(|| {
            Error::request_invalid("Azure Service SAS requires an explicit lifetime")
        })?;
        if expires_in.is_zero() {
            return Err(Error::request_invalid(
                "Azure Service SAS lifetime must be greater than zero",
            ));
        }

        let now = self.now();
        let expiry = expiry_at_wire_second(now, expires_in)?;
        if expiry <= now {
            return Err(Error::request_invalid(
                "Azure Service SAS lifetime does not reach a future wire timestamp",
            ));
        }
        let start = start.map(ceil_to_wire_second).transpose()?;
        if start.is_some_and(|start| start > now) {
            return Err(Error::request_invalid(
                "Azure Service SAS start time must not be in the future",
            ));
        }
        if start.is_some_and(|start| start >= expiry) {
            return Err(Error::request_invalid(
                "Azure Service SAS start time must be before its expiration",
            ));
        }

        Ok(OperationTimes { now, start, expiry })
    }
}

impl GrantCredential for ServiceSasGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now()
    }

    async fn grant_credential(
        &self,
        _ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let Credential::SharedKey {
            account_name,
            account_key,
        } = credential
        else {
            return Err(Error::credential_invalid(
                "Azure Service SAS requires a Shared Key source credential",
            ));
        };

        let config = self.config.validate()?;
        if account_name != &config.account {
            return Err(Error::credential_invalid(
                "Azure Shared Key source account does not match the Service SAS account",
            ));
        }
        if account_key.is_empty() {
            return Err(Error::credential_invalid(
                "Azure Service SAS source account key is missing",
            ));
        }
        let decoded_key = hash::base64_decode(account_key).map_err(|_| {
            Error::credential_invalid("Azure Service SAS source account key is invalid")
        })?;
        if decoded_key.len() != STORAGE_ACCOUNT_KEY_LENGTH {
            return Err(Error::credential_invalid(
                "Azure Service SAS source account key is invalid",
            ));
        }

        let grant = self.grant.validate()?;
        let times = self.operation_times(config.start, expires_in)?;
        if !credential.is_valid_at(times.now) {
            return Err(Error::credential_invalid(
                "Azure Service SAS source credential is not currently usable",
            ));
        }

        let mut signer = ServiceSharedAccessSignature::new(
            config.account,
            String::new(),
            grant.resource,
            grant.permissions,
            times.expiry,
        )
        .with_protocol(config.protocol.as_str())
        .with_version(config.version.as_str());
        if let Some(start) = times.start {
            signer = signer.with_start(start);
        }
        if let Some(ip) = config.ip {
            signer = signer.with_ip(ip);
        }

        let pairs = signer.token_with_decoded_key(&decoded_key);
        let token = encode_query_pairs(&pairs);
        let after_generation = self.now_after_generation();
        if times.expiry <= after_generation {
            return Err(Error::request_invalid(
                "Azure Service SAS expired before granting completed",
            ));
        }

        let output = Credential::with_sas_token_expires_at(&token, times.expiry);
        if !output.is_valid_at(after_generation) {
            return Err(Error::credential_invalid(
                "granted Azure Service SAS is not currently usable",
            ));
        }
        Ok(output)
    }
}

fn expiry_at_wire_second(now: Timestamp, expires_in: Duration) -> Result<Timestamp> {
    let duration_seconds = i64::try_from(expires_in.as_secs()).map_err(|_| {
        Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
    })?;
    let fractional = i64::from(now.subsec_nanosecond())
        .checked_add(i64::from(expires_in.subsec_nanos()))
        .ok_or_else(|| {
            Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
        })?;
    let carry = fractional.div_euclid(1_000_000_000);
    let expiry_second = now
        .as_second()
        .checked_add(duration_seconds)
        .and_then(|value| value.checked_add(carry))
        .ok_or_else(|| {
            Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
        })?;
    Timestamp::from_second(expiry_second).map_err(|_| {
        Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
    })
}

fn ceil_to_wire_second(timestamp: Timestamp) -> Result<Timestamp> {
    let mut second = timestamp.as_second();
    if timestamp.subsec_nanosecond() > 0 {
        second = second.checked_add(1).ok_or_else(|| {
            Error::request_invalid("Azure Service SAS timestamp exceeds the wire time range")
        })?;
    }
    Timestamp::from_second(second).map_err(|_| {
        Error::request_invalid("Azure Service SAS timestamp exceeds the wire time range")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RequestSigner, StaticCredentialProvider};
    use reqsign_core::{ErrorKind, Granter, SignRequest, Signer};
    use std::str::FromStr;

    const VALID_ACCOUNT_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_time() -> Timestamp {
        Timestamp::from_str("2022-03-01T08:12:34Z").unwrap()
    }

    #[test]
    fn test_can_generate_service_sas_token_for_blob() {
        let key = hash::base64_encode("key".as_bytes());
        let expiry = test_time() + Duration::from_secs(300);

        let resource = ServiceSasResource::Blob {
            container: "container".to_string(),
            blob: "path/to/blob.txt".to_string(),
        };

        let sign = ServiceSharedAccessSignature::new(
            "account".to_string(),
            key,
            resource,
            "r".to_string(),
            expiry,
        );

        let token_content = sign.token().expect("token generation failed");
        let token = token_content
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
            .join("&");

        assert_eq!(
            token,
            "sv=2020-12-06&se=2022-03-01T08:17:34Z&sp=r&sr=b&sig=CP9a2LIrR9zeG4I4jZjqPetJSXWJ77QeUA7c3GMypyM="
        );
    }

    #[test]
    fn test_service_sas_resource_from_path() {
        assert_eq!(
            ServiceSasResource::from_path_percent_decoded("/container").unwrap(),
            ServiceSasResource::Container {
                container: "container".to_string()
            }
        );

        assert_eq!(
            ServiceSasResource::from_path_percent_decoded("/container/blob").unwrap(),
            ServiceSasResource::Blob {
                container: "container".to_string(),
                blob: "blob".to_string()
            }
        );
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must parse")
    }

    fn shared_key(account: &str, decoded_key: &str) -> Credential {
        Credential::with_shared_key(account, &hash::base64_encode(decoded_key.as_bytes()))
    }

    fn output_parts(credential: &Credential) -> (&str, Timestamp) {
        match credential {
            Credential::SasToken {
                token,
                expires_at: Some(expires_at),
            } => (token, *expires_at),
            other => panic!("expected expiring SAS credential, got {other:?}"),
        }
    }

    fn query_value(token: &str, key: &str) -> Option<String> {
        form_urlencoded::parse(token.as_bytes())
            .find_map(|(candidate, value)| (candidate == key).then(|| value.into_owned()))
    }

    #[test]
    fn typed_permissions_use_resource_specific_canonical_order() {
        let container_permissions = ServiceSasContainerPermissions::READ
            | ServiceSasContainerPermissions::ADD
            | ServiceSasContainerPermissions::CREATE
            | ServiceSasContainerPermissions::WRITE
            | ServiceSasContainerPermissions::DELETE
            | ServiceSasContainerPermissions::DELETE_VERSION
            | ServiceSasContainerPermissions::PERMANENT_DELETE
            | ServiceSasContainerPermissions::LIST
            | ServiceSasContainerPermissions::TAGS
            | ServiceSasContainerPermissions::FILTER_BY_TAGS
            | ServiceSasContainerPermissions::MOVE
            | ServiceSasContainerPermissions::EXECUTE
            | ServiceSasContainerPermissions::OWNERSHIP
            | ServiceSasContainerPermissions::PERMISSIONS
            | ServiceSasContainerPermissions::SET_IMMUTABILITY_POLICY;
        let container = ServiceSasGrant::for_container("container", container_permissions)
            .validate()
            .expect("container grant must be valid");
        assert_eq!(container.permissions, "racwdxyltfmeopi");
        assert!(container_permissions.contains(ServiceSasContainerPermissions::LIST));
        assert!(container_permissions.contains(ServiceSasContainerPermissions::OWNERSHIP));
        assert!(container_permissions.contains(ServiceSasContainerPermissions::PERMISSIONS));

        let blob_permissions = ServiceSasBlobPermissions::READ
            | ServiceSasBlobPermissions::ADD
            | ServiceSasBlobPermissions::CREATE
            | ServiceSasBlobPermissions::WRITE
            | ServiceSasBlobPermissions::DELETE
            | ServiceSasBlobPermissions::DELETE_VERSION
            | ServiceSasBlobPermissions::PERMANENT_DELETE
            | ServiceSasBlobPermissions::TAGS
            | ServiceSasBlobPermissions::MOVE
            | ServiceSasBlobPermissions::EXECUTE
            | ServiceSasBlobPermissions::OWNERSHIP
            | ServiceSasBlobPermissions::PERMISSIONS
            | ServiceSasBlobPermissions::SET_IMMUTABILITY_POLICY;
        let blob = ServiceSasGrant::for_blob("container", "blob", blob_permissions)
            .validate()
            .expect("blob grant must be valid");
        assert_eq!(blob.permissions, "racwdxytmeopi");
        assert!(blob_permissions.contains(ServiceSasBlobPermissions::TAGS));
        assert!(blob_permissions.contains(ServiceSasBlobPermissions::OWNERSHIP));
        assert!(blob_permissions.contains(ServiceSasBlobPermissions::PERMISSIONS));
    }

    #[test]
    fn validates_complete_grants_versions_and_ip_ranges() {
        for grant in [
            ServiceSasGrant::for_container("container", ServiceSasContainerPermissions::default()),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::default()),
            ServiceSasGrant::for_container("UPPER", ServiceSasContainerPermissions::READ),
            ServiceSasGrant::for_blob("container", "", ServiceSasBlobPermissions::READ),
        ] {
            assert_eq!(
                grant
                    .validate()
                    .expect_err("invalid grant must fail")
                    .kind(),
                ErrorKind::RequestInvalid
            );
        }

        for version in [
            "2020-12-05",
            "2022-10-02",
            "2022-13-40",
            "2022-1-01",
            "9999-01-01",
            "future",
        ] {
            assert_eq!(
                ServiceSasVersion::new(version)
                    .expect_err("unsupported version must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }
        for version in ["2020-12-06", "2022-11-02", "2026-04-06"] {
            assert_eq!(
                ServiceSasVersion::new(version)
                    .expect("documented version must be accepted")
                    .as_str(),
                version
            );
        }

        let start = Ipv4Addr::new(198, 51, 100, 20);
        let end = Ipv4Addr::new(198, 51, 100, 10);
        assert_eq!(
            SasIpRange::range(start, end)
                .expect_err("reversed range must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );
    }

    #[tokio::test]
    async fn grants_leading_slash_blob_with_hierarchical_namespace_permissions() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob(
                "container",
                "/a",
                ServiceSasBlobPermissions::OWNERSHIP | ServiceSasBlobPermissions::PERMISSIONS,
            ),
        )
        .with_time(now);

        let output = operation
            .grant_credential(
                &Context::new(),
                &shared_key("account", VALID_ACCOUNT_KEY),
                Some(Duration::from_secs(60)),
            )
            .await
            .expect("leading-slash blob grant must be valid");
        let (token, expires_at) = output_parts(&output);

        assert_eq!(expires_at, timestamp("2030-01-01T00:01:00Z"));
        assert_eq!(
            token,
            "sv=2020-12-06&se=2030-01-01T00%3A01%3A00Z&sp=op&sr=b&spr=https&sig=fp21tjpRyr%2BTLkc5wZgehHGIbXj04QeiXTppdexgr6I%3D"
        );

        let signer = Signer::new(
            Context::new(),
            StaticCredentialProvider::new_sas_token_expires_at(token, expires_at),
            RequestSigner::new(),
        );
        let mut parts = http::Request::get("https://account.blob.core.windows.net/container//a")
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume the leading-slash blob SAS");
        assert_eq!(
            parts.uri.to_string(),
            format!("https://account.blob.core.windows.net/container//a?{token}")
        );
    }

    #[tokio::test]
    async fn grants_independently_computed_wire_vector() {
        let now = timestamp("2030-01-01T00:00:01.500Z");
        let start = timestamp("2030-01-01T00:00:00.750Z");
        let expiry = timestamp("2030-01-01T00:00:03Z");
        let ip = SasIpRange::range(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 20),
        )
        .expect("range must be ordered");
        let version = ServiceSasVersion::new("2022-11-02").expect("service version must be valid");
        let config = ServiceSasConfig::new("account")
            .with_start(start)
            .with_ip(ip)
            .with_protocol(SasProtocol::HttpsAndHttp)
            .with_version(version);
        let grant = ServiceSasGrant::for_blob(
            "container",
            "path/to/blob name.txt",
            ServiceSasBlobPermissions::WRITE | ServiceSasBlobPermissions::READ,
        );
        let operation = ServiceSasGranter::new(config, grant).with_time(now);
        let source = shared_key("account", VALID_ACCOUNT_KEY);

        let output = operation
            .grant_credential(&Context::new(), &source, Some(Duration::from_millis(1_500)))
            .await
            .expect("Service SAS grant must succeed");
        let (token, expires_at) = output_parts(&output);

        assert_eq!(expires_at, expiry);
        assert_eq!(
            token,
            "sv=2022-11-02&se=2030-01-01T00%3A00%3A03Z&sp=rw&sr=b&st=2030-01-01T00%3A00%3A01Z&sip=198.51.100.10-198.51.100.20&spr=https%2Chttp&sig=57MGNuddYiw/hojfFxQkcz1qgFd8klPpi31BmqTAb28%3D"
        );
        assert_eq!(
            query_value(token, "sig").as_deref(),
            Some("57MGNuddYiw/hojfFxQkcz1qgFd8klPpi31BmqTAb28=")
        );
        assert!(!token.contains(VALID_ACCOUNT_KEY));

        let direct = ServiceSharedAccessSignature::new(
            "account".to_string(),
            hash::base64_encode(VALID_ACCOUNT_KEY.as_bytes()),
            ServiceSasResource::Blob {
                container: "container".to_string(),
                blob: "path/to/blob name.txt".to_string(),
            },
            "rw".to_string(),
            expiry,
        )
        .with_start(timestamp("2030-01-01T00:00:01Z"))
        .with_ip("198.51.100.10-198.51.100.20")
        .with_protocol("https,http")
        .with_version("2022-11-02");
        assert_eq!(
            direct.string_to_sign(),
            "rw\n2030-01-01T00:00:01Z\n2030-01-01T00:00:03Z\n/blob/account/container/path/to/blob name.txt\n\n198.51.100.10-198.51.100.20\nhttps,http\n2022-11-02\nb\n\n\n\n\n\n\n"
        );
        assert_eq!(
            encode_query_pairs(&direct.token().expect("compatibility signer must succeed")),
            token
        );
    }

    #[tokio::test]
    async fn grants_typed_container_permissions_and_encodes_signature() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_container(
                "container",
                ServiceSasContainerPermissions::LIST | ServiceSasContainerPermissions::READ,
            ),
        )
        .with_time(now);

        let output = operation
            .grant_credential(
                &Context::new(),
                &shared_key("account", VALID_ACCOUNT_KEY),
                Some(Duration::from_secs(60)),
            )
            .await
            .expect("container Service SAS grant must succeed");
        let (token, expires_at) = output_parts(&output);

        assert_eq!(expires_at, timestamp("2030-01-01T00:01:00Z"));
        assert_eq!(
            token,
            "sv=2020-12-06&se=2030-01-01T00%3A01%3A00Z&sp=rl&sr=c&spr=https&sig=BInNJ1Os6PeLCwLFrQzDgvuM0ZGsYFuIzWyD/%2BzONkk%3D"
        );
    }

    #[tokio::test]
    async fn rejects_source_variants_account_mismatch_and_invalid_key() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);

        let invalid_sources = [
            Credential::with_bearer_token("bearer-secret", None),
            Credential::with_sas_token("sv=secret&sig=sas-secret"),
            shared_key("differentaccount", VALID_ACCOUNT_KEY),
            Credential::with_shared_key("account", "invalid-key-secret%%%"),
            Credential::with_shared_key("account", &hash::base64_encode(b"short-key")),
            Credential::with_shared_key("account", ""),
        ];
        for source in invalid_sources {
            let err = operation
                .grant_credential(&Context::new(), &source, Some(Duration::from_secs(60)))
                .await
                .expect_err("invalid source must fail");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            let debug = format!("{err:?}");
            for secret in [
                "bearer-secret",
                "sas-secret",
                "differentaccount",
                VALID_ACCOUNT_KEY,
                "invalid-key-secret",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn validates_lifetime_deadline_and_post_generation_usability() {
        let now = timestamp("2030-01-01T00:00:00.500Z");
        let source = shared_key("account", VALID_ACCOUNT_KEY);
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);

        assert_eq!(operation.required_valid_until(&source, None), now);
        for lifetime in [
            None,
            Some(Duration::ZERO),
            Some(Duration::from_millis(400)),
            Some(Duration::from_secs(u64::MAX)),
        ] {
            let err = operation
                .grant_credential(&Context::new(), &source, lifetime)
                .await
                .expect_err("invalid lifetime must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        let start_after_expiry = ServiceSasGranter::new(
            ServiceSasConfig::new("account").with_start(timestamp("2030-01-01T00:01:01Z")),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);
        assert_eq!(
            start_after_expiry
                .grant_credential(&Context::new(), &source, Some(Duration::from_secs(60)),)
                .await
                .expect_err("start at or after expiry must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );

        let future_start = ServiceSasGranter::new(
            ServiceSasConfig::new("account").with_start(timestamp("2030-01-01T00:00:01Z")),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);
        assert_eq!(
            future_start
                .grant_credential(&Context::new(), &source, Some(Duration::from_secs(60)),)
                .await
                .expect_err("future start must fail the immediate usability contract")
                .kind(),
            ErrorKind::RequestInvalid
        );

        let expired_after_generation =
            operation.with_time_after_generation(timestamp("2030-01-01T00:05:00Z"));
        assert_eq!(
            expired_after_generation
                .grant_credential(&Context::new(), &source, Some(Duration::from_secs(300)),)
                .await
                .expect_err("expired post-generation output must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );
    }

    #[tokio::test]
    async fn core_granter_output_matches_presign_and_is_consumed_by_signer() {
        let now = Timestamp::now();
        let key = hash::base64_encode(VALID_ACCOUNT_KEY.as_bytes());
        let source = Credential::with_shared_key("account", &key);
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob(
                "container",
                "path/to/blob.txt",
                ServiceSasBlobPermissions::READ,
            ),
        )
        .with_time(now);
        let output = Granter::new(
            Context::new(),
            StaticCredentialProvider::new_shared_key("account", &key),
            operation,
        )
        .grant(Some(Duration::from_secs(300)))
        .await
        .expect("core granter must return a usable SAS credential");
        let (token, expires_at) = output_parts(&output);
        let token = token.to_string();

        let signer = Signer::new(
            Context::new(),
            StaticCredentialProvider::new_sas_token_expires_at(&token, expires_at),
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

        let mut presigned =
            http::Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        RequestSigner::new()
            .with_time(now)
            .with_service_sas_permissions("r")
            .with_service_sas_protocol("https")
            .sign_request(
                &Context::new(),
                &mut presigned,
                Some(&source),
                Some(Duration::from_secs(300)),
            )
            .await
            .expect("compatibility presign must succeed");
        assert_eq!(
            presigned.uri.to_string(),
            format!("https://account.blob.core.windows.net/container/path/to/blob.txt?{token}")
        );
    }

    #[tokio::test]
    async fn debug_and_errors_redact_grant_and_credential_material() {
        let ip = SasIpRange::address(Ipv4Addr::new(198, 51, 100, 77));
        let config = ServiceSasConfig::new("sensitiveaccount").with_ip(ip);
        let grant = ServiceSasGrant::for_blob(
            "sensitive-container",
            "sensitive/path/blob.txt",
            ServiceSasBlobPermissions::READ | ServiceSasBlobPermissions::WRITE,
        );
        let operation = ServiceSasGranter::new(config.clone(), grant.clone());
        let resource = ServiceSasResource::Blob {
            container: "sensitive-container".to_string(),
            blob: "sensitive/path/blob.txt".to_string(),
        };
        let source = Credential::with_shared_key("sensitiveaccount", "raw-account-key-secret");
        let sas = Credential::with_sas_token("sv=2020-12-06&sig=raw-sas-token-secret");

        for (debug, secret) in [
            (format!("{config:?}"), "sensitiveaccount"),
            (format!("{grant:?}"), "sensitive-container"),
            (format!("{resource:?}"), "sensitive/path"),
            (format!("{ip:?}"), "198.51.100.77"),
            (format!("{operation:?}"), "sensitiveaccount"),
            (format!("{source:?}"), "raw-account-key-secret"),
            (format!("{sas:?}"), "raw-sas-token-secret"),
        ] {
            assert!(!debug.contains(secret));
        }
        let credential_debug = format!("{source:?}\n{sas:?}");
        for fragment in ["raw", "ret", "sv=", "sig="] {
            assert!(!credential_debug.contains(fragment));
        }

        let err = operation
            .grant_credential(&Context::new(), &source, Some(Duration::from_secs(60)))
            .await
            .expect_err("invalid key must fail without disclosure");
        let debug = format!("{err:?}");
        assert!(!debug.contains("raw-account-key-secret"));
        assert!(!debug.contains("sensitiveaccount"));
        assert!(!debug.contains("sensitive-container"));
        assert!(!debug.contains("sensitive/path"));
    }
}
