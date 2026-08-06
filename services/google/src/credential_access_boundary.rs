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

use reqsign_core::{Error, Result};
use serde::Serialize;

mod server_side;
pub use server_side::ServerSideCredentialAccessBoundaryGranter;

mod sts;

#[cfg(feature = "credential-access-boundary-client-side")]
mod client_side;
#[cfg(feature = "credential-access-boundary-client-side")]
pub use client_side::ClientSideCredentialAccessBoundaryGranter;

const MAX_ACCESS_BOUNDARY_RULES: usize = 10;
const MAX_ACCESS_BOUNDARY_CHARACTERS: usize = 2048;
const MAX_CONDITION_CHARACTERS: usize = 2048;
const MAX_OPTIONS_CHARACTERS: usize = 4 * 1024 * 1024;

const OBJECT_VIEWER_ROLE: u8 = 1 << 0;
const OBJECT_CREATOR_ROLE: u8 = 1 << 1;
const OBJECT_USER_ROLE: u8 = 1 << 2;
const OBJECT_ADMIN_ROLE: u8 = 1 << 3;
const ALL_ROLES: u8 =
    OBJECT_VIEWER_ROLE | OBJECT_CREATOR_ROLE | OBJECT_USER_ROLE | OBJECT_ADMIN_ROLE;

/// Typed Google Cloud Storage roles supported by Credential Access Boundaries.
///
/// The CAB schema names the field `availablePermissions`, but it does not accept
/// individual `storage.objects.*` permission names. It accepts IAM role
/// identifiers prefixed with `inRole:`. These constants deliberately expose only
/// the well-known predefined Cloud Storage object roles, preventing callers from
/// injecting raw role identifiers or binding a grant to a mutable custom role.
#[derive(Clone, Copy, PartialEq, Eq)]
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

    fn access_boundary(&self) -> Result<AccessBoundary> {
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
                "credential access boundary exceeds the size limit",
            ));
        }
        Ok(access_boundary)
    }

    #[cfg(any(feature = "credential-access-boundary-client-side", test))]
    fn validate(&self) -> Result<()> {
        self.access_boundary().map(drop)
    }

    fn options_json(&self) -> Result<String> {
        let access_boundary = self.access_boundary()?;
        let json = serde_json::to_string(&StsOptions { access_boundary }).map_err(|err| {
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
            "credential access boundary condition exceeds the size limit",
        ));
    }

    Ok(AvailabilityCondition { expression })
}

#[cfg(test)]
mod tests {
    use reqsign_core::ErrorKind;

    use super::*;

    #[test]
    fn validates_bucket_prefix_permission_and_rule_limits() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_VIEWER;
        let invalid = [
            CredentialAccessBoundaryGrant::for_bucket("ab", permissions),
            CredentialAccessBoundaryGrant::for_bucket("UPPER", permissions),
            CredentialAccessBoundaryGrant::for_bucket("bucket/name", permissions),
            CredentialAccessBoundaryGrant::for_bucket("-bucket", permissions),
            CredentialAccessBoundaryGrant::for_bucket("bucket-", permissions),
            CredentialAccessBoundaryGrant::for_bucket("192.168.0.1", permissions),
            CredentialAccessBoundaryGrant::for_bucket("goog-reserved", permissions),
            CredentialAccessBoundaryGrant::for_bucket("bucket..name", permissions),
            CredentialAccessBoundaryGrant::for_bucket(
                "example-bucket",
                CredentialAccessBoundaryPermissions(0),
            ),
            CredentialAccessBoundaryGrant::for_object_prefix("example-bucket", "", permissions),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "line\nbreak",
                permissions,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "x".repeat(1025),
                permissions,
            ),
        ];
        for grant in invalid {
            let err = grant.validate().expect_err("invalid grant must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        let mut maximum = CredentialAccessBoundaryGrant::for_bucket("bucket-0", permissions);
        for index in 1..MAX_ACCESS_BOUNDARY_RULES {
            maximum = maximum.with_bucket_rule(format!("bucket-{index}"), permissions);
        }
        maximum
            .validate()
            .expect("ten valid rules must be accepted");

        let too_many = maximum.with_bucket_rule("bucket-10", permissions);
        let err = too_many
            .validate()
            .expect_err("more than ten rules must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    }

    #[test]
    fn serializes_typed_roles_and_escapes_prefix_without_widening() {
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
        .expect("prefix grant must serialize");
        let options: serde_json::Value = serde_json::from_str(&json).expect("options must be JSON");
        let expression = options["accessBoundary"]["accessBoundaryRules"][0]
            ["availabilityCondition"]["expression"]
            .as_str()
            .expect("condition must be a string");
        assert!(expression.contains("objects//leading//nested/"));
        assert!(expression.ends_with(r#".startsWith("/leading//nested/")"#));
    }

    #[test]
    fn enforces_access_boundary_size_limit() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_VIEWER;
        CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "x".repeat(772),
            permissions,
        )
        .with_bucket_rule("aaa", permissions)
        .validate()
        .expect("boundary at the documented size limit must be accepted");

        let err = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "x".repeat(773),
            permissions,
        )
        .with_bucket_rule("aaa", permissions)
        .validate()
        .expect_err("boundary over the documented size limit must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    }
}
