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

use bytes::Bytes;
use http::header;
use reqsign_core::Context;
use reqsign_core::Result;
use reqsign_core::hash;
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::time::Duration;

use crate::service_sas::ServiceSasResource;

const DEFAULT_USER_DELEGATION_SAS_VERSION: &str = "2020-12-06";
pub(crate) const USER_DELEGATION_KEY_CACHE_CAPACITY: usize = 64;
pub(crate) const MAX_USER_DELEGATION_KEY_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone)]
pub(crate) struct UserDelegationKey {
    pub signed_oid: String,
    pub signed_tid: String,
    pub signed_start: Timestamp,
    pub signed_expiry: Timestamp,
    pub signed_service: String,
    pub signed_version: String,
    pub value: String,
}

impl Debug for UserDelegationKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserDelegationKey")
            .field("signed_oid", &Redact::from(&self.signed_oid))
            .field("signed_tid", &Redact::from(&self.signed_tid))
            .field("signed_start", &self.signed_start)
            .field("signed_expiry", &self.signed_expiry)
            .field("signed_service", &self.signed_service)
            .field("signed_version", &self.signed_version)
            .field("value", &Redact::from(&self.value))
            .finish()
    }
}

pub(crate) struct UserDelegationKeyCache<K> {
    entries: VecDeque<(K, UserDelegationKey)>,
}

impl<K> Default for UserDelegationKeyCache<K> {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }
}

impl<K: Eq> UserDelegationKeyCache<K> {
    pub(crate) fn find_cloned(
        &self,
        cache_key: &K,
        usable: impl Fn(&UserDelegationKey) -> bool,
    ) -> Option<UserDelegationKey> {
        self.entries.iter().find_map(|(candidate, key)| {
            (candidate == cache_key && usable(key)).then(|| key.clone())
        })
    }

    pub(crate) fn insert(&mut self, cache_key: K, key: UserDelegationKey, current_time: Timestamp) {
        self.entries
            .retain(|(_, cached)| cached.signed_expiry > current_time);
        if let Some(index) = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == &cache_key)
        {
            self.entries.remove(index);
        }
        if key.signed_expiry <= current_time {
            return;
        }
        while self.entries.len() >= USER_DELEGATION_KEY_CACHE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((cache_key, key));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

pub(crate) fn floor_to_wire_second(timestamp: Timestamp) -> Result<Timestamp> {
    Timestamp::from_second(timestamp.as_second())
}

pub(crate) fn ceil_to_wire_second(timestamp: Timestamp) -> Result<Timestamp> {
    let mut second = timestamp.as_second();
    if timestamp.subsec_nanosecond() > 0 {
        second = second.checked_add(1).ok_or_else(|| {
            reqsign_core::Error::request_invalid("Azure SAS timestamp exceeds the wire time range")
        })?;
    }
    Timestamp::from_second(second)
}

pub(crate) fn user_delegation_key_covers(
    key: &UserDelegationKey,
    effective_start: Timestamp,
    expiry: Timestamp,
    current_time: Timestamp,
    service_version: &str,
) -> bool {
    !key.signed_oid.is_empty()
        && !key.signed_tid.is_empty()
        && !key.value.is_empty()
        && key.signed_service == "b"
        && key.signed_version == service_version
        && key.signed_start <= effective_start
        && key.signed_expiry >= expiry
        && key.signed_expiry > current_time
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must parse")
    }

    fn key(expiry: Timestamp, value: &str) -> UserDelegationKey {
        UserDelegationKey {
            signed_oid: "oid".to_string(),
            signed_tid: "tid".to_string(),
            signed_start: timestamp("2030-01-01T00:00:00Z"),
            signed_expiry: expiry,
            signed_service: "b".to_string(),
            signed_version: DEFAULT_USER_DELEGATION_SAS_VERSION.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn wire_time_rounding_preserves_bounds() {
        let fractional = timestamp("2030-01-01T00:00:00.500Z");

        assert_eq!(
            floor_to_wire_second(fractional).expect("floor must succeed"),
            timestamp("2030-01-01T00:00:00Z")
        );
        assert_eq!(
            ceil_to_wire_second(fractional).expect("ceil must succeed"),
            timestamp("2030-01-01T00:00:01Z")
        );
    }

    #[test]
    fn cache_is_bounded_and_drops_expired_entries() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let expiry = now + Duration::from_secs(60);
        let mut cache = UserDelegationKeyCache::default();

        for index in 0..=USER_DELEGATION_KEY_CACHE_CAPACITY {
            cache.insert(format!("key-{index}"), key(expiry, "a2V5"), now);
        }

        assert_eq!(cache.len(), USER_DELEGATION_KEY_CACHE_CAPACITY);
        assert!(cache.find_cloned(&"key-0".to_string(), |_| true).is_none());
        assert!(
            cache
                .find_cloned(&format!("key-{USER_DELEGATION_KEY_CACHE_CAPACITY}"), |_| {
                    true
                },)
                .is_some()
        );

        cache.insert("expired".to_string(), key(now, "expired"), now);
        assert_eq!(cache.len(), USER_DELEGATION_KEY_CACHE_CAPACITY);
        assert!(
            cache
                .find_cloned(&"expired".to_string(), |_| true)
                .is_none()
        );
    }
}

pub(crate) struct UserDelegationKeyRequest<'a> {
    pub scheme: &'a str,
    pub authority: &'a str,
    pub bearer_token: &'a str,
    pub start: Timestamp,
    pub expiry: Timestamp,
    pub service_version: &'a str,
    pub now: Timestamp,
}

pub(crate) async fn get_user_delegation_key(
    ctx: &Context,
    request: UserDelegationKeyRequest<'_>,
) -> Result<UserDelegationKey> {
    let uri: http::Uri = format!(
        "{}://{}/?restype=service&comp=userdelegationkey",
        request.scheme, request.authority
    )
    .parse()
    .map_err(|e| {
        reqsign_core::Error::request_invalid("invalid user delegation key URI").with_source(e)
    })?;

    // Azure Blob Storage expects a KeyInfo payload.
    //
    // Reference: https://learn.microsoft.com/en-us/rest/api/storageservices/get-user-delegation-key
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>{}</Start><Expiry>{}</Expiry></KeyInfo>",
        request.start.format_rfc3339_zulu(),
        request.expiry.format_rfc3339_zulu(),
    );

    let mut authorization: http::HeaderValue = format!("Bearer {}", request.bearer_token)
        .parse()
        .map_err(|e| {
        reqsign_core::Error::credential_invalid(
            "failed to build user delegation key authorization header",
        )
        .with_source(e)
    })?;
    authorization.set_sensitive(true);

    let req = http::Request::post(uri)
        .header("x-ms-version", request.service_version)
        .header("x-ms-date", request.now.format_http_date())
        .header(header::CONTENT_TYPE, "application/xml")
        .header(header::AUTHORIZATION, authorization)
        .body(Bytes::from(body))
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to build user delegation key request")
                .with_source(e)
        })?;

    let resp = ctx.http_send(req).await?;
    let (parts, body) = resp.into_parts();
    if !parts.status.is_success() {
        return Err(
            reqsign_core::Error::unexpected("user delegation key request failed")
                .with_context(format!("status: {}", parts.status)),
        );
    }

    let xml = String::from_utf8_lossy(&body).to_string();

    let signed_oid = extract_tag(&xml, "SignedOid")?;
    let signed_tid = extract_tag(&xml, "SignedTid")?;
    let signed_start = parse_timestamp(&extract_tag(&xml, "SignedStart")?)?;
    let signed_expiry = parse_timestamp(&extract_tag(&xml, "SignedExpiry")?)?;
    let signed_service = extract_tag(&xml, "SignedService")?;
    let signed_version = extract_tag(&xml, "SignedVersion")?;
    let value = extract_tag(&xml, "Value")?;

    Ok(UserDelegationKey {
        signed_oid,
        signed_tid,
        signed_start,
        signed_expiry,
        signed_service,
        signed_version,
        value,
    })
}

fn parse_timestamp(s: &str) -> Result<Timestamp> {
    s.parse::<Timestamp>()
        .map_err(|e| reqsign_core::Error::request_invalid("invalid timestamp").with_source(e))
}

fn extract_tag(xml: &str, tag: &str) -> Result<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let start = xml
        .find(&open)
        .ok_or_else(|| reqsign_core::Error::unexpected("missing xml tag").with_context(tag))?
        + open.len();
    let end = xml[start..]
        .find(&close)
        .ok_or_else(|| reqsign_core::Error::unexpected("missing xml end tag").with_context(tag))?
        + start;

    Ok(xml[start..end].trim().to_string())
}

#[derive(Clone)]
pub(crate) enum UserDelegationSasResource {
    Container {
        container: String,
    },
    Blob {
        container: String,
        blob: String,
    },
    Directory {
        container: String,
        path: String,
        depth: usize,
    },
}

impl UserDelegationSasResource {
    fn canonicalized_resource(&self, account: &str) -> String {
        match self {
            Self::Container { container } => format!("/blob/{account}/{container}"),
            Self::Blob { container, blob } => {
                format!("/blob/{account}/{container}/{blob}")
            }
            Self::Directory {
                container, path, ..
            } => format!("/blob/{account}/{container}/{path}"),
        }
    }

    fn signed_resource(&self) -> &'static str {
        match self {
            Self::Container { .. } => "c",
            Self::Blob { .. } => "b",
            Self::Directory { .. } => "d",
        }
    }

    fn directory_depth(&self) -> Option<usize> {
        match self {
            Self::Directory { depth, .. } => Some(*depth),
            _ => None,
        }
    }
}

impl From<ServiceSasResource> for UserDelegationSasResource {
    fn from(value: ServiceSasResource) -> Self {
        match value {
            ServiceSasResource::Container { container } => Self::Container { container },
            ServiceSasResource::Blob { container, blob } => Self::Blob { container, blob },
        }
    }
}

pub(crate) struct UserDelegationSharedAccessSignature {
    account: String,
    key: UserDelegationKey,

    resource: UserDelegationSasResource,
    permissions: String,
    expiry: Timestamp,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: Option<String>,
    version: String,
}

impl UserDelegationSharedAccessSignature {
    pub(crate) fn new(
        account: String,
        key: UserDelegationKey,
        resource: UserDelegationSasResource,
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
            version: DEFAULT_USER_DELEGATION_SAS_VERSION.to_string(),
        }
    }

    pub(crate) fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    pub(crate) fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    pub(crate) fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    pub(crate) fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    fn signature(&self) -> Result<String> {
        let canonicalized_resource = self.resource.canonicalized_resource(&self.account);

        if self.version.as_str() >= "2025-07-05" {
            return Err(reqsign_core::Error::request_invalid(
                "user delegation SAS versions 2025-07-05 and later are not supported",
            ));
        }

        let start = self
            .start
            .as_ref()
            .map_or_else(String::new, |v| v.format_rfc3339_zulu());
        let mut fields = vec![
            self.permissions.clone(),
            start,
            self.expiry.format_rfc3339_zulu(),
            canonicalized_resource,
            self.key.signed_oid.clone(),
            self.key.signed_tid.clone(),
            self.key.signed_start.format_rfc3339_zulu(),
            self.key.signed_expiry.format_rfc3339_zulu(),
            self.key.signed_service.clone(),
            self.key.signed_version.clone(),
        ];

        if self.version.as_str() >= "2020-02-10" {
            fields.extend([String::new(), String::new(), String::new()]);
        }

        fields.extend([
            self.ip.clone().unwrap_or_default(),
            self.protocol.clone().unwrap_or_default(),
            self.version.clone(),
            self.resource.signed_resource().to_string(),
            String::new(), // snapshot time
        ]);

        if self.version.as_str() >= "2020-12-06" {
            fields.push(String::new()); // encryption scope
        }

        fields.extend([
            String::new(), // rscc
            String::new(), // rscd
            String::new(), // rsce
            String::new(), // rscl
            String::new(), // rsct
        ]);

        let string_to_sign = fields.join("\n");

        let decoded_key = hash::base64_decode(&self.key.value)?;
        Ok(hash::base64_hmac_sha256(
            &decoded_key,
            string_to_sign.as_bytes(),
        ))
    }

    pub(crate) fn token(&self) -> Result<Vec<(String, String)>> {
        let mut elements: Vec<(String, String)> = vec![
            ("sv".to_string(), self.version.to_string()),
            ("se".to_string(), self.expiry.format_rfc3339_zulu()),
            ("sp".to_string(), self.permissions.to_string()),
            (
                "sr".to_string(),
                self.resource.signed_resource().to_string(),
            ),
            ("skoid".to_string(), self.key.signed_oid.to_string()),
            ("sktid".to_string(), self.key.signed_tid.to_string()),
            (
                "skt".to_string(),
                self.key.signed_start.format_rfc3339_zulu(),
            ),
            (
                "ske".to_string(),
                self.key.signed_expiry.format_rfc3339_zulu(),
            ),
            ("sks".to_string(), self.key.signed_service.to_string()),
            ("skv".to_string(), self.key.signed_version.to_string()),
        ];

        if let Some(depth) = self.resource.directory_depth() {
            elements.push(("sdd".to_string(), depth.to_string()));
        }
        if let Some(start) = &self.start {
            elements.push(("st".to_string(), start.format_rfc3339_zulu()))
        }
        if let Some(ip) = &self.ip {
            elements.push(("sip".to_string(), ip.to_string()))
        }
        if let Some(protocol) = &self.protocol {
            elements.push(("spr".to_string(), protocol.to_string()))
        }

        let sig = self.signature()?;
        elements.push(("sig".to_string(), sig));

        Ok(elements)
    }
}
