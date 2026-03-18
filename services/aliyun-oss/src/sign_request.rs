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

use crate::credential::Credential;
use http::HeaderValue;
use http::header::{AUTHORIZATION, CONTENT_TYPE, DATE, HOST};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use reqsign_core::Result;
use reqsign_core::hash::{base64_hmac_sha1, hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, SignRequest, SigningRequest};
use std::collections::HashSet;
use std::fmt::Write;
use std::sync::LazyLock;
use std::time::Duration;

const CONTENT_MD5: &str = "content-md5";
const OSS_V4_ALGORITHM: &str = "OSS4-HMAC-SHA256";
const OSS_V4_REQUEST: &str = "aliyun_v4_request";
const OSS_V4_SERVICE: &str = "oss";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const X_OSS_ADDITIONAL_HEADERS: &str = "x-oss-additional-headers";
const X_OSS_CONTENT_SHA256: &str = "x-oss-content-sha256";
const X_OSS_CREDENTIAL: &str = "x-oss-credential";
const X_OSS_DATE: &str = "x-oss-date";
const X_OSS_EXPIRES: &str = "x-oss-expires";
const X_OSS_SECURITY_TOKEN: &str = "x-oss-security-token";
const X_OSS_SIGNATURE: &str = "x-oss-signature";
const X_OSS_SIGNATURE_VERSION: &str = "x-oss-signature-version";

static OSS_V4_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

static OSS_V4_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// SigningVersion controls which OSS signing algorithm the signer uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningVersion {
    V1,
    V4,
}

/// RequestSigner for Aliyun OSS signature.
#[derive(Debug)]
pub struct RequestSigner {
    bucket: String,
    region: Option<String>,
    signing_version: SigningVersion,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a new builder for Aliyun OSS signer.
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            region: None,
            signing_version: SigningVersion::V1,
            time: None,
        }
    }

    /// Set the OSS region.
    ///
    /// Signature V4 requires this value. V1 keeps ignoring it.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set the signing version.
    ///
    /// The signer defaults to V1. Use V4 together with [`RequestSigner::with_region`]
    /// to opt into OSS Signature Version 4.
    pub fn with_signing_version(mut self, signing_version: SigningVersion) -> Self {
        self.signing_version = signing_version;
        self
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    fn get_time(&self) -> Timestamp {
        self.time.unwrap_or_else(Timestamp::now)
    }
}
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let signing_time = self.get_time();

        match self.signing_version {
            SigningVersion::V1 => {
                if let Some(expires) = expires_in {
                    self.sign_query(req, cred, signing_time, expires)?;
                } else {
                    self.sign_header(req, cred, signing_time)?;
                }
            }
            SigningVersion::V4 => {
                self.sign_v4(req, cred, signing_time, expires_in)?;
            }
        }

        Ok(())
    }
}

impl RequestSigner {
    fn sign_header(
        &self,
        req: &mut http::request::Parts,
        cred: &Credential,
        signing_time: Timestamp,
    ) -> Result<()> {
        let string_to_sign = self.build_string_to_sign(req, cred, signing_time, None)?;
        let signature =
            base64_hmac_sha1(cred.access_key_secret.as_bytes(), string_to_sign.as_bytes());

        // Add date header
        req.headers
            .insert(DATE, Timestamp::format_http_date(signing_time).parse()?);

        // Add security token if present
        if let Some(token) = &cred.security_token {
            req.headers.insert("x-oss-security-token", token.parse()?);
        }

        // Add authorization header
        let auth_value = format!("OSS {}:{}", cred.access_key_id, signature);
        let mut header_value: HeaderValue = auth_value.parse()?;
        header_value.set_sensitive(true);
        req.headers.insert(AUTHORIZATION, header_value);

        Ok(())
    }

    fn sign_query(
        &self,
        req: &mut http::request::Parts,
        cred: &Credential,
        signing_time: Timestamp,
        expires: Duration,
    ) -> Result<()> {
        let expiration_time = signing_time + expires;
        let string_to_sign = self.build_string_to_sign(req, cred, signing_time, Some(expires))?;
        let signature =
            base64_hmac_sha1(cred.access_key_secret.as_bytes(), string_to_sign.as_bytes());

        // Build query parameters
        let mut query_pairs = Vec::new();

        // Parse existing query
        if let Some(query) = req.uri.query() {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    query_pairs.push((key.to_string(), value.to_string()));
                } else if !pair.is_empty() {
                    query_pairs.push((pair.to_string(), String::new()));
                }
            }
        }

        // Add signature parameters
        query_pairs.push(("OSSAccessKeyId".to_string(), cred.access_key_id.clone()));
        query_pairs.push((
            "Expires".to_string(),
            expiration_time.as_second().to_string(),
        ));
        query_pairs.push((
            "Signature".to_string(),
            utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC).to_string(),
        ));

        // Add security token if present
        if let Some(token) = &cred.security_token {
            query_pairs.push((
                "security-token".to_string(),
                utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC).to_string(),
            ));
        }

        // Rebuild URI with new query
        let query_string = query_pairs
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");

        let new_uri = if query_string.is_empty() {
            req.uri.clone()
        } else {
            let path = req.uri.path();
            let new_path_and_query = format!("{path}?{query_string}");
            let mut parts = req.uri.clone().into_parts();
            parts.path_and_query = Some(new_path_and_query.try_into()?);
            http::Uri::from_parts(parts)?
        };

        req.uri = new_uri;
        Ok(())
    }

    fn build_string_to_sign(
        &self,
        req: &http::request::Parts,
        cred: &Credential,
        signing_time: Timestamp,
        expires: Option<Duration>,
    ) -> Result<String> {
        let mut s = String::new();
        s.write_str(req.method.as_str())?;
        s.write_str("\n")?;

        // Content-MD5
        s.write_str(
            req.headers
                .get(CONTENT_MD5)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        )?;
        s.write_str("\n")?;

        // Content-Type
        s.write_str(
            req.headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        )?;
        s.write_str("\n")?;

        // Date or Expires
        match expires {
            Some(expires_duration) => {
                let expiration_time = signing_time + expires_duration;
                writeln!(&mut s, "{}", expiration_time.as_second())?;
            }
            None => {
                writeln!(&mut s, "{}", signing_time.format_http_date())?;
            }
        }

        let canonicalized_headers = self.canonicalize_headers(req, expires.is_none(), cred);
        if !canonicalized_headers.is_empty() {
            writeln!(&mut s, "{canonicalized_headers}")?;
        }

        // Canonicalized Resource
        write!(
            &mut s,
            "{}",
            self.canonicalize_resource(req, cred, expires.is_some())
        )?;

        Ok(s)
    }

    fn sign_v4(
        &self,
        req: &mut http::request::Parts,
        cred: &Credential,
        signing_time: Timestamp,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let region = self.region.as_deref().ok_or_else(|| {
            Error::config_invalid(
                "OSS V4 signing requires region; call RequestSigner::with_region(...)",
            )
        })?;

        let mut signing_req = SigningRequest::build(req)?;
        self.canonicalize_v4_headers(&mut signing_req, cred, signing_time, expires_in.is_some())?;
        let additional_headers = self.v4_additional_headers(&signing_req, expires_in.is_some())?;
        self.canonicalize_v4_query(
            &mut signing_req,
            cred,
            signing_time,
            expires_in,
            region,
            &additional_headers,
        )?;

        let canonical_request = self.build_v4_canonical_request(
            &signing_req,
            expires_in.is_some(),
            &additional_headers,
        )?;
        let scope = self.v4_scope(signing_time, region);
        let string_to_sign =
            self.build_v4_string_to_sign(signing_time, &scope, &canonical_request)?;
        let signature = self.build_v4_signature(cred, signing_time, region, &string_to_sign);

        if expires_in.is_some() {
            signing_req.query_push(X_OSS_SIGNATURE, signature);
        } else {
            let authorization = format!(
                "{OSS_V4_ALGORITHM} Credential={}/{}, AdditionalHeaders={}, Signature={}",
                cred.access_key_id,
                scope,
                additional_headers.join(";"),
                signature
            );
            let mut value: HeaderValue = authorization.parse()?;
            value.set_sensitive(true);
            signing_req.headers.insert(AUTHORIZATION, value);
        }

        signing_req.apply(req)
    }

    fn canonicalize_v4_headers(
        &self,
        req: &mut SigningRequest,
        cred: &Credential,
        signing_time: Timestamp,
        is_presign: bool,
    ) -> Result<()> {
        for (_, value) in req.headers.iter_mut() {
            SigningRequest::header_value_normalize(value);
        }

        if is_presign && req.headers.get(HOST).is_none() {
            req.headers.insert(
                HOST,
                req.authority.as_str().parse().map_err(|e| {
                    Error::request_invalid("invalid authority for Host header").with_source(e)
                })?,
            );
        }

        if !is_presign {
            if req.headers.get(X_OSS_DATE).is_none() {
                req.headers
                    .insert(X_OSS_DATE, signing_time.format_iso8601().parse()?);
            }
            if req.headers.get(X_OSS_CONTENT_SHA256).is_none() {
                req.headers
                    .insert(X_OSS_CONTENT_SHA256, UNSIGNED_PAYLOAD.parse()?);
            }
            if let Some(token) = &cred.security_token {
                if req.headers.get(X_OSS_SECURITY_TOKEN).is_none() {
                    req.headers.insert(X_OSS_SECURITY_TOKEN, token.parse()?);
                }
            }
        }

        Ok(())
    }

    fn canonicalize_v4_query(
        &self,
        req: &mut SigningRequest,
        cred: &Credential,
        signing_time: Timestamp,
        expires_in: Option<Duration>,
        region: &str,
        additional_headers: &[String],
    ) -> Result<()> {
        let mut query_pairs = req
            .query
            .iter()
            .enumerate()
            .map(|(idx, (k, v))| {
                (
                    idx,
                    utf8_percent_encode(k, &OSS_V4_QUERY_ENCODE_SET).to_string(),
                    utf8_percent_encode(v, &OSS_V4_QUERY_ENCODE_SET).to_string(),
                )
            })
            .collect::<Vec<_>>();

        if let Some(expires) = expires_in {
            let scope = self.v4_scope(signing_time, region);
            let mut next_idx = query_pairs.len();
            query_pairs.push((
                next_idx,
                X_OSS_SIGNATURE_VERSION.to_string(),
                OSS_V4_ALGORITHM.to_string(),
            ));
            next_idx += 1;
            query_pairs.push((
                next_idx,
                X_OSS_CREDENTIAL.to_string(),
                utf8_percent_encode(
                    &format!("{}/{}", cred.access_key_id, scope),
                    &OSS_V4_QUERY_ENCODE_SET,
                )
                .to_string(),
            ));
            next_idx += 1;
            query_pairs.push((
                next_idx,
                X_OSS_DATE.to_string(),
                signing_time.format_iso8601(),
            ));
            next_idx += 1;
            query_pairs.push((
                next_idx,
                X_OSS_EXPIRES.to_string(),
                expires.as_secs().to_string(),
            ));
            next_idx += 1;
            query_pairs.push((
                next_idx,
                X_OSS_ADDITIONAL_HEADERS.to_string(),
                utf8_percent_encode(&additional_headers.join(";"), &OSS_V4_QUERY_ENCODE_SET)
                    .to_string(),
            ));
            next_idx += 1;
            if let Some(token) = &cred.security_token {
                query_pairs.push((
                    next_idx,
                    X_OSS_SECURITY_TOKEN.to_string(),
                    utf8_percent_encode(token, &OSS_V4_QUERY_ENCODE_SET).to_string(),
                ));
            }
        }

        query_pairs.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

        req.query = query_pairs
            .into_iter()
            .map(|(_, k, v)| (k, v))
            .collect::<Vec<_>>();

        Ok(())
    }

    fn build_v4_canonical_request(
        &self,
        req: &SigningRequest,
        is_presign: bool,
        additional_headers: &[String],
    ) -> Result<String> {
        let mut canonical_headers = Vec::new();
        for (name, value) in &req.headers {
            let name = name.as_str().to_ascii_lowercase();
            if name == AUTHORIZATION.as_str() {
                continue;
            }
            if self.should_include_v4_header(&name, is_presign)
                || additional_headers.binary_search(&name).is_ok()
            {
                canonical_headers.push((
                    name,
                    value
                        .to_str()
                        .map_err(|e| {
                            Error::request_invalid("invalid header value for V4 signing")
                                .with_source(e)
                        })?
                        .to_string(),
                ));
            }
        }
        canonical_headers.sort_by(|a, b| a.0.cmp(&b.0));

        let mut s = String::new();
        writeln!(&mut s, "{}", req.method)?;
        writeln!(
            &mut s,
            "{}",
            self.v4_canonical_uri(&req.path, req.authority.as_str())?
        )?;
        writeln!(
            &mut s,
            "{}",
            req.query
                .iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        k.clone()
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
        )?;
        for (name, value) in canonical_headers {
            writeln!(&mut s, "{name}:{value}")?;
        }
        writeln!(&mut s)?;
        writeln!(&mut s, "{}", additional_headers.join(";"))?;
        write!(&mut s, "{UNSIGNED_PAYLOAD}")?;

        Ok(s)
    }

    fn build_v4_string_to_sign(
        &self,
        signing_time: Timestamp,
        scope: &str,
        canonical_request: &str,
    ) -> Result<String> {
        let mut s = String::new();
        writeln!(&mut s, "{OSS_V4_ALGORITHM}")?;
        writeln!(&mut s, "{}", signing_time.format_iso8601())?;
        writeln!(&mut s, "{scope}")?;
        write!(&mut s, "{}", hex_sha256(canonical_request.as_bytes()))?;
        Ok(s)
    }

    fn build_v4_signature(
        &self,
        cred: &Credential,
        signing_time: Timestamp,
        region: &str,
        string_to_sign: &str,
    ) -> String {
        let date_key = hmac_sha256(
            format!("aliyun_v4{}", cred.access_key_secret).as_bytes(),
            signing_time.format_date().as_bytes(),
        );
        let region_key = hmac_sha256(&date_key, region.as_bytes());
        let service_key = hmac_sha256(&region_key, OSS_V4_SERVICE.as_bytes());
        let signing_key = hmac_sha256(&service_key, OSS_V4_REQUEST.as_bytes());
        hex_hmac_sha256(&signing_key, string_to_sign.as_bytes())
    }

    fn v4_scope(&self, signing_time: Timestamp, region: &str) -> String {
        format!(
            "{}/{}/{}/{}",
            signing_time.format_date(),
            region,
            OSS_V4_SERVICE,
            OSS_V4_REQUEST
        )
    }

    fn v4_additional_headers(&self, req: &SigningRequest, is_presign: bool) -> Result<Vec<String>> {
        let mut headers = Vec::new();
        for name in req.headers.keys() {
            let name = name.as_str().to_ascii_lowercase();
            if name == AUTHORIZATION.as_str() {
                continue;
            }
            if !self.should_include_v4_header(&name, is_presign) {
                headers.push(name);
            }
        }
        headers.sort();
        headers.dedup();

        Ok(headers)
    }

    fn should_include_v4_header(&self, header: &str, is_presign: bool) -> bool {
        if header == CONTENT_MD5 || header == CONTENT_TYPE.as_str() {
            return true;
        }

        if header.starts_with("x-oss-") {
            return !is_presign || header != X_OSS_CONTENT_SHA256;
        }

        false
    }

    fn v4_canonical_uri(&self, path: &str, authority: &str) -> Result<String> {
        let decoded_path = percent_decode_str(path)
            .decode_utf8()
            .map_err(|e| Error::request_invalid("invalid request path").with_source(e))?;
        let resource_path = if authority.starts_with(&format!("{}.", self.bucket)) {
            format!("/{}{}", self.bucket, decoded_path)
        } else {
            decoded_path.into_owned()
        };

        Ok(utf8_percent_encode(&resource_path, &OSS_V4_URI_ENCODE_SET).to_string())
    }

    fn canonicalize_headers(
        &self,
        req: &http::request::Parts,
        include_implicit_security_token: bool,
        cred: &Credential,
    ) -> String {
        let mut oss_headers = Vec::new();

        // Collect x-oss-* headers
        for (name, value) in &req.headers {
            let name_str = name.as_str().to_lowercase();
            if name_str.starts_with("x-oss-") {
                if let Ok(value_str) = value.to_str() {
                    oss_headers.push((name_str, value_str.to_string()));
                }
            }
        }

        // Header signing implicitly adds the security token header after the
        // string-to-sign is computed, so it must already participate in canonicalization.
        if include_implicit_security_token {
            if let Some(token) = &cred.security_token {
                oss_headers.push(("x-oss-security-token".to_string(), token.clone()));
            }
        }

        // Sort by header name
        oss_headers.sort_by(|a, b| a.0.cmp(&b.0));

        // Format as name:value
        oss_headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn canonicalize_resource(
        &self,
        req: &http::request::Parts,
        cred: &Credential,
        is_query_signing: bool,
    ) -> String {
        let path = req.uri.path();
        let mut query_pairs = Vec::new();

        // Parse query parameters
        if let Some(query) = req.uri.query() {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let decoded_key = percent_encoding::percent_decode_str(key).decode_utf8_lossy();
                    let decoded_value =
                        percent_encoding::percent_decode_str(value).decode_utf8_lossy();
                    if is_sub_resource(&decoded_key) {
                        query_pairs.push((decoded_key.to_string(), decoded_value.to_string()));
                    }
                } else if !pair.is_empty() {
                    let decoded_key =
                        percent_encoding::percent_decode_str(pair).decode_utf8_lossy();
                    if is_sub_resource(&decoded_key) {
                        query_pairs.push((decoded_key.to_string(), String::new()));
                    }
                }
            }
        }

        // Add security token for query signing
        if is_query_signing {
            if let Some(token) = &cred.security_token {
                query_pairs.push(("security-token".to_string(), token.clone()));
            }
        }

        // Sort query parameters
        query_pairs.sort_by(|a, b| a.0.cmp(&b.0));

        // Build resource string
        let decoded_path = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
        let authority = req.uri.authority().map(|v| v.as_str()).unwrap_or("");
        let is_virtual_host = authority.starts_with(&format!("{}.", self.bucket));

        let resource_path = if is_virtual_host {
            format!("/{}{}", self.bucket, decoded_path)
        } else {
            // Path-style addressing already includes bucket in request path: http://endpoint/<bucket>/<object>, do not repeat
            decoded_path.to_string()
        };

        if query_pairs.is_empty() {
            resource_path
        } else {
            let query_string = query_pairs
                .iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        k.clone()
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join("&");
            format!("{resource_path}?{query_string}")
        }
    }
}

fn is_sub_resource(key: &str) -> bool {
    SUBRESOURCES.contains(key)
}

// This list is copied from https://github.com/aliyun/aliyun-oss-go-sdk/blob/b6e0a2ae/oss/conn.go#L31-L54
static SUBRESOURCES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "acl",
        "uploads",
        "location",
        "cors",
        "logging",
        "website",
        "referer",
        "lifecycle",
        "delete",
        "append",
        "tagging",
        "objectMeta",
        "uploadId",
        "partNumber",
        "security-token",
        "position",
        "img",
        "style",
        "styleName",
        "replication",
        "replicationProgress",
        "replicationLocation",
        "cname",
        "bucketInfo",
        "comp",
        "qos",
        "live",
        "status",
        "vod",
        "startTime",
        "endTime",
        "symlink",
        "x-oss-process",
        "response-content-type",
        "x-oss-traffic-limit",
        "response-content-language",
        "response-expires",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "udf",
        "udfName",
        "udfImage",
        "udfId",
        "udfImageDesc",
        "udfApplication",
        "comp",
        "udfApplicationLog",
        "restore",
        "callback",
        "callback-var",
        "qosInfo",
        "policy",
        "stat",
        "encryption",
        "versions",
        "versioning",
        "versionId",
        "requestPayment",
        "x-oss-request-payer",
        "sequential",
        "inventory",
        "inventoryId",
        "continuation-token",
        "asyncFetch",
        "worm",
        "wormId",
        "wormExtend",
        "withHashContext",
        "x-oss-enable-md5",
        "x-oss-enable-sha1",
        "x-oss-enable-sha256",
        "x-oss-hash-ctx",
        "x-oss-md5-ctx",
        "transferAcceleration",
        "regionList",
        "cloudboxes",
        "x-oss-ac-source-ip",
        "x-oss-ac-subnet-mask",
        "x-oss-ac-vpc-id",
        "x-oss-ac-forward-allow",
        "metaQuery",
    ])
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Credential;
    use http::Request;
    use reqsign_core::{Context, SigningRequest};

    fn test_signer() -> RequestSigner {
        RequestSigner::new("bucket")
    }

    fn test_credential(security_token: Option<&str>) -> Credential {
        Credential {
            access_key_id: "access_key_id".to_string(),
            access_key_secret: "access_key_secret".to_string(),
            security_token: security_token.map(ToString::to_string),
            expires_in: None,
        }
    }

    fn test_time() -> Timestamp {
        Timestamp::from_second(1_717_332_000).expect("timestamp must be valid")
    }

    #[test]
    fn test_header_string_to_sign_includes_implicit_security_token_header() {
        let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
            .header("x-oss-meta-color", "blue")
            .body(())
            .expect("request must build");
        let (parts, _) = req.into_parts();

        let string_to_sign = test_signer()
            .build_string_to_sign(
                &parts,
                &test_credential(Some("sts-token")),
                test_time(),
                None,
            )
            .expect("string to sign must build");

        assert_eq!(
            string_to_sign,
            "GET\n\n\nSun, 02 Jun 2024 12:40:00 GMT\nx-oss-meta-color:blue\nx-oss-security-token:sts-token\n/bucket/object.txt"
        );
    }

    #[test]
    fn test_presign_string_to_sign_includes_x_oss_headers() {
        let req = Request::get(
            "https://bucket.oss-cn-beijing.aliyuncs.com/object.txt?x-oss-process=style/test",
        )
        .header("x-oss-meta-color", "blue")
        .body(())
        .expect("request must build");
        let (parts, _) = req.into_parts();

        let string_to_sign = test_signer()
            .build_string_to_sign(
                &parts,
                &test_credential(None),
                test_time(),
                Some(Duration::from_secs(60)),
            )
            .expect("string to sign must build");

        assert_eq!(
            string_to_sign,
            "GET\n\n\n1717332060\nx-oss-meta-color:blue\n/bucket/object.txt?x-oss-process=style/test"
        );
    }

    #[test]
    fn test_presign_string_to_sign_uses_query_security_token_without_header_duplication() {
        let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
            .body(())
            .expect("request must build");
        let (parts, _) = req.into_parts();

        let string_to_sign = test_signer()
            .build_string_to_sign(
                &parts,
                &test_credential(Some("sts-token")),
                test_time(),
                Some(Duration::from_secs(60)),
            )
            .expect("string to sign must build");

        assert_eq!(
            string_to_sign,
            "GET\n\n\n1717332060\n/bucket/object.txt?security-token=sts-token"
        );
        assert!(!string_to_sign.contains("x-oss-security-token:sts-token"));
    }

    #[test]
    fn test_request_signer_accepts_region_configuration() {
        let signer = RequestSigner::new("bucket")
            .with_region("oss-cn-beijing")
            .with_signing_version(SigningVersion::V4);

        assert_eq!(signer.bucket, "bucket");
        assert_eq!(signer.region.as_deref(), Some("oss-cn-beijing"));
        assert_eq!(signer.signing_version, SigningVersion::V4);
    }

    #[test]
    fn test_region_configuration_is_noop_for_v1_signature() {
        let credential = Credential {
            access_key_id: "access_key_id".to_string(),
            access_key_secret: "access_key_secret".to_string(),
            security_token: None,
            expires_in: None,
        };
        let time = Timestamp::from_second(1_700_000_000).expect("timestamp must build");

        let mut without_region =
            http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        RequestSigner::new("bucket")
            .with_time(time)
            .sign_header(&mut without_region, &credential, time)
            .expect("signing without region must succeed");

        let mut with_region =
            http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        RequestSigner::new("bucket")
            .with_region("oss-cn-beijing")
            .with_time(time)
            .sign_header(&mut with_region, &credential, time)
            .expect("signing with region must succeed");

        assert_eq!(
            without_region.headers.get(AUTHORIZATION),
            with_region.headers.get(AUTHORIZATION)
        );
        assert_eq!(
            without_region.headers.get(DATE),
            with_region.headers.get(DATE)
        );
    }

    #[tokio::test]
    async fn test_v4_signing_requires_region() {
        let mut req =
            http::Request::get("https://examplebucket.oss-cn-hangzhou.aliyuncs.com/exampleobject")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        let credential = Credential {
            access_key_id: "testid".to_string(),
            access_key_secret: "yourAccessKeySecret".to_string(),
            security_token: None,
            expires_in: None,
        };

        let err = RequestSigner::new("examplebucket")
            .with_signing_version(SigningVersion::V4)
            .with_time(Timestamp::from_second(1_744_353_684).expect("timestamp must build"))
            .sign_request(&Context::new(), &mut req, Some(&credential), None)
            .await
            .expect_err("v4 without region must fail");
        assert!(err.to_string().contains("OSS V4 signing requires region"));
    }

    #[test]
    fn test_v4_header_signature_matches_golden_output() {
        let credential = Credential {
            access_key_id: "testid".to_string(),
            access_key_secret: "yourAccessKeySecret".to_string(),
            security_token: None,
            expires_in: None,
        };
        let time = Timestamp::from_second(1_744_353_684).expect("timestamp must build");
        let signer = RequestSigner::new("examplebucket")
            .with_region("cn-hangzhou")
            .with_signing_version(SigningVersion::V4)
            .with_time(time);

        let mut canonical_req =
            http::Request::put("https://examplebucket.oss-cn-hangzhou.aliyuncs.com/exampleobject")
                .header("Content-Disposition", "attachment")
                .header("Content-Length", "3")
                .header("Content-MD5", "ICy5YqxZB1uWSwcVLSNLcA==")
                .header("Content-Type", "text/plain")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        let mut signing_req =
            SigningRequest::build(&mut canonical_req).expect("request must build");
        signer
            .canonicalize_v4_headers(&mut signing_req, &credential, time, false)
            .expect("canonical headers must build");
        let additional_headers = signer
            .v4_additional_headers(&signing_req, false)
            .expect("additional headers must build");
        signer
            .canonicalize_v4_query(
                &mut signing_req,
                &credential,
                time,
                None,
                "cn-hangzhou",
                &additional_headers,
            )
            .expect("canonical query must build");
        let canonical_request = signer
            .build_v4_canonical_request(&signing_req, false, &additional_headers)
            .expect("canonical request must build");
        assert_eq!(
            canonical_request,
            "PUT\n/examplebucket/exampleobject\n\ncontent-disposition:attachment\ncontent-length:3\ncontent-md5:ICy5YqxZB1uWSwcVLSNLcA==\ncontent-type:text/plain\nx-oss-content-sha256:UNSIGNED-PAYLOAD\nx-oss-date:20250411T064124Z\n\ncontent-disposition;content-length\nUNSIGNED-PAYLOAD"
        );
        let string_to_sign = signer
            .build_v4_string_to_sign(
                time,
                &signer.v4_scope(time, "cn-hangzhou"),
                &canonical_request,
            )
            .expect("string to sign must build");
        assert_eq!(
            string_to_sign,
            "OSS4-HMAC-SHA256\n20250411T064124Z\n20250411/cn-hangzhou/oss/aliyun_v4_request\nc46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca"
        );

        let mut req =
            http::Request::put("https://examplebucket.oss-cn-hangzhou.aliyuncs.com/exampleobject")
                .header("Content-Disposition", "attachment")
                .header("Content-Length", "3")
                .header("Content-MD5", "ICy5YqxZB1uWSwcVLSNLcA==")
                .header("Content-Type", "text/plain")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;

        signer
            .sign_v4(&mut req, &credential, time, None)
            .expect("v4 header signing must succeed");

        assert_eq!(
            req.headers.get(X_OSS_DATE).and_then(|v| v.to_str().ok()),
            Some("20250411T064124Z")
        );
        assert_eq!(
            req.headers
                .get(X_OSS_CONTENT_SHA256)
                .and_then(|v| v.to_str().ok()),
            Some(UNSIGNED_PAYLOAD)
        );
        assert_eq!(
            req.headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()),
            Some(
                "OSS4-HMAC-SHA256 Credential=testid/20250411/cn-hangzhou/oss/aliyun_v4_request, AdditionalHeaders=content-disposition;content-length, Signature=d3694c2dfc5371ee6acd35e88c4871ac95a7ba01d3a2f476768fe61218590097"
            )
        );
    }

    #[test]
    fn test_v4_presign_signature_matches_golden_output() {
        let credential = Credential {
            access_key_id: "testid".to_string(),
            access_key_secret: "yourAccessKeySecret".to_string(),
            security_token: None,
            expires_in: None,
        };
        let time = Timestamp::from_second(1_733_196_187).expect("timestamp must build");
        let signer = RequestSigner::new("examplebucket")
            .with_region("cn-hangzhou")
            .with_signing_version(SigningVersion::V4)
            .with_time(time);

        let mut canonical_req =
            http::Request::get("https://examplebucket.oss-cn-hangzhou.aliyuncs.com/exampleobject")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        let mut signing_req =
            SigningRequest::build(&mut canonical_req).expect("request must build");
        signer
            .canonicalize_v4_headers(&mut signing_req, &credential, time, true)
            .expect("canonical headers must build");
        let additional_headers = signer
            .v4_additional_headers(&signing_req, true)
            .expect("additional headers must build");
        signer
            .canonicalize_v4_query(
                &mut signing_req,
                &credential,
                time,
                Some(Duration::from_secs(86_400)),
                "cn-hangzhou",
                &additional_headers,
            )
            .expect("canonical query must build");
        let canonical_request = signer
            .build_v4_canonical_request(&signing_req, true, &additional_headers)
            .expect("canonical request must build");
        assert_eq!(
            canonical_request,
            "GET\n/examplebucket/exampleobject\nx-oss-additional-headers=host&x-oss-credential=testid%2F20241203%2Fcn-hangzhou%2Foss%2Faliyun_v4_request&x-oss-date=20241203T032307Z&x-oss-expires=86400&x-oss-signature-version=OSS4-HMAC-SHA256\nhost:examplebucket.oss-cn-hangzhou.aliyuncs.com\n\nhost\nUNSIGNED-PAYLOAD"
        );

        let mut req =
            http::Request::get("https://examplebucket.oss-cn-hangzhou.aliyuncs.com/exampleobject")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        RequestSigner::new("examplebucket")
            .with_region("cn-hangzhou")
            .with_signing_version(SigningVersion::V4)
            .with_time(time)
            .sign_v4(
                &mut req,
                &credential,
                time,
                Some(Duration::from_secs(86_400)),
            )
            .expect("v4 presign must succeed");

        let query = req.uri.query().expect("query must exist");
        assert_eq!(
            query,
            "x-oss-additional-headers=host&x-oss-credential=testid%2F20241203%2Fcn-hangzhou%2Foss%2Faliyun_v4_request&x-oss-date=20241203T032307Z&x-oss-expires=86400&x-oss-signature-version=OSS4-HMAC-SHA256&x-oss-signature=a9ad2ce702a93c7c36ace35dd4e1b80cb76a999c890d7dfe78ff342a23dac8e0"
        );
    }

    #[test]
    fn test_v4_presign_canonical_query_sorts_repeated_keys() {
        let credential = Credential {
            access_key_id: "testid".to_string(),
            access_key_secret: "yourAccessKeySecret".to_string(),
            security_token: None,
            expires_in: None,
        };
        let time = Timestamp::from_second(1_733_196_187).expect("timestamp must build");
        let mut req = http::Request::get(
            "https://examplebucket.oss-cn-hangzhou.aliyuncs.com/exampleobject?prefix=b&acl&prefix=a%20value",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

        RequestSigner::new("examplebucket")
            .with_region("cn-hangzhou")
            .with_signing_version(SigningVersion::V4)
            .with_time(time)
            .sign_v4(&mut req, &credential, time, Some(Duration::from_secs(60)))
            .expect("v4 presign must succeed");

        let query = req.uri.query().expect("query must exist");
        let acl = query.find("acl").expect("acl must exist");
        let prefix_b = query.find("prefix=b").expect("prefix=b must exist");
        let prefix_a = query
            .find("prefix=a%20value")
            .expect("encoded prefix must exist");
        assert!(acl < prefix_a);
        assert!(prefix_b < prefix_a);
    }
}
