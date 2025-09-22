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
use async_trait::async_trait;
use http::header::{AUTHORIZATION, CONTENT_TYPE, DATE};
use http::HeaderValue;
use once_cell::sync::Lazy;
use percent_encoding::utf8_percent_encode;
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::{format_http_date, now, DateTime};
use reqsign_core::Result;
use reqsign_core::{Context, SignRequest};
use std::collections::HashSet;
use std::fmt::Write;
use std::time::Duration;

const CONTENT_MD5: &str = "content-md5";

/// RequestSigner for Aliyun OSS signature.
#[derive(Debug)]
pub struct RequestSigner {
    bucket: String,
    time: Option<DateTime>,
}

impl RequestSigner {
    /// Create a new builder for Aliyun OSS signer.
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            time: None,
        }
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn with_time(mut self, time: DateTime) -> Self {
        self.time = Some(time);
        self
    }

    fn get_time(&self) -> DateTime {
        self.time.unwrap_or_else(now)
    }
}

#[async_trait]
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

        // Determine signing method based on expires_in
        if let Some(expires) = expires_in {
            self.sign_query(req, cred, signing_time, expires)?;
        } else {
            self.sign_header(req, cred, signing_time)?;
        }

        Ok(())
    }
}

impl RequestSigner {
    fn sign_header(
        &self,
        req: &mut http::request::Parts,
        cred: &Credential,
        signing_time: DateTime,
    ) -> Result<()> {
        let string_to_sign = self.build_string_to_sign(req, cred, signing_time, None)?;
        let signature =
            base64_hmac_sha1(cred.access_key_secret.as_bytes(), string_to_sign.as_bytes());

        // Add date header
        req.headers
            .insert(DATE, format_http_date(signing_time).parse()?);

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
        signing_time: DateTime,
        expires: Duration,
    ) -> Result<()> {
        let expiration_time = signing_time
            + jiff::SignedDuration::try_from(expires).map_err(|e| {
                reqsign_core::Error::request_invalid(format!("Invalid expiration duration: {e}"))
            })?;
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
        signing_time: DateTime,
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
                let expiration_time = signing_time
                    + jiff::SignedDuration::try_from(expires_duration).map_err(|e| {
                        reqsign_core::Error::request_invalid(format!(
                            "Invalid expiration duration: {e}"
                        ))
                    })?;
                writeln!(&mut s, "{}", expiration_time.as_second())?;
            }
            None => {
                writeln!(&mut s, "{}", format_http_date(signing_time))?;
            }
        }

        // Canonicalized OSS Headers (only for header signing)
        if expires.is_none() {
            let canonicalized_headers = self.canonicalize_headers(req, cred);
            if !canonicalized_headers.is_empty() {
                writeln!(&mut s, "{canonicalized_headers}")?;
            }
        }

        // Canonicalized Resource
        write!(
            &mut s,
            "{}",
            self.canonicalize_resource(req, cred, expires.is_some())
        )?;

        Ok(s)
    }

    fn canonicalize_headers(&self, req: &http::request::Parts, cred: &Credential) -> String {
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

        // Add security token for header signing
        if let Some(token) = &cred.security_token {
            oss_headers.push(("x-oss-security-token".to_string(), token.clone()));
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
        let resource_path = format!("/{}{}", self.bucket, decoded_path);

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
    SUB_RESOURCES.contains(key)
}

/// This list is copied from <https://github.com/aliyun/aliyun-oss-go-sdk/blob/master/oss/conn.go>
static SUB_RESOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
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
