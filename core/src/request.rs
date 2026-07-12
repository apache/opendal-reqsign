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

use std::borrow::Cow;
use std::mem;
use std::time::Duration;

use crate::{Error, Result};
use http::HeaderMap;
use http::HeaderValue;
use http::Method;
use http::Uri;
use http::header::HeaderName;
use http::uri::Authority;
use http::uri::PathAndQuery;
use http::uri::Scheme;
use std::str::FromStr;

/// Signing context for request.
#[derive(Debug)]
pub struct SigningRequest {
    /// HTTP method.
    pub method: Method,
    /// HTTP scheme.
    pub scheme: Scheme,
    /// HTTP authority.
    pub authority: Authority,
    /// HTTP path.
    pub path: String,
    /// HTTP query parameters.
    pub query: Vec<(String, String)>,
    /// HTTP headers.
    pub headers: HeaderMap,
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn append_query_pair(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    if !value.is_empty() {
        output.push('=');
        output.push_str(value);
    }
}

fn append_query_pairs(output: &mut String, query: &[(String, String)], mut needs_separator: bool) {
    for (key, value) in query {
        if needs_separator {
            output.push('&');
        }

        append_query_pair(output, key, value);
        needs_separator = true;
    }
}

impl SigningRequest {
    /// Build a signing context from http::request::Parts.
    pub fn build(parts: &mut http::request::Parts) -> Result<Self> {
        // Keep the original URI in parts so apply can preserve its raw query.
        let uri = parts.uri.clone().into_parts();
        let paq = uri
            .path_and_query
            .unwrap_or_else(|| PathAndQuery::from_static("/"));

        Ok(SigningRequest {
            method: parts.method.clone(),
            scheme: uri.scheme.unwrap_or(Scheme::HTTP),
            authority: uri.authority.ok_or_else(|| {
                Error::request_invalid("request without authority is invalid for signing")
            })?,
            path: paq.path().to_string(),
            query: paq.query().map(parse_query).unwrap_or_default(),

            // Take the headers out of the request to avoid copy.
            // We will return it back when apply the context.
            headers: mem::take(&mut parts.headers),
        })
    }

    /// Apply the signing context back to http::request::Parts.
    ///
    /// Existing query parameters preserve their raw URI representation when unchanged.
    /// Appended query parameters do not cause the existing query to be rebuilt.
    /// Modifying, removing, or reordering existing parameters rebuilds the query.
    pub fn apply(mut self, parts: &mut http::request::Parts) -> Result<()> {
        let original_query = parts
            .uri
            .query()
            .map(|raw_query| (raw_query.to_string(), parse_query(raw_query)));
        let query_size = self.query_size();

        // Return headers back.
        mem::swap(&mut parts.headers, &mut self.headers);
        parts.method = self.method;
        parts.uri = {
            let mut uri_parts = mem::take(&mut parts.uri).into_parts();
            // Return scheme bakc.
            uri_parts.scheme = Some(self.scheme);
            // Return authority back.
            uri_parts.authority = Some(self.authority);
            // Build path and query.
            uri_parts.path_and_query = {
                let paq = match original_query {
                    Some((raw_query, parsed_query)) if self.query.starts_with(&parsed_query) => {
                        let mut s = self.path;
                        s.reserve(raw_query.len() + query_size + self.query.len() + 1);
                        s.push('?');
                        s.push_str(&raw_query);

                        let needs_separator = !raw_query.is_empty() && !raw_query.ends_with('&');
                        append_query_pairs(
                            &mut s,
                            &self.query[parsed_query.len()..],
                            needs_separator,
                        );
                        s
                    }
                    _ if query_size == 0 => self.path,
                    _ => {
                        let mut s = self.path;
                        s.reserve(query_size + self.query.len() + 1);
                        s.push('?');
                        append_query_pairs(&mut s, &self.query, false);
                        s
                    }
                };

                Some(
                    PathAndQuery::from_str(&paq).map_err(|e| {
                        Error::request_invalid("invalid path and query").with_source(e)
                    })?,
                )
            };
            Uri::from_parts(uri_parts)
                .map_err(|e| Error::request_invalid("failed to build URI").with_source(e))?
        };

        Ok(())
    }

    /// Get the path percent decoded.
    pub fn path_percent_decoded(&self) -> Cow<'_, str> {
        percent_encoding::percent_decode_str(&self.path).decode_utf8_lossy()
    }

    /// Get query size.
    #[inline]
    pub fn query_size(&self) -> usize {
        self.query
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
    }

    /// Push a new query pair into query list.
    #[inline]
    pub fn query_push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.query.push((key.into(), value.into()));
    }

    /// Push a query string into query list.
    #[inline]
    pub fn query_append(&mut self, query: &str) {
        self.query.push((query.to_string(), "".to_string()));
    }

    /// Get query value by filter.
    pub fn query_to_vec_with_filter(&self, filter: impl Fn(&str) -> bool) -> Vec<(String, String)> {
        self.query
            .iter()
            // Filter all queries
            .filter(|(k, _)| filter(k))
            // Clone all queries
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Convert sorted query to string.
    ///
    /// ```shell
    /// [(a, b), (c, d)] => "a:b\nc:d"
    /// ```
    pub fn query_to_string(mut query: Vec<(String, String)>, sep: &str, join: &str) -> String {
        let mut s = String::with_capacity(16);

        // Sort via header name.
        query.sort();

        for (idx, (k, v)) in query.into_iter().enumerate() {
            if idx != 0 {
                s.push_str(join);
            }

            s.push_str(&k);
            if !v.is_empty() {
                s.push_str(sep);
                s.push_str(&v);
            }
        }

        s
    }

    /// Convert sorted query to percent decoded string.
    ///
    /// ```shell
    /// [(a, b), (c, d)] => "a:b\nc:d"
    /// ```
    pub fn query_to_percent_decoded_string(
        mut query: Vec<(String, String)>,
        sep: &str,
        join: &str,
    ) -> String {
        let mut s = String::with_capacity(16);

        // Sort via header name.
        query.sort();

        for (idx, (k, v)) in query.into_iter().enumerate() {
            if idx != 0 {
                s.push_str(join);
            }

            s.push_str(&k);
            if !v.is_empty() {
                s.push_str(sep);
                s.push_str(&percent_encoding::percent_decode_str(&v).decode_utf8_lossy());
            }
        }

        s
    }

    /// Get header value by name.
    ///
    /// Returns empty string if header not found.
    #[inline]
    pub fn header_get_or_default(&self, key: &HeaderName) -> Result<&str> {
        match self.headers.get(key) {
            Some(v) => v
                .to_str()
                .map_err(|e| Error::request_invalid("invalid header value").with_source(e)),
            None => Ok(""),
        }
    }

    /// Normalize header value.
    pub fn header_value_normalize(v: &mut HeaderValue) {
        let bs = v.as_bytes();

        let starting_index = bs.iter().position(|b| *b != b' ').unwrap_or(0);
        let ending_offset = bs.iter().rev().position(|b| *b != b' ').unwrap_or(0);
        let ending_index = bs.len() - ending_offset;

        // This can't fail because we started with a valid HeaderValue and then only trimmed spaces
        *v = HeaderValue::from_bytes(&bs[starting_index..ending_index])
            .expect("invalid header value")
    }

    /// Get header names as sorted vector.
    pub fn header_name_to_vec_sorted(&self) -> Vec<&str> {
        let mut h = self
            .headers
            .keys()
            .map(|k| k.as_str())
            .collect::<Vec<&str>>();
        h.sort_unstable();

        h
    }

    /// Get header names with given prefix.
    pub fn header_to_vec_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.headers
            .iter()
            // Filter all header that starts with prefix
            .filter(|(k, _)| k.as_str().starts_with(prefix))
            // Convert all header name to lowercase
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().expect("must be valid header").to_string(),
                )
            })
            .collect()
    }

    /// Convert sorted headers to string.
    ///
    /// ```shell
    /// [(a, b), (c, d)] => "a:b\nc:d"
    /// ```
    pub fn header_to_string(mut headers: Vec<(String, String)>, sep: &str, join: &str) -> String {
        let mut s = String::with_capacity(16);

        // Sort via header name.
        headers.sort();

        for (idx, (k, v)) in headers.into_iter().enumerate() {
            if idx != 0 {
                s.push_str(join);
            }

            s.push_str(&k);
            s.push_str(sep);
            s.push_str(&v);
        }

        s
    }
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_QUERY: &str = "versionId=a%2Bb%3Dc%2525%26e";

    fn build_signing_request(raw_query: &str) -> Result<(SigningRequest, http::request::Parts)> {
        let req = http::Request::get(format!("https://example.com/object?{raw_query}")).body(())?;
        let (mut parts, _) = req.into_parts();
        let signing_req = SigningRequest::build(&mut parts)?;

        Ok((signing_req, parts))
    }

    #[test]
    fn test_apply_preserves_existing_raw_query() -> Result<()> {
        let (signing_req, mut parts) = build_signing_request(RAW_QUERY)?;
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some(RAW_QUERY));
        Ok(())
    }

    #[test]
    fn test_apply_preserves_existing_raw_query_when_appending() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request(RAW_QUERY)?;
        signing_req.query_push("signature", "value");
        signing_req.apply(&mut parts)?;

        assert_eq!(
            parts.uri.query(),
            Some("versionId=a%2Bb%3Dc%2525%26e&signature=value")
        );
        Ok(())
    }

    #[test]
    fn test_apply_preserves_form_query_wire_representation_when_appending() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request("value=a+b&empty=&flag")?;
        signing_req.query_push("signature", "value");
        signing_req.apply(&mut parts)?;

        assert_eq!(
            parts.uri.query(),
            Some("value=a+b&empty=&flag&signature=value")
        );
        Ok(())
    }

    #[test]
    fn test_apply_rebuilds_explicitly_updated_query() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request(RAW_QUERY)?;
        signing_req.query[0].1 = "updated".to_string();
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some("versionId=updated"));
        Ok(())
    }

    #[test]
    fn test_apply_rebuilds_all_query_pairs_when_updating() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request("keep=%41&change=old")?;
        signing_req.query[1].1 = "new".to_string();
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some("keep=A&change=new"));
        Ok(())
    }

    #[test]
    fn test_apply_rebuilds_query_after_removing() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request("remove=1&keep=%41")?;
        signing_req.query.remove(0);
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some("keep=A"));
        Ok(())
    }

    #[test]
    fn test_apply_rebuilds_ambiguous_duplicate_query_after_removing() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request("x=%41&x=A")?;
        signing_req.query.remove(0);
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some("x=A"));
        Ok(())
    }

    #[test]
    fn test_apply_rebuilds_query_after_inserting() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request("keep=%41")?;
        signing_req
            .query
            .insert(0, ("insert".to_string(), "1".to_string()));
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some("insert=1&keep=A"));
        Ok(())
    }

    #[test]
    fn test_apply_rebuilds_query_after_sorting() -> Result<()> {
        let (mut signing_req, mut parts) = build_signing_request("z=%41&a=1")?;
        signing_req.query.sort();
        signing_req.apply(&mut parts)?;

        assert_eq!(parts.uri.query(), Some("a=1&z=A"));
        Ok(())
    }
}
