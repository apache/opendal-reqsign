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

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use http::HeaderValue;
use reqsign_core::{Error, Result};

/// The AWS region set covered by a SigV4a signature.
///
/// A region set can contain one region, multiple comma-separated regions, or
/// wildcard entries such as `*`. Region names are intentionally not checked
/// against a fixed registry so that new AWS regions remain usable.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SigningRegionSet(String);

impl SigningRegionSet {
    /// Create a signing region set from its wire representation.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let regions = value.split(',').map(str::trim).collect::<Vec<_>>();

        if regions.is_empty() || regions.iter().any(|region| region.is_empty()) {
            return Err(Error::request_invalid(
                "AWS signing region set must not contain empty regions",
            ));
        }

        let value = regions.join(",");
        HeaderValue::from_str(&value).map_err(|e| {
            Error::request_invalid("AWS signing region set is not a valid header value")
                .with_source(e)
        })?;

        Ok(Self(value))
    }

    /// Create a signing region set from individual region entries.
    pub fn from_regions<I, S>(regions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let regions = regions
            .into_iter()
            .map(|region| region.as_ref().to_string())
            .collect::<Vec<_>>();
        Self::new(regions.join(","))
    }

    /// Create a signing region set that covers every AWS region.
    pub fn all() -> Self {
        Self("*".to_string())
    }

    /// Return the canonical wire representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SigningRegionSet {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for SigningRegionSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SigningRegionSet {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for SigningRegionSet {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<&str> for SigningRegionSet {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_comma_separated_regions() {
        let regions = SigningRegionSet::new("us-east-1, us-west-2").unwrap();
        assert_eq!(regions.as_str(), "us-east-1,us-west-2");
    }

    #[test]
    fn builds_from_regions_and_wildcard() {
        let regions = SigningRegionSet::from_regions(["us-east-1", "us-west-2"]).unwrap();
        assert_eq!(regions.as_str(), "us-east-1,us-west-2");
        assert_eq!(SigningRegionSet::all().as_str(), "*");
    }

    #[test]
    fn rejects_empty_members() {
        assert!(SigningRegionSet::new("").is_err());
        assert!(SigningRegionSet::new("us-east-1,").is_err());
        assert!(SigningRegionSet::new("us-east-1,,us-west-2").is_err());
    }
}
