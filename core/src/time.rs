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

//! Time related utils.

use crate::Error;
use std::str::FromStr;

/// DateTime is the alias for `jiff::Timestamp`.
pub type DateTime = jiff::Timestamp;

/// Create datetime of now.
pub fn now() -> DateTime {
    jiff::Timestamp::now()
}

/// Format time into date: `20220301`
pub fn format_date(t: DateTime) -> String {
    t.strftime("%Y%m%d").to_string()
}

/// Format time into ISO8601: `20220313T072004Z`
pub fn format_iso8601(t: DateTime) -> String {
    t.strftime("%Y%m%dT%H%M%SZ").to_string()
}

/// Format time into http date: `Sun, 06 Nov 1994 08:49:37 GMT`
///
/// ## Note
///
/// HTTP date is slightly different from RFC2822.
///
/// - Timezone is fixed to GMT.
/// - Day must be 2 digit.
pub fn format_http_date(t: DateTime) -> String {
    t.strftime("%a, %d %b %Y %T GMT").to_string()
}

/// Format time into RFC3339: `2022-03-13T07:20:04Z`
pub fn format_rfc3339(t: DateTime) -> String {
    t.strftime("%FT%TZ").to_string()
}

/// Parse time from RFC3339.
///
/// All of them are valid time:
///
/// - `2022-03-13T07:20:04Z`
/// - `2022-03-01T08:12:34+00:00`
/// - `2022-03-01T08:12:34.00+00:00`
pub fn parse_rfc3339(s: &str) -> crate::Result<DateTime> {
    FromStr::from_str(s).map_err(|err| {
        Error::unexpected(format!("parse '{s}' into rfc3339 failed")).with_source(err)
    })
}

/// Parse time from RFC2822.
///
/// All of them are valid time:
///
/// - `Sat, 13 Jul 2024 15:09:59 -0400`
/// - `Mon, 15 Aug 2022 16:50:12 GMT`
pub fn parse_rfc2822(s: &str) -> crate::Result<DateTime> {
    let zoned = jiff::fmt::rfc2822::parse(s).map_err(|err| {
        Error::unexpected(format!("parse '{s}' into rfc2822 failed")).with_source(err)
    })?;
    Ok(zoned.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_time() -> DateTime {
        "2022-03-01T08:12:34Z".parse().unwrap()
    }

    #[test]
    fn test_format_date() {
        let t = test_time();
        assert_eq!("20220301", format_date(t))
    }

    #[test]
    fn test_format_ios8601() {
        let t = test_time();
        assert_eq!("20220301T081234Z", format_iso8601(t))
    }

    #[test]
    fn test_format_http_date() {
        let t = test_time();
        assert_eq!("Tue, 01 Mar 2022 08:12:34 GMT", format_http_date(t))
    }

    #[test]
    fn test_format_rfc3339() {
        let t = test_time();
        assert_eq!("2022-03-01T08:12:34Z", format_rfc3339(t))
    }

    #[test]
    fn test_parse_rfc3339() {
        let t = test_time();

        for v in [
            "2022-03-01T08:12:34Z",
            "2022-03-01T08:12:34+00:00",
            "2022-03-01T08:12:34.00+00:00",
        ] {
            assert_eq!(t, parse_rfc3339(v).expect("must be valid time"));
        }
    }
}
