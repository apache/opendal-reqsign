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
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::Duration;

/// An instant in time represented as the number of nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(jiff::Timestamp);

impl Timestamp {
    /// Create the timestamp of now.
    pub fn now() -> Self {
        Self(jiff::Timestamp::now())
    }

    /// Format the timestamp into date: `20220301`
    pub fn format_date(self) -> String {
        self.0.strftime("%Y%m%d").to_string()
    }

    /// Format the timestamp into ISO8601: `20220313T072004Z`
    pub fn format_iso8601(self) -> String {
        self.0.strftime("%Y%m%dT%H%M%SZ").to_string()
    }

    /// Format the timestamp into http date: `Sun, 06 Nov 1994 08:49:37 GMT`
    ///
    /// ## Note
    ///
    /// HTTP date is slightly different from RFC2822.
    ///
    /// - Timezone is fixed to GMT.
    /// - Day must be 2 digit.
    pub fn format_http_date(self) -> String {
        self.0.strftime("%a, %d %b %Y %T GMT").to_string()
    }

    /// Format the timestamp into RFC3339: `2022-03-13T07:20:04Z`
    pub fn format_rfc3339(self) -> String {
        self.0.strftime("%FT%TZ").to_string()
    }

    /// Parse a timestamp from RFC3339.
    ///
    /// All of them are valid time:
    ///
    /// - `2022-03-13T07:20:04Z`
    /// - `2022-03-01T08:12:34+00:00`
    /// - `2022-03-01T08:12:34.00+00:00`
    pub fn parse_rfc3339(s: &str) -> crate::Result<Timestamp> {
        match s.parse() {
            Ok(t) => Ok(Timestamp(t)),
            Err(err) => {
                Err(Error::unexpected(format!("parse '{s}' into rfc3339 failed")).with_source(err))
            }
        }
    }

    /// Parse a timestamp from RFC2822.
    ///
    /// All of them are valid time:
    ///
    /// - `Sat, 13 Jul 2024 15:09:59 -0400`
    /// - `Mon, 15 Aug 2022 16:50:12 GMT`
    pub fn parse_rfc2822(s: &str) -> crate::Result<Timestamp> {
        match jiff::fmt::rfc2822::parse(s) {
            Ok(zoned) => Ok(Timestamp(zoned.timestamp())),
            Err(err) => {
                Err(Error::unexpected(format!("parse '{s}' into rfc2822 failed")).with_source(err))
            }
        }
    }

    /// Parse the string format "2023-10-31 21:59:10.000000".
    pub fn parse_datetime_utc(s: &str) -> crate::Result<Timestamp> {
        let dt = s.parse::<jiff::civil::DateTime>().map_err(|err| {
            Error::unexpected(format!("parse '{s}' into datetime failed")).with_source(err)
        })?;

        let ts = jiff::tz::TimeZone::UTC.to_timestamp(dt).map_err(|err| {
            Error::unexpected(format!("convert '{s}' into timestamp failed")).with_source(err)
        })?;

        Ok(Timestamp(ts))
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Timestamp {
        let ts = self
            .0
            .checked_add(rhs)
            .expect("adding unsigned duration to timestamp overflowed");

        Timestamp(ts)
    }
}

impl AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Duration) -> Timestamp {
        let ts = self
            .0
            .checked_sub(rhs)
            .expect("subtracting unsigned duration from timestamp overflowed");

        Timestamp(ts)
    }
}

impl SubAssign<Duration> for Timestamp {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_time() -> Timestamp {
        Timestamp("2022-03-01T08:12:34Z".parse().unwrap())
    }

    #[test]
    fn test_format_date() {
        let t = test_time();
        assert_eq!("20220301", t.format_date())
    }

    #[test]
    fn test_format_ios8601() {
        let t = test_time();
        assert_eq!("20220301T081234Z", t.format_iso8601())
    }

    #[test]
    fn test_format_http_date() {
        let t = test_time();
        assert_eq!("Tue, 01 Mar 2022 08:12:34 GMT", t.format_http_date())
    }

    #[test]
    fn test_format_rfc3339() {
        let t = test_time();
        assert_eq!("2022-03-01T08:12:34Z", t.format_rfc3339())
    }

    #[test]
    fn test_parse_rfc3339() {
        let t = test_time();

        for v in [
            "2022-03-01T08:12:34Z",
            "2022-03-01T08:12:34+00:00",
            "2022-03-01T08:12:34.00+00:00",
        ] {
            assert_eq!(t, Timestamp::parse_rfc3339(v).expect("must be valid time"));
        }
    }
}
