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

use std::time::Duration;

use reqsign_core::time::Timestamp;
use reqsign_core::{Error, ErrorKind, Result};
use serde::Deserialize;

pub(super) const STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";
pub(super) const TOKEN_EXCHANGE_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:token-exchange";
pub(super) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub(super) const MAX_ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

pub(super) fn checked_expiration(
    response_time: Timestamp,
    expires_in: Duration,
) -> Result<Timestamp> {
    let expires_in_seconds = i64::try_from(expires_in.as_secs())
        .map_err(|_| Error::unexpected("credential access boundary STS expiration is invalid"))?;
    let expiration_second = response_time
        .as_second()
        .checked_add(expires_in_seconds)
        .ok_or_else(|| Error::unexpected("credential access boundary STS expiration is invalid"))?;
    Timestamp::from_second(expiration_second)
        .map_err(|_| Error::unexpected("credential access boundary STS expiration is invalid"))?;
    Ok(response_time + expires_in)
}

#[derive(Deserialize)]
struct StsErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

pub(super) fn sts_error(status: http::StatusCode, body: &[u8]) -> Error {
    let error_code = serde_json::from_slice::<StsErrorResponse>(body)
        .ok()
        .and_then(|response| response.error);
    let recognized_code = match error_code.as_deref() {
        Some(
            code @ ("invalid_grant"
            | "invalid_request"
            | "invalid_target"
            | "invalid_scope"
            | "unsupported_grant_type"
            | "unsupported_token_type"
            | "unauthorized_client"
            | "access_denied"
            | "quota_exceeded"),
        ) => Some(code),
        _ => None,
    };

    let mut error = match recognized_code {
        Some("invalid_grant") => Error::credential_invalid(
            "credential access boundary token exchange rejected the source credential",
        ),
        Some(
            "invalid_request"
            | "invalid_target"
            | "invalid_scope"
            | "unsupported_grant_type"
            | "unsupported_token_type",
        ) => {
            Error::request_invalid("credential access boundary token exchange rejected the request")
        }
        Some("unauthorized_client" | "access_denied") => {
            Error::permission_denied("credential access boundary token exchange was denied")
        }
        Some("quota_exceeded") => {
            Error::rate_limited("credential access boundary token exchange was rate limited")
        }
        _ if status == http::StatusCode::UNAUTHORIZED => Error::credential_invalid(
            "credential access boundary token exchange rejected the source credential",
        ),
        _ if status == http::StatusCode::FORBIDDEN => {
            Error::permission_denied("credential access boundary token exchange was denied")
        }
        _ if status == http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("credential access boundary token exchange was rate limited")
        }
        _ => Error::unexpected("credential access boundary token exchange failed")
            .set_retryable(status.is_server_error()),
    }
    .with_context(format!("sts_status: {}", status.as_u16()));

    if let Some(code) = recognized_code {
        error = error.with_context(format!("sts_error: {code}"));
    }
    if error.kind() == ErrorKind::Unexpected && status.is_server_error() {
        error = error.set_retryable(true);
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_expiration_rejects_timestamp_overflow() {
        let response_time: Timestamp = "9999-12-30T21:59:59Z"
            .parse()
            .expect("timestamp must be valid");
        let err = checked_expiration(response_time, Duration::from_secs(2))
            .expect_err("expiration overflow must fail without panicking");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
    }
}
