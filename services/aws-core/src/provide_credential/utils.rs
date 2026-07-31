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

use reqsign_core::{Error, Result};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AwsPartition {
    pub(crate) id: &'static str,
    pub(crate) dns_suffix: &'static str,
}

pub(crate) fn partition_for_region(region: &str) -> Result<AwsPartition> {
    if !(3..=64).contains(&region.len())
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !region
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !region
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(Error::config_invalid("AWS STS signing region is invalid"));
    }

    let partition = if region.starts_with("cn-") {
        AwsPartition {
            id: "aws-cn",
            dns_suffix: "amazonaws.com.cn",
        }
    } else if region.starts_with("eusc-") {
        AwsPartition {
            id: "aws-eusc",
            dns_suffix: "amazonaws.eu",
        }
    } else if region.starts_with("us-isob-") {
        AwsPartition {
            id: "aws-iso-b",
            dns_suffix: "sc2s.sgov.gov",
        }
    } else if region.starts_with("us-iso-") {
        AwsPartition {
            id: "aws-iso",
            dns_suffix: "c2s.ic.gov",
        }
    } else if region.starts_with("eu-isoe-") {
        AwsPartition {
            id: "aws-iso-e",
            dns_suffix: "cloud.adc-e.uk",
        }
    } else if region.starts_with("us-isof-") {
        AwsPartition {
            id: "aws-iso-f",
            dns_suffix: "csp.hci.ic.gov",
        }
    } else if region.starts_with("us-gov-") {
        AwsPartition {
            id: "aws-us-gov",
            dns_suffix: "amazonaws.com",
        }
    } else {
        AwsPartition {
            id: "aws",
            dns_suffix: "amazonaws.com",
        }
    };
    Ok(partition)
}

/// Return the legacy global or partition-aware regional STS endpoint.
pub fn sts_endpoint(region: Option<&str>, use_regional: bool) -> Result<String> {
    if use_regional {
        let region =
            region.ok_or_else(|| Error::config_invalid("regional STS endpoint requires region"))?;
        let partition = partition_for_region(region)?;
        return Ok(format!("sts.{region}.{}", partition.dns_suffix));
    }

    match region {
        None => Ok("sts.amazonaws.com".to_string()),
        Some(region) => match partition_for_region(region)?.id {
            "aws" => Ok("sts.amazonaws.com".to_string()),
            "aws-cn" => Ok("sts.amazonaws.com.cn".to_string()),
            _ => Err(Error::config_invalid(
                "legacy global STS endpoint is unavailable for this AWS partition",
            )),
        },
    }
}

/// Common structure for AWS error responses
#[derive(Debug, Deserialize)]
pub struct AwsErrorResponse {
    #[serde(rename = "Error")]
    pub error: AwsError,
}

#[derive(Debug, Deserialize)]
pub struct AwsError {
    #[serde(rename = "Code")]
    pub code: String,
}

/// Parse AWS STS error response and return appropriate error
///
/// This function analyzes AWS error codes and maps them to the correct ErrorKind
/// with meaningful context for debugging.
pub fn parse_sts_error(operation: &str, status: http::StatusCode, body: &str) -> Error {
    // Try to parse the XML error response
    if let Ok(error_resp) = quick_xml::de::from_str::<AwsErrorResponse>(body) {
        let code = &error_resp.error.code;
        let recognized_code = matches!(
            code.as_str(),
            "AccessDenied"
                | "UnauthorizedAccess"
                | "Forbidden"
                | "ExpiredToken"
                | "TokenRefreshRequired"
                | "InvalidToken"
                | "InvalidParameterValue"
                | "MissingParameter"
                | "InvalidParameterCombination"
                | "RegionDisabled"
                | "Throttling"
                | "RequestLimitExceeded"
                | "TooManyRequestsException"
                | "ServiceUnavailable"
                | "InternalError"
                | "InternalFailure"
                | "InvalidRequest"
                | "MalformedQueryString"
                | "MalformedPolicyDocument"
                | "PackedPolicyTooLarge"
        );
        // Map AWS error codes to appropriate ErrorKind
        let mut error = match code.as_str() {
            // Permission/Authorization errors
            "AccessDenied" | "UnauthorizedAccess" | "Forbidden" => {
                Error::permission_denied("AWS STS request was denied")
            }

            // Credential errors
            "ExpiredToken" | "TokenRefreshRequired" | "InvalidToken" => {
                Error::credential_invalid("AWS STS rejected the source credential")
            }

            // Configuration errors
            "InvalidParameterValue" | "MissingParameter" | "InvalidParameterCombination" => {
                Error::config_invalid("AWS STS configuration is invalid")
            }

            // Rate limiting
            "Throttling" | "RequestLimitExceeded" | "TooManyRequestsException" => {
                Error::rate_limited("AWS STS request was rate limited")
            }

            // Service unavailable (retryable)
            "ServiceUnavailable" | "InternalError" | "InternalFailure" => {
                Error::unexpected("AWS STS service failed").set_retryable(true)
            }

            // Request errors
            "InvalidRequest" | "MalformedQueryString" => {
                Error::request_invalid("AWS STS rejected the request")
            }

            // Default to unexpected
            _ => Error::unexpected("AWS STS request failed"),
        };

        // Add context
        error = error.with_context(format!("operation: {operation}"));
        if recognized_code {
            error = error.with_context(format!("error_code: {code}"));
        }

        error
    } else {
        // Failed to parse error response, return generic error based on status code
        let mut error = match status.as_u16() {
            400..=499 if status == http::StatusCode::FORBIDDEN => {
                Error::permission_denied("AWS STS request was denied")
            }
            400..=499 if status == http::StatusCode::UNAUTHORIZED => {
                Error::credential_invalid("AWS STS rejected the source credential")
            }
            429 => Error::rate_limited("AWS STS request was rate limited"),
            400..=499 => Error::request_invalid("AWS STS rejected the request"),
            500..=599 => Error::unexpected("AWS STS service failed").set_retryable(true),
            _ => Error::unexpected("AWS STS request failed"),
        };

        error = error
            .with_context(format!("operation: {operation}"))
            .with_context(format!("http_status: {status}"));

        error
    }
}

/// Parse IMDS error response
///
/// EC2 Instance Metadata Service has its own error format
pub fn parse_imds_error(operation: &str, status: http::StatusCode, body: &str) -> Error {
    // IMDS returns JSON errors, try to parse them
    #[derive(Debug, Deserialize)]
    struct ImdsError {
        #[serde(rename = "Code")]
        code: String,
        #[serde(rename = "Message")]
        message: String,
    }

    if let Ok(error) = serde_json::from_str::<ImdsError>(body) {
        let err = match error.code.as_str() {
            "AssumeRoleUnauthorizedAccess" => Error::permission_denied(format!(
                "EC2 instance not authorized to assume role: {}",
                error.message
            ))
            .with_context("hint: check if the IAM role has a trust relationship with EC2"),
            "InvalidUserData.Malformed" => {
                Error::config_invalid(format!("malformed instance metadata: {}", error.message))
            }
            _ if error.code.contains("Expired") => {
                Error::credential_invalid(format!("IMDS credentials expired: {}", error.message))
            }
            _ => Error::unexpected(format!("IMDS error [{}]: {}", error.code, error.message)),
        };

        err.with_context(format!("operation: {operation}"))
            .with_context(format!("error_code: {}", error.code))
    } else {
        // Generic error based on status
        match status.as_u16() {
            401 | 403 => Error::permission_denied(format!("IMDS access denied: {body}"))
                .with_context(format!("operation: {operation}"))
                .with_context("hint: check if IMDSv2 is required"),
            404 => Error::config_invalid("instance metadata not found")
                .with_context(format!("operation: {operation}"))
                .with_context("hint: are you running on EC2?"),
            500..=599 => Error::unexpected(format!("IMDS server error: {body}"))
                .with_context(format!("operation: {operation}"))
                .set_retryable(true),
            _ => Error::unexpected(format!("IMDS request failed: {body}"))
                .with_context(format!("operation: {operation}"))
                .with_context(format!("http_status: {status}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use reqsign_core::ErrorKind;

    use super::*;

    #[test]
    fn resolves_partition_aware_sts_endpoints() {
        let cases = [
            ("us-east-1", "sts.us-east-1.amazonaws.com"),
            ("cn-north-1", "sts.cn-north-1.amazonaws.com.cn"),
            ("eusc-de-east-1", "sts.eusc-de-east-1.amazonaws.eu"),
            ("us-iso-east-1", "sts.us-iso-east-1.c2s.ic.gov"),
            ("us-isob-east-1", "sts.us-isob-east-1.sc2s.sgov.gov"),
            ("eu-isoe-west-1", "sts.eu-isoe-west-1.cloud.adc-e.uk"),
            ("us-isof-east-1", "sts.us-isof-east-1.csp.hci.ic.gov"),
            ("us-gov-west-1", "sts.us-gov-west-1.amazonaws.com"),
        ];

        for (region, expected) in cases {
            assert_eq!(
                sts_endpoint(Some(region), true).expect("regional endpoint must resolve"),
                expected
            );
        }
        assert_eq!(
            sts_endpoint(None, false).expect("commercial global endpoint must resolve"),
            "sts.amazonaws.com"
        );
        assert_eq!(
            sts_endpoint(Some("cn-north-1"), false).expect("China global endpoint must resolve"),
            "sts.amazonaws.com.cn"
        );
        assert_eq!(
            sts_endpoint(Some("us-iso-east-1"), false)
                .expect_err("isolated partitions must reject the legacy global endpoint")
                .kind(),
            ErrorKind::ConfigInvalid
        );
    }

    #[test]
    fn redacts_sts_error_material_and_preserves_legacy_kinds() {
        let cases = [
            ("RegionDisabled", ErrorKind::Unexpected),
            ("MalformedPolicyDocument", ErrorKind::Unexpected),
            ("PackedPolicyTooLarge", ErrorKind::Unexpected),
            ("InvalidRequest", ErrorKind::RequestInvalid),
        ];

        for (code, expected_kind) in cases {
            let body = format!(
                "<ErrorResponse><Error><Code>{code}</Code>\
                 <Message>response-secret</Message></Error></ErrorResponse>"
            );
            let error = parse_sts_error(
                "AssumeRoleWithWebIdentity",
                http::StatusCode::BAD_REQUEST,
                &body,
            );
            assert_eq!(error.kind(), expected_kind);
            let debug = format!("{error:?}");
            assert!(!debug.contains("response-secret"));
        }

        let error = parse_sts_error(
            "AssumeRole",
            http::StatusCode::FORBIDDEN,
            "raw-response-secret",
        );
        let debug = format!("{error:?}");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(!debug.contains("raw-response-secret"));
    }
}
