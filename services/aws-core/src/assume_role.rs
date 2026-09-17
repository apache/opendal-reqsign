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

use std::collections::HashSet;
use std::fmt::{Debug, Formatter};

use bytes::Bytes;
use form_urlencoded::Serializer;
use quick_xml::de;
use reqsign_core::hash::hex_sha256;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, Signer, SigningCredential};
use serde::Deserialize;

use crate::Credential;
use crate::constants::X_AMZ_CONTENT_SHA_256;
use crate::provide_credential::utils::{parse_sts_error, partition_for_region, sts_endpoint};

const MIN_DURATION_SECONDS: u32 = 900;
const MAX_DURATION_SECONDS: u32 = 43_200;
const MAX_POLICY_ARNS: usize = 10;
const MAX_POLICY_PLAINTEXT_CHARACTERS: usize = 2_048;
const MAX_SESSION_TAGS: usize = 50;
const MAX_GET_URI_LENGTH: usize = 2_048;

/// A typed [AWS STS `AssumeRole`] authority transition.
///
/// The source credential authorizes this transition, but the returned
/// credential derives its permissions from the target role and optional
/// session policies. It is not necessarily a monotonic downscope of the
/// source principal's direct permissions.
///
/// Validation is performed before the STS request is signed or sent. AWS
/// still owns trust-policy evaluation, the target role's configured maximum
/// session duration, the one-hour role-chaining limit, inherited
/// transitive-tag conflicts, and packed-policy limits that cannot be
/// determined from reqsign's opaque source credential locally.
///
/// [AWS STS `AssumeRole`]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
#[derive(Clone)]
pub struct AssumeRoleGrant {
    pub(crate) role_arn: String,
    pub(crate) role_session_name: String,
    pub(crate) external_id: Option<String>,
    pub(crate) tags: Vec<(String, String)>,
    pub(crate) policy: Option<String>,
    pub(crate) policy_arns: Vec<String>,
    pub(crate) serial_number: Option<String>,
    pub(crate) token_code: Option<String>,
}

impl Debug for AssumeRoleGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleGrant").finish_non_exhaustive()
    }
}

impl AssumeRoleGrant {
    /// Create a grant for one target role and auditable role session name.
    pub fn new(role_arn: impl Into<String>, role_session_name: impl Into<String>) -> Self {
        Self {
            role_arn: role_arn.into(),
            role_session_name: role_session_name.into(),
            external_id: None,
            tags: Vec::new(),
            policy: None,
            policy_arns: Vec::new(),
            serial_number: None,
            token_code: None,
        }
    }

    /// Set the external ID required by the target role's trust policy.
    pub fn with_external_id(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Set one inline JSON session policy.
    ///
    /// Session policies restrict the target role session. They cannot grant
    /// permissions beyond the target role's identity-based policy.
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    /// Set up to ten managed session policy ARNs.
    pub fn with_policy_arns(mut self, policy_arns: Vec<String>) -> Self {
        self.policy_arns = policy_arns;
        self
    }

    /// Set up to fifty session tags.
    pub fn with_tags(mut self, tags: Vec<(String, String)>) -> Self {
        self.tags = tags;
        self
    }

    /// Bind the MFA device serial number and current six-digit token code.
    pub fn with_mfa(
        mut self,
        serial_number: impl Into<String>,
        token_code: impl Into<String>,
    ) -> Self {
        self.serial_number = Some(serial_number.into());
        self.token_code = Some(token_code.into());
        self
    }

    fn validate(&self) -> Result<IamArn<'_>> {
        let role = validate_role_arn(&self.role_arn)?;
        validate_role_session_name(&self.role_session_name)?;

        if let Some(external_id) = &self.external_id {
            validate_external_id(external_id)?;
        }

        validate_session_policies(self.policy.as_deref(), &self.policy_arns, role)?;
        validate_tags(&self.tags)?;
        validate_mfa(self.serial_number.as_deref(), self.token_code.as_deref())?;
        Ok(role)
    }

    #[doc(hidden)]
    pub fn validate_for_region(&self, region: &str) -> Result<()> {
        let partition = partition_for_region(region)?;
        self.validate_for_partition(partition.id)
    }

    pub(crate) fn validate_for_partition(&self, expected_partition: &str) -> Result<()> {
        if self.validate()?.partition != expected_partition {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole role partition does not match the signing region",
            ));
        }
        Ok(())
    }
}

/// Shared, redacted AWS STS `AssumeRole` execution machinery.
///
/// This type is public only so the SigV4 service crate can share the exact
/// request, signing orchestration, response, expiration, and error path with
/// [`crate::AssumeRoleCredentialProvider`].
#[doc(hidden)]
pub struct AssumeRoleOperation {
    endpoint: String,
    parameters: String,
}

impl Debug for AssumeRoleOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleOperation")
            .finish_non_exhaustive()
    }
}

impl AssumeRoleOperation {
    /// Create a validated operation for a trusted STS endpoint authority.
    #[doc(hidden)]
    pub fn new(
        endpoint: impl Into<String>,
        grant: &AssumeRoleGrant,
        duration_seconds: Option<u32>,
    ) -> Result<Self> {
        let endpoint = endpoint.into();
        validate_sts_endpoint(&endpoint)?;
        validate_duration_seconds(duration_seconds)?;
        grant.validate()?;

        Ok(Self {
            parameters: build_assume_role_query(grant, duration_seconds),
            endpoint,
        })
    }

    /// Sign with the configured signer, send through `Context`, and parse the
    /// returned expiration-aware AWS credential.
    #[doc(hidden)]
    pub async fn execute(
        &self,
        ctx: &Context,
        sts_signer: &Signer<Credential>,
    ) -> Result<Credential> {
        let request = self.build_request()?;
        let (mut parts, body) = request.into_parts();
        sts_signer.sign(&mut parts, None).await.map_err(|err| {
            Error::new(err.kind(), "failed to sign AWS STS AssumeRole request")
                .set_retryable(err.is_retryable())
        })?;
        let request = http::Request::from_parts(parts, body);

        self.send(ctx, request).await
    }

    /// Build the unsigned request shared by fixed and explicit-source flows.
    #[doc(hidden)]
    pub fn build_request(&self) -> Result<http::Request<Bytes>> {
        let get_uri = format!("https://{}/?{}", self.endpoint, self.parameters);
        let (method, uri, body) = if get_uri.len() <= MAX_GET_URI_LENGTH {
            (http::Method::GET, get_uri, Bytes::new())
        } else {
            (
                http::Method::POST,
                format!("https://{}/", self.endpoint),
                Bytes::from(self.parameters.clone()),
            )
        };
        let payload_hash = hex_sha256(&body);

        http::Request::builder()
            .method(method)
            .uri(uri)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(X_AMZ_CONTENT_SHA_256, payload_hash)
            .body(body)
            .map_err(|_| Error::request_invalid("failed to build AWS STS AssumeRole request"))
    }

    /// Send an already signed request and parse its expiration-aware credential.
    #[doc(hidden)]
    pub async fn send(&self, ctx: &Context, request: http::Request<Bytes>) -> Result<Credential> {
        let response = ctx.http_send(request).await.map_err(|_| {
            Error::unexpected("failed to send AWS STS AssumeRole request").set_retryable(true)
        })?;
        parse_assume_role_response(response, Timestamp::now())
    }
}

/// Return the standard regional STS endpoint after validating the region.
#[doc(hidden)]
pub fn regional_sts_endpoint(region: &str, grant: &AssumeRoleGrant) -> Result<String> {
    grant.validate_for_region(region)?;
    sts_endpoint(Some(region), true)
}

fn build_assume_role_query(grant: &AssumeRoleGrant, duration_seconds: Option<u32>) -> String {
    let mut serializer = Serializer::new(String::new());
    serializer
        .append_pair("Action", "AssumeRole")
        .append_pair("RoleArn", &grant.role_arn)
        .append_pair("Version", "2011-06-15")
        .append_pair("RoleSessionName", &grant.role_session_name);

    if let Some(external_id) = &grant.external_id {
        serializer.append_pair("ExternalId", external_id);
    }
    if let Some(duration_seconds) = duration_seconds {
        serializer.append_pair("DurationSeconds", &duration_seconds.to_string());
    }
    if let Some(policy) = &grant.policy {
        serializer.append_pair("Policy", policy);
    }
    for (index, arn) in grant.policy_arns.iter().enumerate() {
        serializer.append_pair(&format!("PolicyArns.member.{}.arn", index + 1), arn);
    }
    for (index, (key, value)) in grant.tags.iter().enumerate() {
        let index = index + 1;
        serializer
            .append_pair(&format!("Tags.member.{index}.Key"), key)
            .append_pair(&format!("Tags.member.{index}.Value"), value);
    }
    if let (Some(serial_number), Some(token_code)) = (&grant.serial_number, &grant.token_code) {
        serializer
            .append_pair("SerialNumber", serial_number)
            .append_pair("TokenCode", token_code);
    }

    serializer.finish()
}

fn parse_assume_role_response(
    response: http::Response<Bytes>,
    response_time: Timestamp,
) -> Result<Credential> {
    let status = response.status();
    let body = response.into_body();
    let body = String::from_utf8_lossy(&body);

    if status != http::StatusCode::OK {
        return Err(parse_sts_error("AssumeRole", status, &body));
    }

    let response: AssumeRoleResponse = de::from_str(&body).map_err(|_| {
        Error::unexpected("failed to parse AWS STS AssumeRole response")
            .with_context(format!("response_length: {}", body.len()))
    })?;
    let response = response.result.credentials;
    if !(16..=128).contains(&response.access_key_id.chars().count())
        || !response.access_key_id.bytes().all(is_access_key_character)
        || response.secret_access_key.is_empty()
        || response.session_token.trim().is_empty()
        || http::HeaderValue::try_from(response.session_token.as_str()).is_err()
    {
        return Err(Error::unexpected(
            "AWS STS AssumeRole response contains malformed credentials",
        ));
    }

    let expires_at: Timestamp = response.expiration.parse().map_err(|_| {
        Error::unexpected("failed to parse AWS STS AssumeRole credential expiration")
    })?;
    let credential = Credential {
        access_key_id: response.access_key_id,
        secret_access_key: response.secret_access_key,
        session_token: Some(response.session_token),
        expires_in: Some(expires_at),
    };
    if !credential.is_valid_at(response_time) {
        return Err(Error::credential_invalid(
            "AWS STS AssumeRole returned credentials that are already expired",
        ));
    }

    Ok(credential)
}

fn validate_duration_seconds(duration_seconds: Option<u32>) -> Result<()> {
    if duration_seconds
        .is_some_and(|seconds| !(MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&seconds))
    {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole duration must be between 900 and 43200 seconds",
        ));
    }
    Ok(())
}

fn validate_sts_endpoint(endpoint: &str) -> Result<()> {
    let authority: http::uri::Authority = endpoint
        .parse()
        .map_err(|_| Error::config_invalid("AWS STS endpoint authority is invalid"))?;
    if authority.as_str() != endpoint
        || authority.host().is_empty()
        || authority.port().is_some()
        || endpoint.contains('@')
    {
        return Err(Error::config_invalid(
            "AWS STS endpoint authority is invalid",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IamArn<'a> {
    partition: &'a str,
    account: &'a str,
}

fn validate_role_arn(role_arn: &str) -> Result<IamArn<'_>> {
    let arn = validate_iam_arn(role_arn, "role/", 64)
        .ok_or_else(|| Error::request_invalid("AWS STS AssumeRole role ARN is invalid"))?;
    Ok(arn)
}

fn validate_policy_arn(policy_arn: &str) -> Result<IamArn<'_>> {
    let arn = validate_iam_arn(policy_arn, "policy/", 128).ok_or_else(|| {
        Error::request_invalid("AWS STS AssumeRole managed policy ARN is invalid")
    })?;
    Ok(arn)
}

fn validate_iam_arn<'a>(
    value: &'a str,
    resource_prefix: &str,
    maximum_name_length: usize,
) -> Option<IamArn<'a>> {
    if !(20..=2_048).contains(&value.chars().count()) {
        return None;
    }

    let mut fields = value.splitn(6, ':');
    let (Some(arn), Some(partition), Some(service), Some(region), Some(account), Some(resource)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return None;
    };

    if arn != "arn"
        || !matches!(
            partition,
            "aws"
                | "aws-cn"
                | "aws-eusc"
                | "aws-iso"
                | "aws-iso-b"
                | "aws-iso-e"
                | "aws-iso-f"
                | "aws-us-gov"
        )
        || service != "iam"
        || !region.is_empty()
        || account.len() != 12
        || !account.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let resource = resource.strip_prefix(resource_prefix)?;
    if !validate_iam_resource_path(resource, maximum_name_length) {
        return None;
    }

    Some(IamArn { partition, account })
}

fn validate_iam_resource_path(resource: &str, maximum_name_length: usize) -> bool {
    let name = match resource.rsplit_once('/') {
        Some((path, name)) => {
            if path.is_empty()
                || path.len() + 2 > 512
                || !path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            {
                return false;
            }
            name
        }
        None => resource,
    };

    (1..=maximum_name_length).contains(&name.chars().count())
        && name.chars().all(is_aws_word_character)
}

fn validate_role_session_name(role_session_name: &str) -> Result<()> {
    if !(2..=64).contains(&role_session_name.chars().count())
        || !role_session_name.chars().all(is_aws_word_character)
    {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole session name is invalid",
        ));
    }
    Ok(())
}

fn validate_external_id(external_id: &str) -> Result<()> {
    if !(2..=1_224).contains(&external_id.chars().count())
        || !external_id.chars().all(|character| {
            is_aws_word_character(character) || character == ':' || character == '/'
        })
    {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole external ID is invalid",
        ));
    }
    Ok(())
}

fn is_aws_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || "_+=,.@-".contains(character)
}

fn is_access_key_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn validate_session_policies(
    policy: Option<&str>,
    policy_arns: &[String],
    role: IamArn<'_>,
) -> Result<()> {
    if policy_arns.len() > MAX_POLICY_ARNS {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole accepts at most ten managed session policies",
        ));
    }

    for policy_arn in policy_arns {
        let policy = validate_policy_arn(policy_arn)?;
        if policy.partition != role.partition || policy.account != role.account {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole managed session policies must match the role partition and account",
            ));
        }
    }

    if let Some(policy) = policy {
        if policy.is_empty() || !policy.chars().all(is_session_policy_character) {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole inline session policy contains invalid characters",
            ));
        }
        let value: serde_json::Value = serde_json::from_str(policy).map_err(|_| {
            Error::request_invalid("AWS STS AssumeRole inline session policy must be valid JSON")
        })?;
        if !value.is_object() {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole inline session policy must be a JSON object",
            ));
        }
    }

    let plaintext_characters = policy.map_or(0, |value| value.chars().count())
        + policy_arns
            .iter()
            .map(|value| value.chars().count())
            .sum::<usize>();
    if plaintext_characters > MAX_POLICY_PLAINTEXT_CHARACTERS {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole session policy plaintext exceeds 2048 characters",
        ));
    }
    Ok(())
}

fn is_session_policy_character(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r') || (' '..='\u{00ff}').contains(&character)
}

fn validate_tags(tags: &[(String, String)]) -> Result<()> {
    if tags.len() > MAX_SESSION_TAGS {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole accepts at most fifty session tags",
        ));
    }

    let mut unique_keys = HashSet::with_capacity(tags.len());
    for (key, value) in tags {
        if !(1..=128).contains(&key.chars().count()) || !key.chars().all(is_session_tag_character) {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole session tag key is invalid",
            ));
        }
        if value.chars().count() > 256 || !value.chars().all(is_session_tag_character) {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole session tag value is invalid",
            ));
        }
        if !unique_keys.insert(key.to_lowercase()) {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole session tag keys are case-insensitively unique",
            ));
        }
    }
    Ok(())
}

fn is_session_tag_character(character: char) -> bool {
    character.is_alphanumeric()
        || character.is_whitespace() && !character.is_control()
        || "_:./=+-@".contains(character)
}

fn validate_mfa(serial_number: Option<&str>, token_code: Option<&str>) -> Result<()> {
    let (Some(serial_number), Some(token_code)) = (serial_number, token_code) else {
        if serial_number.is_some() || token_code.is_some() {
            return Err(Error::request_invalid(
                "AWS STS AssumeRole MFA serial number and token code must be provided together",
            ));
        }
        return Ok(());
    };

    if !(9..=256).contains(&serial_number.chars().count())
        || !serial_number.chars().all(|character| {
            is_aws_word_character(character) || character == '/' || character == ':'
        })
    {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole MFA serial number is invalid",
        ));
    }
    if token_code.len() != 6 || !token_code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::request_invalid(
            "AWS STS AssumeRole MFA token code must contain six digits",
        ));
    }
    Ok(())
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResponse {
    #[serde(rename = "AssumeRoleResult")]
    result: AssumeRoleResult,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResult {
    credentials: AssumeRoleCredentials,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_existing_assume_role_query_shape() {
        let grant = AssumeRoleGrant::new(
            "arn:aws:iam::123456789012:role/test-role",
            "reqsign",
        )
        .with_external_id("external/id")
        .with_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#,
        )
        .with_policy_arns(vec![
            "arn:aws:iam::123456789012:policy/ReadOnlyAccess".to_string(),
            "arn:aws:iam::123456789012:policy/ExamplePolicy".to_string(),
        ])
        .with_tags(vec![("Project".to_string(), "reqsign".to_string())])
        .with_mfa("arn:aws:iam::123456789012:mfa/user", "123456");

        let query = build_assume_role_query(&grant, Some(3_600));
        assert!(query.starts_with(
            "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ftest-role&Version=2011-06-15&RoleSessionName=reqsign"
        ));
        assert!(query.contains("ExternalId=external%2Fid"));
        assert!(query.contains("DurationSeconds=3600"));
        assert!(query.contains(
            "PolicyArns.member.1.arn=arn%3Aaws%3Aiam%3A%3A123456789012%3Apolicy%2FReadOnlyAccess"
        ));
        assert!(query.contains("Tags.member.1.Key=Project&Tags.member.1.Value=reqsign"));
        assert!(query.ends_with(
            "SerialNumber=arn%3Aaws%3Aiam%3A%3A123456789012%3Amfa%2Fuser&TokenCode=123456"
        ));
    }

    #[test]
    fn parses_expiration_aware_credentials_without_debuggable_response_secrets() {
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                br#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                    <AssumeRoleResult>
                        <Credentials>
                            <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
                            <SecretAccessKey>returned-secret</SecretAccessKey>
                            <SessionToken>returned-session-token</SessionToken>
                            <Expiration>2035-11-09T13:34:41Z</Expiration>
                        </Credentials>
                    </AssumeRoleResult>
                </AssumeRoleResponse>"#,
            ))
            .expect("response must build");
        let response_time = "2030-01-01T00:00:00Z"
            .parse()
            .expect("timestamp must parse");

        let credential =
            parse_assume_role_response(response, response_time).expect("response must parse");
        assert_eq!(credential.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(
            credential.session_token.as_deref(),
            Some("returned-session-token")
        );
        assert_eq!(
            credential.expires_in,
            Some(
                "2035-11-09T13:34:41Z"
                    .parse()
                    .expect("timestamp must parse")
            )
        );
    }

    #[test]
    fn validates_role_paths_policy_accounts_and_partitions() {
        let grant =
            AssumeRoleGrant::new("arn:aws:iam::123456789012:role/team!prod/Reader", "reqsign")
                .with_policy_arns(vec![
                    "arn:aws:iam::123456789012:policy/team!prod/Reader".to_string(),
                ]);
        grant
            .validate_for_region("us-east-1")
            .expect("valid IAM paths must be accepted");

        let cross_account =
            AssumeRoleGrant::new("arn:aws:iam::123456789012:role/Reader", "reqsign")
                .with_policy_arns(vec!["arn:aws:iam::210987654321:policy/Reader".to_string()]);
        assert_eq!(
            cross_account
                .validate_for_region("us-east-1")
                .expect_err("managed policies must match the role account")
                .kind(),
            reqsign_core::ErrorKind::RequestInvalid
        );

        let wrong_partition =
            AssumeRoleGrant::new("arn:aws-cn:iam::123456789012:role/Reader", "reqsign");
        assert_eq!(
            wrong_partition
                .validate_for_region("us-east-1")
                .expect_err("role and region partitions must match")
                .kind(),
            reqsign_core::ErrorKind::RequestInvalid
        );

        AssumeRoleGrant::new("arn:aws-eusc:iam::123456789012:role/Reader", "reqsign")
            .validate_for_region("eusc-de-east-1")
            .expect("EUSC role and region partitions must match");
    }

    #[test]
    fn uses_post_when_the_encoded_query_exceeds_the_get_limit() {
        let tags = (0..8)
            .map(|index| (format!("Tag{index}"), "x".repeat(256)))
            .collect();
        let grant = AssumeRoleGrant::new("arn:aws:iam::123456789012:role/Reader", "reqsign")
            .with_tags(tags);
        let operation =
            AssumeRoleOperation::new("sts.us-east-1.amazonaws.com", &grant, Some(3_600))
                .expect("large grant must be valid");
        let request = operation.build_request().expect("large request must build");

        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://sts.us-east-1.amazonaws.com/");
        assert!(request.uri().query().is_none());
        assert!(request.body().len() > MAX_GET_URI_LENGTH);
        assert_eq!(
            request
                .headers()
                .get(X_AMZ_CONTENT_SHA_256)
                .expect("payload hash must be present"),
            &hex_sha256(request.body())
        );
    }

    #[test]
    fn rejects_credentials_that_cannot_be_used_for_aws_signing() {
        let response = |access_key_id: &str, session_token: &str| {
            http::Response::builder()
                .status(http::StatusCode::OK)
                .body(Bytes::from(format!(
                    "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
                     <AccessKeyId>{access_key_id}</AccessKeyId>\
                     <SecretAccessKey>returned-secret</SecretAccessKey>\
                     <SessionToken>{session_token}</SessionToken>\
                     <Expiration>2035-11-09T13:34:41Z</Expiration>\
                     </Credentials></AssumeRoleResult></AssumeRoleResponse>"
                )))
                .expect("response must build")
        };
        let response_time = "2030-01-01T00:00:00Z"
            .parse()
            .expect("timestamp must parse");

        for malformed in [
            response("ASIAINVALID@OUTPUT1", "returned-token"),
            response("ASIAINVALIDOUTPUT01", "prefix&#10;suffix"),
        ] {
            assert_eq!(
                parse_assume_role_response(malformed, response_time)
                    .expect_err("unusable credentials must be rejected")
                    .kind(),
                reqsign_core::ErrorKind::Unexpected
            );
        }
    }
}
