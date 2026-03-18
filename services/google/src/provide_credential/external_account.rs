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

use std::collections::BTreeMap;
use std::time::Duration;

use form_urlencoded::Serializer;
use http::header::{ACCEPT, CONTENT_TYPE};
use log::{debug, error};
use serde::{Deserialize, Serialize};

use crate::credential::{Credential, ExternalAccount, Token, external_account};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, Result};

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);
/// Default timeout declared by AIP-4117 for executable sources.
const DEFAULT_EXECUTABLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Gate required by AIP-4117 before executable sources may be used.
const GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES: &str = "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES";
const GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE: &str = "GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE";
const GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE: &str = "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE";
const GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL: &str =
    "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL";
const GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE: &str = "GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE";
const EXECUTABLE_RESPONSE_VERSION: u64 = 1;
const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";

/// STS token response.
#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

/// Impersonated token response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonatedTokenResponse {
    access_token: String,
    expire_time: String,
}

/// Impersonation request.
#[derive(Serialize)]
struct ImpersonationRequest {
    scope: Vec<String>,
    lifetime: String,
}

#[derive(Deserialize)]
struct ExecutableResponse {
    version: u64,
    success: bool,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    saml_response: Option<String>,
    #[serde(default)]
    expiration_time: Option<i64>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

struct ExecutableSubjectToken {
    token: String,
    expires_at: Option<Timestamp>,
}

/// ExternalAccountCredentialProvider exchanges external account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ExternalAccountCredentialProvider {
    external_account: ExternalAccount,
    scope: Option<String>,
}

impl ExternalAccountCredentialProvider {
    /// Create a new ExternalAccountCredentialProvider.
    pub fn new(external_account: ExternalAccount) -> Self {
        Self {
            external_account,
            scope: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    fn resolve_scope(&self, ctx: &Context) -> String {
        self.scope
            .clone()
            .or_else(|| ctx.env_var(crate::constants::GOOGLE_SCOPE))
            .unwrap_or_else(|| crate::constants::DEFAULT_SCOPE.to_string())
    }

    async fn load_oidc_token(&self, ctx: &Context) -> Result<String> {
        match &self.external_account.credential_source {
            external_account::Source::File(source) => {
                self.load_file_sourced_token(ctx, source).await
            }
            external_account::Source::Url(source) => self.load_url_sourced_token(ctx, source).await,
            external_account::Source::Executable(source) => {
                self.load_executable_sourced_token(ctx, source).await
            }
        }
    }

    async fn load_file_sourced_token(
        &self,
        ctx: &Context,
        source: &external_account::FileSource,
    ) -> Result<String> {
        let file = resolve_template(ctx, &source.file)?;
        debug!("loading OIDC token from file: {}", file);

        let content = ctx.file_read(&file).await?;
        let token = source.format.parse(&content)?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(reqsign_core::Error::credential_invalid(
                "OIDC token loaded from file is empty",
            ));
        }

        Ok(token)
    }

    async fn load_url_sourced_token(
        &self,
        ctx: &Context,
        source: &external_account::UrlSource,
    ) -> Result<String> {
        let url = resolve_template(ctx, &source.url)?;
        debug!("loading OIDC token from URL: {}", url);

        let mut req = http::Request::get(&url);

        // Add custom headers if any
        if let Some(headers) = &source.headers {
            for (key, value) in headers {
                let value = resolve_template(ctx, value)?;
                req = req.header(key, value);
            }
        }

        let resp = ctx
            .http_send(req.body(Vec::<u8>::new().into()).map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?)
            .await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {resp:?}");
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange OIDC token failed: {body}"
            )));
        }

        let token = source.format.parse(resp.body())?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(reqsign_core::Error::credential_invalid(
                "OIDC token loaded from URL is empty",
            ));
        }

        Ok(token)
    }

    fn resolved_subject_token_type(&self, ctx: &Context) -> Result<String> {
        resolve_template(ctx, &self.external_account.subject_token_type)
    }

    fn build_executable_env(
        &self,
        ctx: &Context,
        output_file: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        let mut envs = BTreeMap::new();
        envs.insert(
            GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE.to_string(),
            resolve_template(ctx, &self.external_account.audience)?,
        );
        envs.insert(
            GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE.to_string(),
            self.resolved_subject_token_type(ctx)?,
        );

        if let Some(url) = &self.external_account.service_account_impersonation_url {
            let url = resolve_template(ctx, url)?;
            let email = parse_impersonated_service_account_email(&url)?;
            envs.insert(
                GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL.to_string(),
                email,
            );
        }

        if let Some(path) = output_file {
            envs.insert(
                GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE.to_string(),
                path.to_string(),
            );
        }

        Ok(envs)
    }

    fn validate_executable_usage(
        &self,
        ctx: &Context,
        source: &external_account::ExecutableSource,
    ) -> Result<(String, Duration, Option<String>)> {
        if ctx
            .env_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES)
            .as_deref()
            != Some("1")
        {
            return Err(reqsign_core::Error::config_invalid(
                "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES must be set to 1 to use executable-sourced external accounts",
            ));
        }

        let command = resolve_template(ctx, &source.executable.command)?;
        let command = command.trim().to_string();
        if command.is_empty() {
            return Err(reqsign_core::Error::config_invalid(
                "credential_source.executable.command must not be empty",
            ));
        }

        let timeout = match source.executable.timeout_millis {
            Some(0) => {
                return Err(reqsign_core::Error::config_invalid(
                    "credential_source.executable.timeout_millis must be positive",
                ));
            }
            Some(v) => Duration::from_millis(v),
            None => DEFAULT_EXECUTABLE_TIMEOUT,
        };

        let output_file = source
            .executable
            .output_file
            .as_deref()
            .map(|v| resolve_template(ctx, v))
            .transpose()?;

        Ok((command, timeout, output_file))
    }

    fn parse_executable_response(
        &self,
        ctx: &Context,
        body: &[u8],
        require_expiration: bool,
        require_unexpired: bool,
    ) -> Result<ExecutableSubjectToken> {
        let response: ExecutableResponse = serde_json::from_slice(body).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse executable response").with_source(e)
        })?;

        if response.version != EXECUTABLE_RESPONSE_VERSION {
            return Err(reqsign_core::Error::credential_invalid(format!(
                "unsupported executable response version: {}",
                response.version
            )));
        }

        if !response.success {
            let message = match (response.code.as_deref(), response.message.as_deref()) {
                (Some(code), Some(message)) => {
                    format!("executable credential source failed with code {code}: {message}")
                }
                (None, Some(message)) => {
                    format!("executable credential source failed: {message}")
                }
                (Some(code), None) => {
                    format!("executable credential source failed with code {code}")
                }
                (None, None) => "executable credential source failed".to_string(),
            };
            return Err(reqsign_core::Error::credential_invalid(message));
        }

        let token_type = response.token_type.as_deref().ok_or_else(|| {
            reqsign_core::Error::credential_invalid(
                "successful executable response missing token_type",
            )
        })?;
        if !matches!(
            token_type,
            TOKEN_TYPE_JWT | TOKEN_TYPE_ID_TOKEN | TOKEN_TYPE_SAML2
        ) {
            return Err(reqsign_core::Error::credential_invalid(format!(
                "unsupported executable response token_type: {token_type}"
            )));
        }

        let expected = self.resolved_subject_token_type(ctx)?;
        if token_type != expected {
            return Err(reqsign_core::Error::credential_invalid(format!(
                "executable response token_type {token_type} does not match configured subject_token_type {expected}"
            )));
        }

        let token = if token_type == TOKEN_TYPE_SAML2 {
            response.saml_response.as_deref().ok_or_else(|| {
                reqsign_core::Error::credential_invalid(
                    "successful SAML executable response missing saml_response",
                )
            })?
        } else {
            response.id_token.as_deref().ok_or_else(|| {
                reqsign_core::Error::credential_invalid(
                    "successful executable response missing id_token",
                )
            })?
        };
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(reqsign_core::Error::credential_invalid(
                "executable response subject token is empty",
            ));
        }

        let expires_at = response
            .expiration_time
            .map(Timestamp::from_second)
            .transpose()?;

        if require_expiration && expires_at.is_none() {
            return Err(reqsign_core::Error::credential_invalid(
                "executable response missing expiration_time required by output_file",
            ));
        }

        if let Some(expires_at) = expires_at {
            if require_unexpired && Timestamp::now() >= expires_at {
                return Err(reqsign_core::Error::credential_invalid(
                    "executable response is expired",
                ));
            }
        }

        Ok(ExecutableSubjectToken { token, expires_at })
    }

    async fn load_executable_sourced_token(
        &self,
        ctx: &Context,
        source: &external_account::ExecutableSource,
    ) -> Result<String> {
        let (command, timeout, output_file) = self.validate_executable_usage(ctx, source)?;

        if let Some(path) = output_file.as_deref() {
            if let Ok(content) = ctx.file_read(path).await {
                debug!("loading executable credential response from output file: {path}");
                let subject = self.parse_executable_response(ctx, &content, true, false)?;
                if subject
                    .expires_at
                    .is_some_and(|expires_at| Timestamp::now() < expires_at)
                {
                    return Ok(subject.token);
                }
            }
        }

        let envs = self.build_executable_env(ctx, output_file.as_deref())?;
        debug!(
            "executing external account credential command with declared timeout {:?}",
            timeout
        );
        let output = execute_command_with_env(ctx, &command, &envs, timeout).await?;
        let parsed =
            self.parse_executable_response(ctx, &output.stdout, output_file.is_some(), true);
        let subject = if output.success() {
            parsed?
        } else {
            match parsed {
                Err(err) if err.kind() == reqsign_core::ErrorKind::CredentialInvalid => {
                    return Err(err);
                }
                Ok(_) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    let detail = if stderr.is_empty() {
                        format!("command exited with status {}", output.status)
                    } else {
                        format!("command exited with status {}: {}", output.status, stderr)
                    };
                    return Err(reqsign_core::Error::credential_invalid(format!(
                        "executable credential source failed: {detail}"
                    )));
                }
                Err(_) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    let detail = if stderr.is_empty() {
                        format!("command exited with status {}", output.status)
                    } else {
                        format!("command exited with status {}: {}", output.status, stderr)
                    };
                    return Err(reqsign_core::Error::credential_invalid(format!(
                        "executable credential source failed: {detail}"
                    )));
                }
            }
        };
        Ok(subject.token)
    }

    async fn exchange_sts_token(&self, ctx: &Context, oidc_token: &str) -> Result<Token> {
        debug!("exchanging OIDC token for STS access token");

        let scope = self.resolve_scope(ctx);
        let token_url = resolve_template(ctx, &self.external_account.token_url)?;
        let audience = resolve_template(ctx, &self.external_account.audience)?;
        let subject_token_type = resolve_template(ctx, &self.external_account.subject_token_type)?;

        let body = Serializer::new(String::new())
            .append_pair(
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            )
            .append_pair(
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            )
            .append_pair("audience", &audience)
            .append_pair("scope", &scope)
            .append_pair("subject_token", oidc_token)
            .append_pair("subject_token_type", &subject_token_type)
            .finish();

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(token_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {resp:?}");
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange token failed: {body}"
            )));
        }

        let token_resp: StsTokenResponse = serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse STS response").with_source(e)
        })?;

        let expires_at = token_resp
            .expires_in
            .map(|expires_in| Timestamp::now() + Duration::from_secs(expires_in));

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    async fn impersonate_service_account(
        &self,
        ctx: &Context,
        access_token: &str,
    ) -> Result<Option<Token>> {
        let Some(url) = &self.external_account.service_account_impersonation_url else {
            return Ok(None);
        };

        debug!("impersonating service account");

        let scope = self.resolve_scope(ctx);
        let lifetime = self
            .external_account
            .service_account_impersonation
            .as_ref()
            .and_then(|s| s.token_lifetime_seconds)
            .unwrap_or(MAX_LIFETIME.as_secs() as usize);

        let lifetime = if lifetime == 0 {
            return Err(reqsign_core::Error::config_invalid(
                "service_account_impersonation.token_lifetime_seconds must be positive",
            ));
        } else {
            lifetime.min(MAX_LIFETIME.as_secs() as usize)
        };

        let request = ImpersonationRequest {
            scope: vec![scope.clone()],
            lifetime: format!("{lifetime}s"),
        };

        let body = serde_json::to_vec(&request).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize request").with_source(e)
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(http::header::AUTHORIZATION, {
                let mut value: http::HeaderValue =
                    format!("Bearer {access_token}").parse().map_err(|e| {
                        reqsign_core::Error::unexpected("failed to parse header value")
                            .with_source(e)
                    })?;
                value.set_sensitive(true);
                value
            })
            .body(body.into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("impersonated token got unexpected response: {resp:?}");
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange impersonated token failed: {body}"
            )));
        }

        let token_resp: ImpersonatedTokenResponse =
            serde_json::from_slice(resp.body()).map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse impersonation response")
                    .with_source(e)
            })?;

        // Parse expire time from RFC3339 format
        Ok(Some(Token {
            access_token: token_resp.access_token,
            expires_at: token_resp.expire_time.parse().ok(),
        }))
    }
}
impl ProvideCredential for ExternalAccountCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Load OIDC token from source
        let oidc_token = self.load_oidc_token(ctx).await?;

        // Exchange for STS token
        let sts_token = self.exchange_sts_token(ctx, &oidc_token).await?;

        // Try to impersonate service account if configured
        let final_token = if let Some(token) = self
            .impersonate_service_account(ctx, &sts_token.access_token)
            .await?
        {
            token
        } else {
            sts_token
        };

        Ok(Some(Credential::with_token(final_token)))
    }
}

fn resolve_template(ctx: &Context, input: &str) -> Result<String> {
    // Google external account credentials commonly contain `${VAR}` placeholders that must be
    // substituted using process environment variables (e.g. GitHub Actions OIDC).
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    loop {
        let Some(start) = rest.find("${") else {
            out.push_str(rest);
            return Ok(out);
        };

        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];

        let Some(end) = rest.find('}') else {
            return Err(reqsign_core::Error::config_invalid(format!(
                "invalid template syntax in value: {input}"
            )));
        };

        let var = &rest[..end];
        rest = &rest[end + 1..];

        if var.is_empty() {
            return Err(reqsign_core::Error::config_invalid(format!(
                "empty template variable in value: {input}"
            )));
        }

        let value = ctx.env_var(var).filter(|v| !v.is_empty()).ok_or_else(|| {
            reqsign_core::Error::config_invalid(format!(
                "missing environment variable {var} required by template: {input}"
            ))
        })?;
        out.push_str(&value);
    }
}

fn parse_impersonated_service_account_email(url: &str) -> Result<String> {
    let marker = "/serviceAccounts/";
    let start = url.find(marker).ok_or_else(|| {
        reqsign_core::Error::config_invalid(format!(
            "service_account_impersonation_url missing {marker}: {url}"
        ))
    })?;
    let rest = &url[start + marker.len()..];
    let end = rest.find(':').ok_or_else(|| {
        reqsign_core::Error::config_invalid(format!(
            "service_account_impersonation_url missing action separator: {url}"
        ))
    })?;

    let email = percent_encoding::percent_decode_str(&rest[..end])
        .decode_utf8()
        .map_err(|e| {
            reqsign_core::Error::config_invalid(
                "service_account_impersonation_url contains invalid UTF-8 email",
            )
            .with_source(e)
        })?;
    if email.is_empty() {
        return Err(reqsign_core::Error::config_invalid(
            "service_account_impersonation_url resolved empty service account email",
        ));
    }

    Ok(email.into_owned())
}

async fn execute_command_with_env(
    ctx: &Context,
    command: &str,
    envs: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<reqsign_core::CommandOutput> {
    #[cfg(windows)]
    {
        let mut script = String::new();
        for (k, v) in envs {
            script.push_str("set \"");
            script.push_str(k);
            script.push('=');
            script.push_str(&quote_for_cmd_set(v));
            script.push_str("\" && ");
        }
        script.push_str(command);

        let args = ["/C", script.as_str()];
        tokio::time::timeout(timeout, ctx.command_execute("cmd", &args))
            .await
            .map_err(|_| {
                reqsign_core::Error::credential_invalid(format!(
                    "executable credential source timed out after {}ms",
                    timeout.as_millis()
                ))
            })?
    }

    #[cfg(not(windows))]
    {
        let mut script = String::new();
        for (k, v) in envs {
            script.push_str(k);
            script.push('=');
            script.push_str(&quote_for_sh(v));
            script.push(' ');
        }
        script.push_str("exec ");
        script.push_str(command);

        let args = ["-c", script.as_str()];
        tokio::time::timeout(timeout, ctx.command_execute("sh", &args))
            .await
            .map_err(|_| {
                reqsign_core::Error::credential_invalid(format!(
                    "executable credential source timed out after {}ms",
                    timeout.as_millis()
                ))
            })?
    }
}

#[cfg(windows)]
fn quote_for_cmd_set(value: &str) -> String {
    value.replace('^', "^^").replace('"', "^\"")
}

#[cfg(not(windows))]
fn quote_for_sh(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use reqsign_core::{CommandExecute, CommandOutput, Env, FileRead, HttpSend};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct MockEnv {
        vars: HashMap<String, String>,
    }

    impl MockEnv {
        fn with_var(mut self, k: &str, v: &str) -> Self {
            self.vars.insert(k.to_string(), v.to_string());
            self
        }
    }

    impl Env for MockEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }

        fn vars(&self) -> HashMap<String, String> {
            self.vars.clone()
        }

        fn home_dir(&self) -> Option<PathBuf> {
            None
        }
    }

    #[derive(Debug, Default)]
    struct MockFileRead {
        files: HashMap<String, Vec<u8>>,
    }

    impl MockFileRead {
        fn with_file(mut self, path: &str, content: impl Into<Vec<u8>>) -> Self {
            self.files.insert(path.to_string(), content.into());
            self
        }
    }
    impl FileRead for MockFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            self.files.get(path).cloned().ok_or_else(|| {
                reqsign_core::Error::config_invalid(format!("file not found: {path}"))
            })
        }
    }

    #[derive(Debug, Default)]
    struct RecordedCommand {
        program: Option<String>,
        args: Vec<String>,
    }

    #[derive(Clone, Debug)]
    struct MockCommandExecute {
        recorded: Arc<Mutex<RecordedCommand>>,
        output: CommandOutput,
    }

    impl MockCommandExecute {
        fn success(stdout: impl Into<Vec<u8>>) -> Self {
            Self {
                recorded: Arc::new(Mutex::new(RecordedCommand::default())),
                output: CommandOutput {
                    status: 0,
                    stdout: stdout.into(),
                    stderr: Vec::new(),
                },
            }
        }

        fn failure(stderr: impl Into<Vec<u8>>) -> Self {
            Self {
                recorded: Arc::new(Mutex::new(RecordedCommand::default())),
                output: CommandOutput {
                    status: 1,
                    stdout: Vec::new(),
                    stderr: stderr.into(),
                },
            }
        }

        fn with_status(
            status: i32,
            stdout: impl Into<Vec<u8>>,
            stderr: impl Into<Vec<u8>>,
        ) -> Self {
            Self {
                recorded: Arc::new(Mutex::new(RecordedCommand::default())),
                output: CommandOutput {
                    status,
                    stdout: stdout.into(),
                    stderr: stderr.into(),
                },
            }
        }
    }

    impl CommandExecute for MockCommandExecute {
        async fn command_execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
            let mut recorded = self.recorded.lock().expect("lock must succeed");
            recorded.program = Some(program.to_string());
            recorded.args = args.iter().map(|v| (*v).to_string()).collect();
            Ok(self.output.clone())
        }
    }

    #[derive(Debug)]
    struct CaptureStsHttpSend {
        expected_url: String,
        expected_scope: String,
        expected_subject_token: String,
        expected_audience: String,
        expected_subject_token_type: String,
        access_token: String,
    }
    impl HttpSend for CaptureStsHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(req.uri().to_string(), self.expected_url);
            assert_eq!(
                req.headers()
                    .get(CONTENT_TYPE)
                    .expect("content-type must exist")
                    .to_str()
                    .expect("content-type must be valid string"),
                "application/x-www-form-urlencoded"
            );

            let pairs: HashMap<String, String> = form_urlencoded::parse(req.body().as_ref())
                .into_owned()
                .collect();
            assert_eq!(
                pairs.get("grant_type").map(String::as_str),
                Some("urn:ietf:params:oauth:grant-type:token-exchange")
            );
            assert_eq!(
                pairs.get("requested_token_type").map(String::as_str),
                Some("urn:ietf:params:oauth:token-type:access_token")
            );
            assert_eq!(
                pairs.get("audience").map(String::as_str),
                Some(self.expected_audience.as_str())
            );
            assert_eq!(
                pairs.get("scope").map(String::as_str),
                Some(self.expected_scope.as_str())
            );
            assert_eq!(
                pairs.get("subject_token").map(String::as_str),
                Some(self.expected_subject_token.as_str())
            );
            assert_eq!(
                pairs.get("subject_token_type").map(String::as_str),
                Some(self.expected_subject_token_type.as_str())
            );

            let body = serde_json::json!({
                "access_token": &self.access_token,
                "expires_in": 3600
            });
            Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(serde_json::to_vec(&body).expect("json must encode").into())
                .expect("response must build"))
        }
    }

    #[derive(Debug)]
    struct UrlThenStsHttpSend {
        expected_get_url: String,
        expected_get_auth: String,
        expected_post_url: String,
        expected_subject_token: String,
    }
    impl HttpSend for UrlThenStsHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            match *req.method() {
                http::Method::GET => {
                    assert_eq!(req.uri().to_string(), self.expected_get_url);
                    assert_eq!(
                        req.headers()
                            .get(AUTHORIZATION)
                            .expect("authorization must exist")
                            .to_str()
                            .expect("authorization must be valid string"),
                        self.expected_get_auth
                    );
                    Ok(http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(b"test-oidc-token".as_slice().into())
                        .expect("response must build"))
                }
                http::Method::POST => {
                    assert_eq!(req.uri().to_string(), self.expected_post_url);
                    let pairs: HashMap<String, String> =
                        form_urlencoded::parse(req.body().as_ref())
                            .into_owned()
                            .collect();
                    assert_eq!(
                        pairs.get("subject_token").map(String::as_str),
                        Some(self.expected_subject_token.as_str())
                    );
                    Ok(http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(
                            br#"{"access_token":"final-token","expires_in":3600}"#
                                .as_slice()
                                .into(),
                        )
                        .expect("response must build"))
                }
                _ => unreachable!("unexpected method"),
            }
        }
    }

    #[test]
    fn test_resolve_template() {
        let ctx = Context::new().with_env(MockEnv::default().with_var("FOO", "bar"));
        assert_eq!(resolve_template(&ctx, "a${FOO}c").unwrap(), "abarc");
    }

    #[tokio::test]
    async fn test_external_account_file_source_uses_form_encoded_sts() -> Result<()> {
        let external_account = ExternalAccount {
            audience: "aud".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            credential_source: external_account::Source::File(external_account::FileSource {
                file: "/var/run/token".to_string(),
                format: external_account::Format::Text,
            }),
            service_account_impersonation_url: None,
            service_account_impersonation: None,
        };

        let http = CaptureStsHttpSend {
            expected_url: "https://sts.googleapis.com/v1/token".to_string(),
            expected_scope: "scope-a".to_string(),
            expected_subject_token: "test-oidc".to_string(),
            expected_audience: "aud".to_string(),
            expected_subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            access_token: "access-token".to_string(),
        };
        let fs = MockFileRead::default().with_file("/var/run/token", b"  test-oidc \n");
        let ctx = Context::new().with_http_send(http).with_file_read(fs);

        let provider =
            ExternalAccountCredentialProvider::new(external_account).with_scope("scope-a");
        let cred = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must exist");
        assert!(cred.has_token());
        assert!(cred.has_valid_token());
        Ok(())
    }

    #[tokio::test]
    async fn test_external_account_url_source_supports_env_templates() -> Result<()> {
        let external_account = ExternalAccount {
            audience: "aud".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            credential_source: external_account::Source::Url(external_account::UrlSource {
                url: "https://example.com/${PATH}".to_string(),
                format: external_account::Format::Text,
                headers: Some(HashMap::from([(
                    "Authorization".to_string(),
                    "Bearer ${TOKEN}".to_string(),
                )])),
            }),
            service_account_impersonation_url: None,
            service_account_impersonation: None,
        };

        let http = UrlThenStsHttpSend {
            expected_get_url: "https://example.com/oidc".to_string(),
            expected_get_auth: "Bearer secret".to_string(),
            expected_post_url: "https://sts.googleapis.com/v1/token".to_string(),
            expected_subject_token: "test-oidc-token".to_string(),
        };

        let env = MockEnv::default()
            .with_var("PATH", "oidc")
            .with_var("TOKEN", "secret");

        let ctx = Context::new().with_http_send(http).with_env(env);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let cred = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must exist");
        assert!(cred.has_token());
        assert!(cred.has_valid_token());
        Ok(())
    }

    fn executable_source(
        command: &str,
        output_file: Option<&str>,
    ) -> external_account::ExecutableSource {
        external_account::ExecutableSource {
            executable: external_account::ExecutableConfig {
                command: command.to_string(),
                timeout_millis: Some(5000),
                output_file: output_file.map(|v| v.to_string()),
            },
        }
    }

    fn executable_account(
        source: external_account::ExecutableSource,
        subject_token_type: &str,
    ) -> ExternalAccount {
        ExternalAccount {
            audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider".to_string(),
            subject_token_type: subject_token_type.to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            credential_source: external_account::Source::Executable(source),
            service_account_impersonation_url: Some(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test%40example.com:generateAccessToken"
                    .to_string(),
            ),
            service_account_impersonation: None,
        }
    }

    #[tokio::test]
    async fn test_executable_source_uses_cached_output_file() -> Result<()> {
        let external_account = executable_account(
            executable_source("/bin/example --flag", Some("/tmp/exec-cache.json")),
            TOKEN_TYPE_ID_TOKEN,
        );
        let cache = serde_json::json!({
            "version": 1,
            "success": true,
            "token_type": TOKEN_TYPE_ID_TOKEN,
            "id_token": "cached-token",
            "expiration_time": Timestamp::now().as_second() + 3600,
        });
        let fs = MockFileRead::default().with_file(
            "/tmp/exec-cache.json",
            serde_json::to_vec(&cache).expect("json"),
        );
        let ctx = Context::new()
            .with_file_read(fs)
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(MockCommandExecute::success(br#"{"unexpected":true}"#));

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let token = provider.load_oidc_token(&ctx).await?;
        assert_eq!(token, "cached-token");
        Ok(())
    }

    #[tokio::test]
    async fn test_executable_source_runs_command_with_required_env() -> Result<()> {
        let external_account = executable_account(
            executable_source(
                "/bin/example --arg=value",
                Some("/tmp/cache-${SUFFIX}.json"),
            ),
            TOKEN_TYPE_ID_TOKEN,
        );
        let command = MockCommandExecute::success(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "success": true,
                "token_type": TOKEN_TYPE_ID_TOKEN,
                "id_token": "exec-token",
                "expiration_time": Timestamp::now().as_second() + 3600,
            }))
            .expect("json"),
        );
        let recorded = command.recorded.clone();
        let env = MockEnv::default()
            .with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1")
            .with_var("SUFFIX", "value");
        let ctx = Context::new().with_env(env).with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let token = provider.load_oidc_token(&ctx).await?;
        assert_eq!(token, "exec-token");

        let recorded = recorded.lock().expect("lock must succeed");
        #[cfg(windows)]
        {
            assert_eq!(recorded.program.as_deref(), Some("cmd"));
            let script = recorded.args.get(1).expect("cmd script must exist");
            assert!(script.contains("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE="));
            assert!(script.contains("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE="));
            assert!(script.contains("GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL=test@example.com"));
            assert!(script.contains("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE=/tmp/cache-value.json"));
            assert!(script.contains("/bin/example --arg=value"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(recorded.program.as_deref(), Some("sh"));
            let script = recorded.args.get(1).expect("sh script must exist");
            assert!(script.contains("GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE='//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider'"));
            assert!(script.contains(
                "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE='urn:ietf:params:oauth:token-type:id_token'"
            ));
            assert!(
                script.contains("GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL='test@example.com'")
            );
            assert!(script.contains("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE='/tmp/cache-value.json'"));
            assert!(script.ends_with("exec /bin/example --arg=value"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_executable_source_requires_opt_in() {
        let external_account =
            executable_account(executable_source("/bin/example", None), TOKEN_TYPE_ID_TOKEN);
        let ctx = Context::new().with_command_execute(MockCommandExecute::success(Vec::new()));

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("missing opt-in must fail");
        assert!(
            err.to_string()
                .contains("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES")
        );
    }

    #[tokio::test]
    async fn test_executable_source_rejects_error_response() {
        let external_account =
            executable_account(executable_source("/bin/example", None), TOKEN_TYPE_ID_TOKEN);
        let command = MockCommandExecute::with_status(
            1,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "success": false,
                "code": "401",
                "message": "Caller not authorized.",
            }))
            .expect("json"),
            b"permission denied".as_slice(),
        );
        let ctx = Context::new()
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("error response must fail");
        assert!(err.to_string().contains("Caller not authorized"));
    }

    #[derive(Clone, Debug)]
    struct SlowCommandExecute;

    impl CommandExecute for SlowCommandExecute {
        async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(CommandOutput {
                status: 0,
                stdout: br#"{"version":1,"success":true,"token_type":"urn:ietf:params:oauth:token-type:id_token","id_token":"slow-token"}"#.to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn test_executable_source_honors_timeout() {
        let source = external_account::ExecutableSource {
            executable: external_account::ExecutableConfig {
                command: "/bin/example".to_string(),
                timeout_millis: Some(1),
                output_file: None,
            },
        };
        let external_account = executable_account(source, TOKEN_TYPE_ID_TOKEN);
        let ctx = Context::new()
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(SlowCommandExecute);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("slow executable must time out");
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_executable_source_rejects_non_zero_exit() {
        let external_account =
            executable_account(executable_source("/bin/example", None), TOKEN_TYPE_ID_TOKEN);
        let command = MockCommandExecute::failure("permission denied");
        let ctx = Context::new()
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("non-zero exit must fail");
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_executable_source_rejects_token_type_mismatch() {
        let external_account =
            executable_account(executable_source("/bin/example", None), TOKEN_TYPE_ID_TOKEN);
        let command = MockCommandExecute::success(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "success": true,
                "token_type": TOKEN_TYPE_SAML2,
                "saml_response": "response",
            }))
            .expect("json"),
        );
        let ctx = Context::new()
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("mismatched token type must fail");
        assert!(err.to_string().contains("does not match"));
    }

    #[tokio::test]
    async fn test_executable_source_requires_expiration_for_output_file() {
        let external_account = executable_account(
            executable_source("/bin/example", Some("/tmp/cache.json")),
            TOKEN_TYPE_ID_TOKEN,
        );
        let command = MockCommandExecute::success(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "success": true,
                "token_type": TOKEN_TYPE_ID_TOKEN,
                "id_token": "token",
            }))
            .expect("json"),
        );
        let ctx = Context::new()
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("missing expiration must fail");
        assert!(err.to_string().contains("expiration_time"));
    }

    #[tokio::test]
    async fn test_executable_source_rejects_expired_cached_output() -> Result<()> {
        let external_account = executable_account(
            executable_source("/bin/example", Some("/tmp/cache.json")),
            TOKEN_TYPE_ID_TOKEN,
        );
        let cache = serde_json::json!({
            "version": 1,
            "success": true,
            "token_type": TOKEN_TYPE_ID_TOKEN,
            "id_token": "cached-token",
            "expiration_time": Timestamp::now().as_second() - 1,
        });
        let fs = MockFileRead::default()
            .with_file("/tmp/cache.json", serde_json::to_vec(&cache).expect("json"));
        let command = MockCommandExecute::success(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "success": true,
                "token_type": TOKEN_TYPE_ID_TOKEN,
                "id_token": "fresh-token",
                "expiration_time": Timestamp::now().as_second() + 3600,
            }))
            .expect("json"),
        );
        let ctx = Context::new()
            .with_file_read(fs)
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let token = provider.load_oidc_token(&ctx).await?;
        assert_eq!(token, "fresh-token");
        Ok(())
    }

    #[tokio::test]
    async fn test_executable_source_rejects_invalid_cached_output() {
        let external_account = executable_account(
            executable_source("/bin/example", Some("/tmp/cache.json")),
            TOKEN_TYPE_ID_TOKEN,
        );
        let fs = MockFileRead::default().with_file("/tmp/cache.json", b"{invalid json");
        let command = MockCommandExecute::success(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "success": true,
                "token_type": TOKEN_TYPE_ID_TOKEN,
                "id_token": "fresh-token",
                "expiration_time": Timestamp::now().as_second() + 3600,
            }))
            .expect("json"),
        );
        let ctx = Context::new()
            .with_file_read(fs)
            .with_env(MockEnv::default().with_var(GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES, "1"))
            .with_command_execute(command);

        let provider = ExternalAccountCredentialProvider::new(external_account);
        let err = provider
            .load_oidc_token(&ctx)
            .await
            .expect_err("invalid cache must fail");
        assert!(
            err.to_string()
                .contains("failed to parse executable response")
        );
    }
}
