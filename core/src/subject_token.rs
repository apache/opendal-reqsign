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

use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;

use crate::time::Timestamp;
use crate::{BoxedFuture, Context, Error, MaybeSend, Result};

/// An opaque assertion that a service-specific credential provider can exchange.
///
/// Reqsign does not parse the token or infer its issuer, audience, or token type.
/// Those exchange semantics remain owned by the service-specific provider.
#[derive(Clone)]
pub struct SubjectToken {
    token: String,
    expires_at: Option<Timestamp>,
}

impl SubjectToken {
    /// Create a subject token with unknown expiration.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            expires_at: None,
        }
    }

    /// Set the absolute source expiration.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Return the opaque token value for service exchange.
    ///
    /// Callers must not include this value in logs, errors, cache keys, or
    /// provider identity strings.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Return the known absolute source expiration, if any.
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Validate that the token is non-empty and usable at `timestamp`.
    ///
    /// Unknown expiration remains subject to authoritative service validation.
    pub fn validate_at(&self, timestamp: Timestamp) -> Result<()> {
        if self.token.trim().is_empty() {
            return Err(Error::credential_invalid("subject token is empty"));
        }

        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= timestamp)
        {
            return Err(Error::credential_invalid("subject token has expired"));
        }

        Ok(())
    }
}

impl Debug for SubjectToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubjectToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl From<String> for SubjectToken {
    fn from(token: String) -> Self {
        Self::new(token)
    }
}

impl From<&str> for SubjectToken {
    fn from(token: &str) -> Self {
        Self::new(token)
    }
}

/// Supplies one explicitly selected subject token to a credential provider.
///
/// Implementations return an error instead of falling back to another token
/// source. Service-specific providers validate known expiration before exchange
/// I/O and retain ownership of all protocol configuration.
pub trait ProvideSubjectToken: Debug + Send + Sync + Unpin + 'static {
    /// Load the subject token selected by this provider.
    fn provide_subject_token(
        &self,
        ctx: &Context,
    ) -> impl Future<Output = Result<SubjectToken>> + MaybeSend;
}

/// Dyn-compatible version of [`ProvideSubjectToken`].
pub trait ProvideSubjectTokenDyn: Debug + Send + Sync + Unpin + 'static {
    /// Dyn version of [`ProvideSubjectToken::provide_subject_token`].
    fn provide_subject_token_dyn<'a>(
        &'a self,
        ctx: &'a Context,
    ) -> BoxedFuture<'a, Result<SubjectToken>>;
}

impl<T> ProvideSubjectTokenDyn for T
where
    T: ProvideSubjectToken + ?Sized,
{
    fn provide_subject_token_dyn<'a>(
        &'a self,
        ctx: &'a Context,
    ) -> BoxedFuture<'a, Result<SubjectToken>> {
        Box::pin(self.provide_subject_token(ctx))
    }
}

impl<T> ProvideSubjectToken for Arc<T>
where
    T: ProvideSubjectTokenDyn + ?Sized,
{
    async fn provide_subject_token(&self, ctx: &Context) -> Result<SubjectToken> {
        self.deref().provide_subject_token_dyn(ctx).await
    }
}

/// Supplies a caller-bound subject token without performing I/O.
///
/// Each independently constructed provider represents one caller identity.
#[derive(Clone)]
pub struct StaticSubjectTokenProvider {
    subject_token: SubjectToken,
}

impl StaticSubjectTokenProvider {
    /// Create a provider for a token with unknown expiration.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            subject_token: SubjectToken::new(token),
        }
    }

    /// Create a provider from a complete [`SubjectToken`].
    pub fn from_subject_token(subject_token: SubjectToken) -> Self {
        Self { subject_token }
    }

    /// Set the absolute source expiration.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.subject_token.expires_at = Some(expires_at);
        self
    }
}

impl Debug for StaticSubjectTokenProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticSubjectTokenProvider")
            .field("subject_token", &self.subject_token)
            .finish()
    }
}

impl ProvideSubjectToken for StaticSubjectTokenProvider {
    async fn provide_subject_token(&self, _ctx: &Context) -> Result<SubjectToken> {
        Ok(self.subject_token.clone())
    }
}

/// Loads a subject token from a caller-selected path through [`Context`].
#[derive(Clone, Debug)]
pub struct FileSubjectTokenProvider {
    path: String,
}

impl FileSubjectTokenProvider {
    /// Create a file-backed subject-token provider.
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl ProvideSubjectToken for FileSubjectTokenProvider {
    async fn provide_subject_token(&self, ctx: &Context) -> Result<SubjectToken> {
        let token = ctx.file_read_as_string(&self.path).await.map_err(|err| {
            Error::config_invalid("failed to read subject token file")
                .with_source(err)
                .with_context(format!("file: {}", self.path))
        })?;
        Ok(SubjectToken::new(token.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileRead, Result};

    const SECRET: &str = "header.payload.signature";

    #[derive(Debug)]
    struct TestFileRead;

    impl FileRead for TestFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            assert_eq!(path, "/subject-token");
            Ok(format!("  {SECRET}\n").into_bytes())
        }
    }

    #[test]
    fn debug_fully_redacts_subject_token() {
        let token = SubjectToken::new(SECRET);
        let provider = StaticSubjectTokenProvider::from_subject_token(token.clone());

        assert!(!format!("{token:?}").contains(SECRET));
        assert!(!format!("{provider:?}").contains(SECRET));
        assert!(format!("{token:?}").contains("[REDACTED]"));
    }

    #[test]
    fn validates_empty_and_expired_tokens() {
        let now = Timestamp::now();
        assert!(SubjectToken::new(" ").validate_at(now).is_err());
        assert!(
            SubjectToken::new(SECRET)
                .with_expires_at(now)
                .validate_at(now)
                .is_err()
        );
        assert!(SubjectToken::new(SECRET).validate_at(now).is_ok());
    }

    #[test]
    fn file_provider_trims_token() {
        let provider = FileSubjectTokenProvider::new("/subject-token");
        let ctx = Context::new().with_file_read(TestFileRead);
        let token = futures::executor::block_on(provider.provide_subject_token(&ctx))
            .expect("file provider must succeed");

        assert_eq!(token.token(), SECRET);
        assert_eq!(token.expires_at(), None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn provider_future_remains_send_on_native_targets() {
        fn assert_send<T: Send>(_future: T) {}

        let provider = StaticSubjectTokenProvider::new(SECRET);
        let ctx = Context::new();
        assert_send(provider.provide_subject_token(&ctx));
    }
}
