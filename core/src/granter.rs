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

use crate::time::Timestamp;
use crate::{
    Context, Error, GrantCredential, GrantCredentialDyn, ProvideCredential, ProvideCredentialDyn,
    Result, SigningCredential,
};
use std::any::type_name;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Loads a source credential and grants a bounded service credential.
///
/// `Granter` caches only the source credential. Every call to [`Granter::grant`]
/// invokes the configured service granter and validates the returned credential
/// after all granting I/O has completed. Granted outputs are never cached or
/// written back into the source cache.
#[derive(Clone)]
pub struct Granter<K: SigningCredential> {
    ctx: Context,
    provider: Arc<dyn ProvideCredentialDyn<Credential = K>>,
    granter: Arc<dyn GrantCredentialDyn<Credential = K>>,
    credential: Arc<Mutex<Option<K>>>,
}

impl<K: SigningCredential> Debug for Granter<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Granter")
            .field("credential_type", &type_name::<K>())
            .finish_non_exhaustive()
    }
}

impl<K: SigningCredential> Granter<K> {
    /// Create a granter from a context, source provider, and bound granting operation.
    pub fn new(
        ctx: Context,
        provider: impl ProvideCredential<Credential = K>,
        granter: impl GrantCredential<Credential = K>,
    ) -> Self {
        Self {
            ctx,
            provider: Arc::new(provider),
            granter: Arc::new(granter),
            credential: Arc::new(Mutex::new(None)),
        }
    }

    /// Replace the context and create an isolated empty source credential cache.
    pub fn with_context(mut self, ctx: Context) -> Self {
        self.ctx = ctx;
        self.credential = Arc::new(Mutex::new(None));
        self
    }

    /// Replace the source provider and create an isolated empty source credential cache.
    pub fn with_credential_provider(
        mut self,
        provider: impl ProvideCredential<Credential = K>,
    ) -> Self {
        self.provider = Arc::new(provider);
        self.credential = Arc::new(Mutex::new(None));
        self
    }

    /// Replace the granting operation while retaining the shared source credential cache.
    ///
    /// The replacement operation must accept the same service credential family and
    /// must still validate the same concrete source credential variant before
    /// doing I/O. The service operation owns any service-specific intermediate
    /// cache; `Granter` does not transfer such state from the old operation.
    pub fn with_credential_granter(
        mut self,
        granter: impl GrantCredential<Credential = K>,
    ) -> Self {
        self.granter = Arc::new(granter);
        self
    }

    /// Grant a bounded service credential.
    ///
    /// Cached source credentials must be fresh according to
    /// [`SigningCredential::is_valid`] and usable through the service granter's
    /// required deadline. A refreshed source credential only needs to satisfy
    /// the exact deadline. Provider and granting errors are returned without
    /// retry or fallback. The granted result must own material independent from
    /// the cached source credential.
    pub async fn grant(&self, expires_in: Option<Duration>) -> Result<K> {
        let credential = self.credential.lock().expect("lock poisoned").clone();
        let credential = match credential {
            Some(credential)
                if credential.is_valid()
                    && credential.is_valid_at(
                        self.granter
                            .required_valid_until_dyn(&credential, expires_in),
                    ) =>
            {
                credential
            }
            _ => {
                let credential = self
                    .provider
                    .provide_credential_dyn(&self.ctx)
                    .await?
                    .ok_or_else(|| {
                        Error::credential_invalid("failed to load source credential")
                            .with_context(format!("credential_type: {}", type_name::<K>()))
                    })?;

                let required_until = self
                    .granter
                    .required_valid_until_dyn(&credential, expires_in);
                if !credential.is_valid_at(required_until) {
                    return Err(Error::credential_invalid(
                        "refreshed source credential expires before the granting deadline",
                    )
                    .with_context(format!("credential_type: {}", type_name::<K>()))
                    .with_context(format!("required_valid_until: {required_until}")));
                }

                *self.credential.lock().expect("lock poisoned") = Some(credential.clone());
                credential
            }
        };

        let granted = self
            .granter
            .grant_credential_dyn(&self.ctx, &credential, expires_in)
            .await?;
        let now = Timestamp::now();
        if !granted.is_valid_at(now) {
            return Err(
                Error::credential_invalid("granted credential is not currently usable")
                    .with_context(format!("credential_type: {}", type_name::<K>()))
                    .with_context(format!("validated_at: {now}")),
            );
        }

        Ok(granted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;
    use crate::{ErrorKind, GrantCredentialDyn, StaticEnv};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct TestCredential {
        generation: usize,
        fresh: bool,
        expires_at: Timestamp,
        secret: Arc<String>,
    }

    impl Debug for TestCredential {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestCredential")
                .field("generation", &self.generation)
                .field("secret", &self.secret)
                .finish()
        }
    }

    impl SigningCredential for TestCredential {
        fn is_valid(&self) -> bool {
            self.fresh && self.is_valid_at(Timestamp::now() + Duration::from_secs(20))
        }

        fn is_valid_at(&self, timestamp: Timestamp) -> bool {
            !self.secret.is_empty() && self.expires_at > timestamp
        }
    }

    #[derive(Clone)]
    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        secret: Arc<String>,
        expires_at: Timestamp,
        fresh: bool,
    }

    impl Debug for CountingProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CountingProvider")
                .field("secret", &self.secret)
                .finish()
        }
    }

    impl CountingProvider {
        fn new(secret: &str, expires_at: Timestamp) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    calls: calls.clone(),
                    secret: Arc::new(secret.to_string()),
                    expires_at,
                    fresh: true,
                },
                calls,
            )
        }

        fn with_fresh(mut self, fresh: bool) -> Self {
            self.fresh = fresh;
            self
        }
    }

    impl ProvideCredential for CountingProvider {
        type Credential = TestCredential;

        async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let generation = ctx
                .env_var("generation")
                .and_then(|value| value.parse().ok())
                .unwrap_or(call);
            Ok(Some(TestCredential {
                generation,
                fresh: self.fresh,
                expires_at: self.expires_at,
                secret: self.secret.clone(),
            }))
        }
    }

    #[derive(Clone)]
    struct CountingGranter {
        calls: Arc<AtomicUsize>,
        required_until: Timestamp,
        output_expires_at: Timestamp,
        secret: Arc<String>,
    }

    impl Debug for CountingGranter {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CountingGranter")
                .field("secret", &self.secret)
                .finish()
        }
    }

    impl CountingGranter {
        fn new(
            secret: &str,
            required_until: Timestamp,
            output_expires_at: Timestamp,
        ) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    calls: calls.clone(),
                    required_until,
                    output_expires_at,
                    secret: Arc::new(secret.to_string()),
                },
                calls,
            )
        }
    }

    impl GrantCredential for CountingGranter {
        type Credential = TestCredential;

        fn required_valid_until(
            &self,
            _credential: &Self::Credential,
            _expires_in: Option<Duration>,
        ) -> Timestamp {
            self.required_until
        }

        async fn grant_credential(
            &self,
            _ctx: &Context,
            credential: &Self::Credential,
            _expires_in: Option<Duration>,
        ) -> Result<Self::Credential> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(TestCredential {
                generation: credential.generation * 100 + call,
                fresh: true,
                expires_at: self.output_expires_at,
                secret: Arc::new(format!("granted-{call}")),
            })
        }
    }

    #[derive(Clone)]
    struct ErrorProvider {
        calls: Arc<AtomicUsize>,
    }

    impl Debug for ErrorProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ErrorProvider").finish_non_exhaustive()
        }
    }

    impl ProvideCredential for ErrorProvider {
        type Credential = TestCredential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::unexpected("source provider failed"))
        }
    }

    #[derive(Clone)]
    struct FailOnceGranter {
        calls: Arc<AtomicUsize>,
        required_until: Timestamp,
        output_expires_at: Timestamp,
    }

    impl Debug for FailOnceGranter {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FailOnceGranter").finish_non_exhaustive()
        }
    }

    impl GrantCredential for FailOnceGranter {
        type Credential = TestCredential;

        fn required_valid_until(
            &self,
            _credential: &Self::Credential,
            _expires_in: Option<Duration>,
        ) -> Timestamp {
            self.required_until
        }

        async fn grant_credential(
            &self,
            _ctx: &Context,
            credential: &Self::Credential,
            _expires_in: Option<Duration>,
        ) -> Result<Self::Credential> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == 1 {
                return Err(Error::unexpected("grant operation failed"));
            }
            Ok(TestCredential {
                generation: credential.generation * 100 + call,
                fresh: true,
                expires_at: self.output_expires_at,
                secret: Arc::new(format!("granted-{call}")),
            })
        }
    }

    fn future_timestamp(seconds: u64) -> Timestamp {
        Timestamp::now() + Duration::from_secs(seconds)
    }

    fn context_with_generation(generation: usize) -> Context {
        Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([("generation".to_string(), generation.to_string())]),
        })
    }

    #[test]
    fn dyn_bridge_forwards_deadline_and_grant() {
        let required_until = future_timestamp(60);
        let output_expires_at = future_timestamp(120);
        let (operation, calls) =
            CountingGranter::new("operation-secret", required_until, output_expires_at);
        let operation: Arc<dyn GrantCredentialDyn<Credential = TestCredential>> =
            Arc::new(operation);
        let credential = TestCredential {
            generation: 4,
            fresh: true,
            expires_at: future_timestamp(120),
            secret: Arc::new("source-secret".to_string()),
        };

        assert_eq!(
            operation.required_valid_until(&credential, None),
            required_until
        );
        let granted = futures::executor::block_on(operation.grant_credential(
            &Context::new(),
            &credential,
            None,
        ))
        .expect("dyn grant must succeed");

        assert_eq!(granted.generation, 401);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caches_only_source_and_shares_it_across_clones() {
        let (provider, provider_calls) =
            CountingProvider::new("provider-secret", future_timestamp(300));
        let source_secret = provider.secret.clone();
        let (operation, operation_calls) = CountingGranter::new(
            "operation-secret",
            future_timestamp(30),
            future_timestamp(120),
        );
        let granter = Granter::new(context_with_generation(7), provider, operation);

        let first = futures::executor::block_on(granter.grant(None)).expect("grant must succeed");
        let second =
            futures::executor::block_on(granter.clone().grant(None)).expect("grant must succeed");

        assert_eq!(first.generation, 701);
        assert_eq!(second.generation, 702);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation_calls.load(Ordering::SeqCst), 2);
        assert!(!Arc::ptr_eq(&first.secret, &source_secret));
        assert!(!Arc::ptr_eq(&second.secret, &source_secret));
    }

    #[test]
    fn replacements_follow_source_cache_isolation_contract() {
        let (provider, provider_calls) =
            CountingProvider::new("provider-secret", future_timestamp(300));
        let (operation, _) = CountingGranter::new(
            "operation-secret",
            future_timestamp(30),
            future_timestamp(120),
        );
        let granter = Granter::new(context_with_generation(1), provider, operation);
        futures::executor::block_on(granter.grant(None)).expect("initial grant must succeed");

        let (replacement_operation, _) = CountingGranter::new(
            "replacement-operation-secret",
            future_timestamp(30),
            future_timestamp(120),
        );
        let replacement = granter
            .clone()
            .with_credential_granter(replacement_operation);
        let granted = futures::executor::block_on(replacement.grant(None))
            .expect("operation replacement must reuse source");
        assert_eq!(granted.generation / 100, 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

        let isolated_context = granter.clone().with_context(context_with_generation(2));
        let granted = futures::executor::block_on(isolated_context.grant(None))
            .expect("context replacement must reload source");
        assert_eq!(granted.generation / 100, 2);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);

        let (replacement_provider, replacement_provider_calls) =
            CountingProvider::new("replacement-provider-secret", future_timestamp(300));
        let isolated_provider = granter.with_credential_provider(replacement_provider);
        futures::executor::block_on(isolated_provider.grant(None))
            .expect("provider replacement must reload source");
        assert_eq!(replacement_provider_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejects_unusable_source_without_caching_it() {
        let required_until = future_timestamp(120);
        let (provider, provider_calls) =
            CountingProvider::new("source-secret", future_timestamp(60));
        let (operation, operation_calls) =
            CountingGranter::new("operation-secret", required_until, future_timestamp(180));
        let granter = Granter::new(Context::new(), provider, operation);

        for _ in 0..2 {
            let err = futures::executor::block_on(granter.grant(None))
                .expect_err("short-lived source must be rejected");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            assert!(!format!("{err:?}").contains("source-secret"));
        }

        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refreshed_source_needs_exact_validity_but_is_not_reused_when_stale() {
        let (provider, provider_calls) =
            CountingProvider::new("source-secret", future_timestamp(300));
        let provider = provider.with_fresh(false);
        let (operation, operation_calls) = CountingGranter::new(
            "operation-secret",
            future_timestamp(30),
            future_timestamp(120),
        );
        let granter = Granter::new(Context::new(), provider, operation);

        futures::executor::block_on(granter.grant(None))
            .expect("exact-valid refreshed source must be accepted");
        futures::executor::block_on(granter.grant(None))
            .expect("stale cached source must be refreshed again");

        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn provider_and_grant_errors_do_not_create_output_cache_state() {
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let (operation, operation_calls) = CountingGranter::new(
            "operation-secret",
            future_timestamp(30),
            future_timestamp(120),
        );
        let provider_error = Granter::new(
            Context::new(),
            ErrorProvider {
                calls: provider_calls.clone(),
            },
            operation,
        );
        for _ in 0..2 {
            futures::executor::block_on(provider_error.grant(None))
                .expect_err("provider error must be returned");
        }
        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation_calls.load(Ordering::SeqCst), 0);

        let (provider, provider_calls) =
            CountingProvider::new("source-secret", future_timestamp(300));
        let grant_calls = Arc::new(AtomicUsize::new(0));
        let granter = Granter::new(
            Context::new(),
            provider,
            FailOnceGranter {
                calls: grant_calls.clone(),
                required_until: future_timestamp(30),
                output_expires_at: future_timestamp(120),
            },
        );
        futures::executor::block_on(granter.grant(None))
            .expect_err("first grant error must be returned");
        let output = futures::executor::block_on(granter.grant(None))
            .expect("second grant must execute again");

        assert_eq!(output.generation, 102);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(grant_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn rejects_output_that_is_expired_after_granting() {
        let (provider, _) = CountingProvider::new("source-secret", future_timestamp(120));
        let (operation, _) = CountingGranter::new(
            "operation-secret",
            future_timestamp(30),
            Timestamp::now() - Duration::from_secs(1),
        );
        let granter = Granter::new(Context::new(), provider, operation);

        let err = futures::executor::block_on(granter.grant(None))
            .expect_err("expired output must be rejected");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert!(!format!("{err:?}").contains("source-secret"));
        assert!(!format!("{err:?}").contains("operation-secret"));
    }

    #[test]
    fn debug_is_opaque_even_after_source_is_cached() {
        let (provider, _) = CountingProvider::new("provider-secret", future_timestamp(300));
        let (operation, _) = CountingGranter::new(
            "operation-secret",
            future_timestamp(30),
            future_timestamp(120),
        );
        let granter = Granter::new(Context::new(), provider, operation);
        futures::executor::block_on(granter.grant(None)).expect("grant must succeed");

        let debug = format!("{granter:?}");
        assert!(debug.starts_with("Granter"));
        assert!(!debug.contains("provider-secret"));
        assert!(!debug.contains("operation-secret"));
        assert!(!debug.contains("granted-"));
    }
}
