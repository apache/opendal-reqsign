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

use std::collections::VecDeque;
use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex as SyncMutex, Weak};
use std::time::Duration;

use aes_gcm::aead::{Aead, Generate, KeyInit, array::Array};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use form_urlencoded::Serializer;
use futures::lock::Mutex;
use http::header::{ACCEPT, CONTENT_TYPE};
use prost::Message;
use reqsign_core::hash::hex_sha256;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::CredentialAccessBoundaryGrant;
use super::sts::{
    ACCESS_TOKEN_TYPE, MAX_ACCESS_TOKEN_LIFETIME, STS_ENDPOINT, TOKEN_EXCHANGE_GRANT_TYPE,
    checked_expiration, sts_error,
};
use crate::constants::TOKEN_OPERATION_HEADROOM;
use crate::{Credential, Token};

const ACCESS_BOUNDARY_INTERMEDIARY_TOKEN_TYPE: &str =
    "urn:ietf:params:oauth:token-type:access_boundary_intermediary_token";
const TOKEN_EXCHANGE_HEADROOM: Duration = Duration::from_secs(10);
const MAX_MINIMUM_TOKEN_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60 - 1);
const DEFAULT_MINIMUM_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 60);
const INTERMEDIARY_CACHE_CAPACITY: usize = 64;
const MAX_SESSION_KEY_ENCODED_BYTES: usize = 64 * 1024;
const MAX_SESSION_KEYSET_KEYS: usize = 32;
const AES_GCM_KEY_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmKey";
const TINK_KEY_STATUS_ENABLED: i32 = 1;
const TINK_KEY_MATERIAL_SYMMETRIC: i32 = 1;
const TINK_PREFIX: i32 = 1;
const LEGACY_PREFIX: i32 = 2;
const RAW_PREFIX: i32 = 3;
const CRUNCHY_PREFIX: i32 = 4;
const AES_GCM_KEY_VERSION: u32 = 0;
const AES_GCM_NONCE_BYTES: usize = 12;

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    issued_token_type: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    access_boundary_session_key: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct IntermediaryCacheKey {
    endpoint: &'static str,
    source_authority: String,
    source_expires_at: Timestamp,
}

struct IntermediaryCredentials {
    access_token: Zeroizing<String>,
    expires_at: Timestamp,
    aead_key: TinkAesGcmKey,
}

impl Debug for IntermediaryCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntermediaryCredentials")
            .field("access_token", &"REDACTED")
            .field("expires_at", &self.expires_at)
            .field("aead_key", &"REDACTED")
            .finish()
    }
}

impl IntermediaryCredentials {
    fn covers(&self, now: Timestamp, minimum_lifetime: Duration) -> Result<bool> {
        let required_until = checked_expiration(now, minimum_lifetime)?;
        Ok(self.expires_at > required_until)
    }
}

#[derive(Default)]
struct IntermediaryCache {
    entries: VecDeque<(IntermediaryCacheKey, Arc<IntermediaryCredentials>)>,
}

impl IntermediaryCache {
    fn find(
        &mut self,
        key: &IntermediaryCacheKey,
        now: Timestamp,
        minimum_lifetime: Duration,
    ) -> Result<Option<Arc<IntermediaryCredentials>>> {
        self.entries
            .retain(|(_, credentials)| credentials.expires_at > now);
        let mut index = None;
        for (candidate_index, (candidate, credentials)) in self.entries.iter().enumerate() {
            if candidate == key && credentials.covers(now, minimum_lifetime)? {
                index = Some(candidate_index);
                break;
            }
        }
        let Some(index) = index else {
            return Ok(None);
        };

        let entry = self.entries.remove(index).ok_or_else(|| {
            Error::unexpected("client-side CAB intermediary cache is inconsistent")
        })?;
        let credentials = entry.1.clone();
        self.entries.push_back(entry);
        Ok(Some(credentials))
    }

    fn insert(
        &mut self,
        key: IntermediaryCacheKey,
        credentials: Arc<IntermediaryCredentials>,
        now: Timestamp,
    ) {
        self.entries
            .retain(|(candidate, cached)| candidate != &key && cached.expires_at > now);
        while self.entries.len() >= INTERMEDIARY_CACHE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((key, credentials));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Default)]
struct IntermediaryState {
    cache: Mutex<IntermediaryCache>,
    refresh_locks: RefreshLockRegistry,
}

impl IntermediaryState {
    fn refresh_lock(&self, key: &IntermediaryCacheKey) -> RefreshLockLease {
        let mut refresh_locks = self
            .refresh_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lock) = refresh_locks
            .iter()
            .find_map(|(candidate, lock)| (candidate == key).then(|| lock.upgrade()).flatten())
        {
            return RefreshLockLease {
                key: key.clone(),
                lock,
                registry: self.refresh_locks.clone(),
            };
        }

        let lock = Arc::new(Mutex::new(()));
        refresh_locks.push((key.clone(), Arc::downgrade(&lock)));
        RefreshLockLease {
            key: key.clone(),
            lock,
            registry: self.refresh_locks.clone(),
        }
    }

    #[cfg(test)]
    fn refresh_lock_len(&self) -> usize {
        self.refresh_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

struct RefreshLockLease {
    key: IntermediaryCacheKey,
    lock: Arc<Mutex<()>>,
    registry: RefreshLockRegistry,
}

type RefreshLockRegistry = Arc<SyncMutex<Vec<(IntermediaryCacheKey, Weak<Mutex<()>>)>>>;

impl Drop for RefreshLockLease {
    fn drop(&mut self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if Arc::strong_count(&self.lock) != 1 {
            return;
        }
        registry.retain(|(candidate, weak)| {
            candidate != &self.key
                || weak
                    .upgrade()
                    .is_none_or(|lock| !Arc::ptr_eq(&lock, &self.lock))
        });
    }
}

/// Exchanges source credentials for intermediary material and generates Google
/// Credential Access Boundary tokens locally.
///
/// The granter exchanges the source OAuth access token for an access-boundary
/// intermediary token and session key when the cached intermediary no longer
/// covers the requested lifetime, then creates every downscoped credential
/// locally. It does not spawn background work; the first caller that needs a
/// refresh performs the exchange. Refreshes for the same source authority,
/// expiration, and endpoint are serialized, while unrelated partitions can
/// proceed independently. After a failed refresh, the next waiting caller
/// retries instead of receiving cached failure state. Clones and values produced
/// with [`ClientSideCredentialAccessBoundaryGranter::with_grant`] share a bounded
/// intermediary cache partitioned by the source token authority, its declared
/// expiration, and the Google STS endpoint. Cancellation never installs a
/// partially fetched intermediary, and refresh-lock registry entries live only
/// while callers for that partition are active.
///
/// Each call performs fresh authenticated encryption and returns a distinct,
/// token-only [`Credential`]. The output expiration exactly matches the
/// intermediary expiration. The optional lifetime passed to
/// [`reqsign_core::Granter::grant`] is treated as the minimum remaining output
/// lifetime; it does not shorten the token. `None` uses the 30-minute default,
/// which can be changed with
/// [`ClientSideCredentialAccessBoundaryGranter::with_minimum_token_lifetime`].
///
/// The source must be a token-only Google OAuth access token for a service
/// account, with a known absolute expiration and the Cloud Platform scope.
/// Client-issued CAB tokens do not support user principals. STS rejects tokens
/// that already carry security attributes; the opaque source token does not
/// expose enough information to detect its principal, scope, or existing
/// attributes locally. An intermediary response without `expires_in`, which STS
/// uses for user access-token sources, is rejected.
///
/// Google currently returns a serialized Tink AEAD keyset as the session key.
/// This implementation accepts enabled primary AES-GCM keys and fails closed for
/// other key types.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter, time::Timestamp};
/// use reqsign_google::{
///     ClientSideCredentialAccessBoundaryGranter, CredentialAccessBoundaryGrant,
///     CredentialAccessBoundaryPermissions, TokenCredentialProvider,
/// };
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = TokenCredentialProvider::new("source-oauth-token")
///     .with_expires_at(Timestamp::now() + Duration::from_secs(3600));
/// let grant = CredentialAccessBoundaryGrant::for_object_prefix(
///     "example-bucket",
///     "customer-a/",
///     CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
/// );
/// // Supply a Context configured with an HttpSend implementation.
/// let context = Context::new();
/// let credential = Granter::new(
///     context,
///     source,
///     ClientSideCredentialAccessBoundaryGranter::new(grant),
/// )
/// .grant(None)
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ClientSideCredentialAccessBoundaryGranter {
    grant: CredentialAccessBoundaryGrant,
    minimum_token_lifetime: Duration,
    intermediary_state: Arc<IntermediaryState>,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
    #[cfg(test)]
    time_after_generation: Option<Timestamp>,
    #[cfg(test)]
    nonces: Option<Arc<std::sync::Mutex<VecDeque<[u8; AES_GCM_NONCE_BYTES]>>>>,
}

impl Debug for ClientSideCredentialAccessBoundaryGranter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSideCredentialAccessBoundaryGranter")
            .finish_non_exhaustive()
    }
}

impl ClientSideCredentialAccessBoundaryGranter {
    /// Create a granter for a bound Credential Access Boundary.
    pub fn new(grant: CredentialAccessBoundaryGrant) -> Self {
        Self {
            grant,
            minimum_token_lifetime: DEFAULT_MINIMUM_TOKEN_LIFETIME,
            intermediary_state: Arc::new(IntermediaryState::default()),
            #[cfg(test)]
            now: None,
            #[cfg(test)]
            time_after_request: None,
            #[cfg(test)]
            time_after_generation: None,
            #[cfg(test)]
            nonces: None,
        }
    }

    /// Replace the bound grant while retaining the shared intermediary cache.
    pub fn with_grant(mut self, grant: CredentialAccessBoundaryGrant) -> Self {
        self.grant = grant;
        self
    }

    /// Set the minimum remaining lifetime for outputs granted without an
    /// explicit per-call lifetime.
    ///
    /// The value is rounded up to a whole second and must then be greater than
    /// zero and strictly less than twelve hours. The largest accepted value is
    /// 11 hours, 59 minutes, and 59 seconds. Validation occurs before STS I/O.
    pub fn with_minimum_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.minimum_token_lifetime = lifetime;
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    fn time_after_request(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.time_after_request {
            return now;
        }
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    fn time_after_generation(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.time_after_generation {
            return now;
        }
        #[cfg(test)]
        if let Some(now) = self.time_after_request {
            return now;
        }
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    #[cfg(test)]
    fn with_time(mut self, now: Timestamp) -> Self {
        self.now = Some(now);
        self.time_after_request = Some(now);
        self.time_after_generation = Some(now);
        self
    }

    #[cfg(test)]
    fn with_time_after_request(mut self, now: Timestamp) -> Self {
        self.time_after_request = Some(now);
        self.time_after_generation = Some(now);
        self
    }

    #[cfg(test)]
    fn with_time_after_generation(mut self, now: Timestamp) -> Self {
        self.time_after_generation = Some(now);
        self
    }

    #[cfg(test)]
    fn with_nonces(mut self, nonces: impl IntoIterator<Item = [u8; AES_GCM_NONCE_BYTES]>) -> Self {
        self.nonces = Some(Arc::new(std::sync::Mutex::new(
            nonces.into_iter().collect(),
        )));
        self
    }

    fn effective_minimum_lifetime(&self, expires_in: Option<Duration>) -> Result<Duration> {
        let requested = expires_in.unwrap_or(self.minimum_token_lifetime);
        if requested.is_zero() {
            return Err(Error::request_invalid(
                "client-side credential access boundary minimum lifetime must be greater than zero and less than twelve hours",
            ));
        }
        let whole_seconds = requested
            .as_secs()
            .checked_add(u64::from(requested.subsec_nanos() != 0))
            .ok_or_else(|| {
                Error::request_invalid(
                    "client-side credential access boundary minimum lifetime must be greater than zero and less than twelve hours",
                )
        })?;
        let requested = Duration::from_secs(whole_seconds).max(TOKEN_OPERATION_HEADROOM);
        if requested > MAX_MINIMUM_TOKEN_LIFETIME {
            return Err(Error::request_invalid(
                "client-side credential access boundary minimum lifetime must be greater than zero and less than twelve hours",
            ));
        }
        Ok(requested)
    }

    fn source_token<'a>(
        &self,
        credential: &'a Credential,
        required_until: Timestamp,
    ) -> Result<&'a Token> {
        if credential.service_account.is_some() {
            return Err(Error::credential_invalid(
                "client-side credential access boundary requires a token-only source credential",
            ));
        }
        let token = credential.token.as_ref().ok_or_else(|| {
            Error::credential_invalid(
                "client-side credential access boundary requires an OAuth access token",
            )
        })?;
        if token.access_token.is_empty() {
            return Err(Error::credential_invalid(
                "client-side credential access boundary source access token is empty",
            ));
        }
        if token.expires_at.is_none() {
            return Err(Error::credential_invalid(
                "client-side credential access boundary source token expiration is required",
            ));
        }
        if !token.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "source OAuth access token expires before the client-side CAB intermediary exchange can complete",
            ));
        }
        Ok(token)
    }

    fn build_intermediary_request(
        &self,
        source_token: &str,
    ) -> Result<http::Request<bytes::Bytes>> {
        let body = Serializer::new(String::new())
            .append_pair("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
            .append_pair(
                "requested_token_type",
                ACCESS_BOUNDARY_INTERMEDIARY_TOKEN_TYPE,
            )
            .append_pair("subject_token_type", ACCESS_TOKEN_TYPE)
            .append_pair("subject_token", source_token)
            .finish();

        http::Request::builder()
            .method(http::Method::POST)
            .uri(STS_ENDPOINT)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())
            .map_err(|err| {
                Error::unexpected("failed to build client-side CAB intermediary request")
                    .with_source(err)
            })
    }

    fn parse_intermediary_response(
        &self,
        response: http::Response<bytes::Bytes>,
        source: &Token,
        response_time: Timestamp,
        minimum_lifetime: Duration,
    ) -> Result<IntermediaryCredentials> {
        if response.status() != http::StatusCode::OK {
            return Err(sts_error(response.status(), response.body()));
        }

        let mut token_response: StsTokenResponse = serde_json::from_slice(response.body())
            .map_err(|_| {
                Error::unexpected("failed to parse client-side CAB intermediary STS response")
            })?;
        if token_response.access_token.is_empty()
            || token_response.issued_token_type != ACCESS_BOUNDARY_INTERMEDIARY_TOKEN_TYPE
            || token_response.token_type != "Bearer"
        {
            return Err(Error::unexpected(
                "client-side CAB intermediary STS response is malformed",
            ));
        }
        let session_key = Zeroizing::new(
            token_response
                .access_boundary_session_key
                .take()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::unexpected("client-side CAB intermediary STS response is malformed")
                })?,
        );

        let source_expiration = source.expires_at.ok_or_else(|| {
            Error::credential_invalid(
                "client-side credential access boundary source token expiration is required",
            )
        })?;
        if source_expiration <= response_time {
            return Err(Error::credential_invalid(
                "source OAuth access token expired during the client-side CAB intermediary exchange",
            ));
        }

        let expires_in = token_response.expires_in.ok_or_else(|| {
            Error::credential_invalid(
                "client-side credential access boundary requires a service-account source with an explicit STS expiration",
            )
        })?;
        let expires_in = Duration::from_secs(expires_in);
        if expires_in.is_zero() || expires_in > MAX_ACCESS_TOKEN_LIFETIME {
            return Err(Error::unexpected(
                "client-side CAB intermediary STS expiration is invalid",
            ));
        }
        let expires_at = checked_expiration(response_time, expires_in)?.min(source_expiration);
        let required_until = checked_expiration(response_time, minimum_lifetime)?;
        if expires_at <= required_until {
            return Err(Error::credential_invalid(
                "client-side CAB intermediary token is not valid for the minimum output lifetime",
            ));
        }

        let aead_key = TinkAesGcmKey::parse(&session_key)?;
        Ok(IntermediaryCredentials {
            access_token: Zeroizing::new(token_response.access_token),
            expires_at,
            aead_key,
        })
    }

    fn cache_key(&self, source: &Token) -> Result<IntermediaryCacheKey> {
        let source_expires_at = source.expires_at.ok_or_else(|| {
            Error::credential_invalid(
                "client-side credential access boundary source token expiration is required",
            )
        })?;
        Ok(IntermediaryCacheKey {
            endpoint: STS_ENDPOINT,
            source_authority: hex_sha256(source.access_token.as_bytes()),
            source_expires_at,
        })
    }

    async fn intermediary_credentials(
        &self,
        ctx: &Context,
        source: &Token,
        minimum_lifetime: Duration,
    ) -> Result<Arc<IntermediaryCredentials>> {
        let cache_key = self.cache_key(source)?;
        let now = self.now();
        if let Some(credentials) =
            self.intermediary_state
                .cache
                .lock()
                .await
                .find(&cache_key, now, minimum_lifetime)?
        {
            return Ok(credentials);
        }

        let refresh_lock = self.intermediary_state.refresh_lock(&cache_key);
        let _refresh_guard = refresh_lock.lock.lock().await;
        let now = self.now();
        if let Some(credentials) =
            self.intermediary_state
                .cache
                .lock()
                .await
                .find(&cache_key, now, minimum_lifetime)?
        {
            return Ok(credentials);
        }

        let required_until = checked_expiration(
            now,
            minimum_lifetime.saturating_add(TOKEN_EXCHANGE_HEADROOM),
        )?;
        if !source.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "source OAuth access token expires before the client-side CAB intermediary exchange can complete",
            ));
        }

        let request = self.build_intermediary_request(&source.access_token)?;
        let response = ctx.http_send(request).await.map_err(|err| {
            Error::new(
                err.kind(),
                "client-side CAB intermediary STS request failed",
            )
            .set_retryable(err.is_retryable())
        })?;
        let response_time = self.time_after_request();
        let credentials = Arc::new(self.parse_intermediary_response(
            response,
            source,
            response_time,
            minimum_lifetime,
        )?);
        self.intermediary_state.cache.lock().await.insert(
            cache_key,
            credentials.clone(),
            response_time,
        );
        Ok(credentials)
    }

    fn next_nonce(&self) -> Result<[u8; AES_GCM_NONCE_BYTES]> {
        #[cfg(test)]
        if let Some(nonces) = &self.nonces {
            return nonces
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("test CAB nonce queue is empty"));
        }

        <[u8; AES_GCM_NONCE_BYTES]>::try_generate()
            .map_err(|_| Error::unexpected("failed to generate client-side CAB encryption nonce"))
    }

    #[cfg(test)]
    async fn cache_len(&self) -> usize {
        self.intermediary_state.cache.lock().await.len()
    }

    #[cfg(test)]
    fn refresh_lock_len(&self) -> usize {
        self.intermediary_state.refresh_lock_len()
    }
}

impl GrantCredential for ClientSideCredentialAccessBoundaryGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        let minimum_lifetime = self
            .effective_minimum_lifetime(expires_in)
            .unwrap_or(TOKEN_OPERATION_HEADROOM);
        self.now() + minimum_lifetime + TOKEN_EXCHANGE_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let minimum_lifetime = self.effective_minimum_lifetime(expires_in)?;
        let restrictions = serialize_restrictions(&self.grant)?;
        let required_until = checked_expiration(
            self.now(),
            minimum_lifetime.saturating_add(TOKEN_EXCHANGE_HEADROOM),
        )?;
        let source = self.source_token(credential, required_until)?;
        let intermediary = self
            .intermediary_credentials(ctx, source, minimum_lifetime)
            .await?;

        let nonce = self.next_nonce()?;
        let encrypted = intermediary.aead_key.encrypt(&restrictions, &nonce)?;
        let access_token = format!(
            "{}.{}",
            intermediary.access_token.as_str(),
            URL_SAFE_NO_PAD.encode(encrypted)
        );
        let output = Credential::with_token(Token {
            access_token,
            expires_at: Some(intermediary.expires_at),
        });

        let completed_at = self.time_after_generation();
        let required_until = checked_expiration(completed_at, minimum_lifetime)?;
        if !output.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "client-issued CAB token is not valid for the minimum output lifetime after generation",
            ));
        }
        Ok(output)
    }
}

struct TinkAesGcmKey {
    output_prefix: Vec<u8>,
    key_value: Zeroizing<Vec<u8>>,
}

impl Debug for TinkAesGcmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TinkAesGcmKey")
            .field("output_prefix", &"REDACTED")
            .field("key_value", &"REDACTED")
            .finish()
    }
}

impl TinkAesGcmKey {
    fn parse(session_key: &str) -> Result<Self> {
        if session_key.len() > MAX_SESSION_KEY_ENCODED_BYTES {
            return Err(Error::unexpected(
                "client-side CAB session key is malformed",
            ));
        }
        let decoded = STANDARD
            .decode(session_key)
            .map(Zeroizing::new)
            .map_err(|_| Error::unexpected("client-side CAB session key is malformed"))?;
        let mut keyset = TinkKeyset::decode(decoded.as_slice())
            .map_err(|_| Error::unexpected("client-side CAB session key is malformed"))?;
        if keyset.keys.is_empty() || keyset.keys.len() > MAX_SESSION_KEYSET_KEYS {
            zeroize_keyset(&mut keyset);
            return Err(Error::unexpected(
                "client-side CAB session key is malformed",
            ));
        }

        let primary_indexes = keyset
            .keys
            .iter()
            .enumerate()
            .filter_map(|(index, key)| (key.key_id == keyset.primary_key_id).then_some(index))
            .collect::<Vec<_>>();
        if primary_indexes.len() != 1 {
            zeroize_keyset(&mut keyset);
            return Err(Error::unexpected(
                "client-side CAB session key is malformed",
            ));
        }
        let mut primary = keyset.keys.swap_remove(primary_indexes[0]);
        zeroize_keyset(&mut keyset);
        if primary.status != TINK_KEY_STATUS_ENABLED {
            zeroize_key(&mut primary);
            return Err(Error::unexpected(
                "client-side CAB session key is malformed",
            ));
        }

        let output_prefix = match primary.output_prefix_type {
            TINK_PREFIX => {
                let mut prefix = Vec::with_capacity(5);
                prefix.push(1);
                prefix.extend_from_slice(&primary.key_id.to_be_bytes());
                prefix
            }
            LEGACY_PREFIX | CRUNCHY_PREFIX => {
                let mut prefix = Vec::with_capacity(5);
                prefix.push(0);
                prefix.extend_from_slice(&primary.key_id.to_be_bytes());
                prefix
            }
            RAW_PREFIX => Vec::new(),
            _ => {
                zeroize_key(&mut primary);
                return Err(Error::unexpected(
                    "client-side CAB session key is malformed",
                ));
            }
        };

        let mut key_data = primary
            .key_data
            .take()
            .ok_or_else(|| Error::unexpected("client-side CAB session key is malformed"))?;
        if key_data.type_url != AES_GCM_KEY_TYPE_URL
            || key_data.key_material_type != TINK_KEY_MATERIAL_SYMMETRIC
        {
            key_data.value.zeroize();
            return Err(Error::unexpected(
                "client-side CAB session key uses an unsupported AEAD key",
            ));
        }
        let aes_key = AesGcmKeyProto::decode(key_data.value.as_slice());
        key_data.value.zeroize();
        let mut aes_key =
            aes_key.map_err(|_| Error::unexpected("client-side CAB session key is malformed"))?;
        if aes_key.version != AES_GCM_KEY_VERSION || !matches!(aes_key.key_value.len(), 16 | 32) {
            aes_key.key_value.zeroize();
            return Err(Error::unexpected(
                "client-side CAB session key uses an unsupported AEAD key",
            ));
        }

        Ok(Self {
            output_prefix,
            key_value: Zeroizing::new(aes_key.key_value),
        })
    }

    fn encrypt(&self, restrictions: &[u8], nonce: &[u8; AES_GCM_NONCE_BYTES]) -> Result<Vec<u8>> {
        let ciphertext = match self.key_value.len() {
            16 => Aes128Gcm::new_from_slice(&self.key_value)
                .map_err(|_| Error::unexpected("failed to initialize client-side CAB encryption"))?
                .encrypt(&Array(*nonce), restrictions),
            32 => Aes256Gcm::new_from_slice(&self.key_value)
                .map_err(|_| Error::unexpected("failed to initialize client-side CAB encryption"))?
                .encrypt(&Array(*nonce), restrictions),
            _ => {
                return Err(Error::unexpected(
                    "client-side CAB session key uses an unsupported AEAD key",
                ));
            }
        }
        .map_err(|_| Error::unexpected("failed to encrypt client-side CAB restrictions"))?;

        let mut encrypted =
            Vec::with_capacity(self.output_prefix.len() + nonce.len() + ciphertext.len());
        encrypted.extend_from_slice(&self.output_prefix);
        encrypted.extend_from_slice(nonce);
        encrypted.extend_from_slice(&ciphertext);
        Ok(encrypted)
    }
}

fn zeroize_keyset(keyset: &mut TinkKeyset) {
    for key in &mut keyset.keys {
        zeroize_key(key);
    }
}

fn zeroize_key(key: &mut TinkKeysetKey) {
    if let Some(key_data) = &mut key.key_data {
        key_data.value.zeroize();
    }
}

fn serialize_restrictions(grant: &CredentialAccessBoundaryGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let rules = grant
        .rules
        .iter()
        .map(|rule| {
            let available_resource = format!(
                "//storage.googleapis.com/projects/_/buckets/{}",
                rule.bucket
            );
            let available_permissions = rule
                .permissions
                .roles()?
                .into_iter()
                .map(str::to_owned)
                .collect();
            let compiled_availability_condition = rule
                .object_prefix
                .as_deref()
                .map(|prefix| prefix_condition_expr(&rule.bucket, prefix));
            Ok(ClientSideAccessBoundaryRule {
                available_resource,
                available_permissions,
                compiled_availability_condition,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ClientSideAccessBoundary {
        access_boundary_rules: rules,
    }
    .encode_to_vec())
}

fn prefix_condition_expr(bucket: &str, prefix: &str) -> CelExpr {
    let object_resource_prefix = format!("projects/_/buckets/{bucket}/objects/{prefix}");
    let resource_starts_with = call(
        2,
        Some(select(3, ident(4, "resource"), "name")),
        "startsWith",
        vec![string_constant(5, object_resource_prefix)],
    );
    let list_prefix = call(
        6,
        Some(call(
            7,
            Some(ident(8, "api")),
            "getAttribute",
            vec![
                string_constant(9, "storage.googleapis.com/objectListPrefix"),
                string_constant(10, ""),
            ],
        )),
        "startsWith",
        vec![string_constant(11, prefix)],
    );
    call(1, None, "_||_", vec![resource_starts_with, list_prefix])
}

fn ident(id: i64, name: impl Into<String>) -> CelExpr {
    CelExpr {
        id,
        ident_expr: Some(CelIdent { name: name.into() }),
        ..Default::default()
    }
}

fn select(id: i64, operand: CelExpr, field: impl Into<String>) -> CelExpr {
    CelExpr {
        id,
        select_expr: Some(CelSelect {
            operand: Some(Box::new(operand)),
            field: field.into(),
            test_only: false,
        }),
        ..Default::default()
    }
}

fn call(
    id: i64,
    target: Option<CelExpr>,
    function: impl Into<String>,
    args: Vec<CelExpr>,
) -> CelExpr {
    CelExpr {
        id,
        call_expr: Some(CelCall {
            target: target.map(Box::new),
            function: function.into(),
            args,
        }),
        ..Default::default()
    }
}

fn string_constant(id: i64, value: impl Into<String>) -> CelExpr {
    CelExpr {
        id,
        const_expr: Some(CelConstant {
            string_value: Some(value.into()),
        }),
        ..Default::default()
    }
}

#[derive(Clone, PartialEq, Message)]
struct ClientSideAccessBoundary {
    #[prost(message, repeated, tag = "1")]
    access_boundary_rules: Vec<ClientSideAccessBoundaryRule>,
}

#[derive(Clone, PartialEq, Message)]
struct ClientSideAccessBoundaryRule {
    #[prost(string, tag = "1")]
    available_resource: String,
    #[prost(string, repeated, tag = "2")]
    available_permissions: Vec<String>,
    #[prost(message, optional, tag = "4")]
    compiled_availability_condition: Option<CelExpr>,
}

#[derive(Clone, PartialEq, Message)]
struct CelExpr {
    #[prost(int64, tag = "2")]
    id: i64,
    #[prost(message, optional, tag = "3")]
    const_expr: Option<CelConstant>,
    #[prost(message, optional, tag = "4")]
    ident_expr: Option<CelIdent>,
    #[prost(message, optional, tag = "5")]
    select_expr: Option<CelSelect>,
    #[prost(message, optional, tag = "6")]
    call_expr: Option<CelCall>,
}

#[derive(Clone, PartialEq, Message)]
struct CelIdent {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, Message)]
struct CelSelect {
    #[prost(message, optional, boxed, tag = "1")]
    operand: Option<Box<CelExpr>>,
    #[prost(string, tag = "2")]
    field: String,
    #[prost(bool, tag = "3")]
    test_only: bool,
}

#[derive(Clone, PartialEq, Message)]
struct CelCall {
    #[prost(message, optional, boxed, tag = "1")]
    target: Option<Box<CelExpr>>,
    #[prost(string, tag = "2")]
    function: String,
    #[prost(message, repeated, tag = "3")]
    args: Vec<CelExpr>,
}

#[derive(Clone, PartialEq, Message)]
struct CelConstant {
    #[prost(string, optional, tag = "6")]
    string_value: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct TinkKeyset {
    #[prost(uint32, tag = "1")]
    primary_key_id: u32,
    #[prost(message, repeated, tag = "2")]
    keys: Vec<TinkKeysetKey>,
}

#[derive(Clone, PartialEq, Message)]
struct TinkKeysetKey {
    #[prost(message, optional, tag = "1")]
    key_data: Option<TinkKeyData>,
    #[prost(int32, tag = "2")]
    status: i32,
    #[prost(uint32, tag = "3")]
    key_id: u32,
    #[prost(int32, tag = "4")]
    output_prefix_type: i32,
}

#[derive(Clone, PartialEq, Message)]
struct TinkKeyData {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
    #[prost(int32, tag = "3")]
    key_material_type: i32,
}

#[derive(Clone, PartialEq, Message)]
struct AesGcmKeyProto {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "3")]
    key_value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet, VecDeque};
    use std::fmt::Formatter;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use bytes::Bytes;
    use http::header::{AUTHORIZATION, HeaderMap};
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer, time::Timestamp};
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{CredentialAccessBoundaryPermissions, RequestSigner, ServiceAccount};

    // This is the access-boundary session key returned by Google's
    // MockStsTransport in google-auth-library-java. It is a serialized Tink
    // AES-256-GCM keyset and contains no production credential material.
    const GOOGLE_AUTH_LIBRARY_SESSION_KEY: &str = concat!(
        "CPaEhYsKEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQW",
        "VzR2NtS2V5EiIaIMx8syvGIGGu5yvrdq/I0Q9ZWIR1oqJXFnDFxHuwX4SEGAEQARj2hIWLCiAB"
    );

    #[derive(Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("CapturedRequest")
                .field("method", &self.method)
                .field("uri", &self.uri)
                .field("headers", &"REDACTED")
                .field("body", &"REDACTED")
                .finish()
        }
    }

    #[derive(Clone)]
    struct RequestGate {
        started: Arc<Semaphore>,
        release: Arc<Semaphore>,
    }

    impl RequestGate {
        async fn wait_started(&self) {
            self.started
                .acquire()
                .await
                .expect("started semaphore must remain open")
                .forget();
        }

        fn release_one(&self) {
            self.release.add_permits(1);
        }
    }

    #[derive(Clone)]
    struct MockHttpSend {
        calls: Arc<AtomicUsize>,
        requests: Arc<StdMutex<Vec<CapturedRequest>>>,
        responses: Arc<StdMutex<VecDeque<http::Response<Bytes>>>>,
        gate: Option<RequestGate>,
    }

    impl Debug for MockHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockHttpSend").finish_non_exhaustive()
        }
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(StdMutex::new(Vec::new())),
                responses: Arc::new(StdMutex::new(responses.into_iter().collect())),
                gate: None,
            }
        }

        fn gated(
            responses: impl IntoIterator<Item = http::Response<Bytes>>,
        ) -> (Self, RequestGate) {
            let gate = RequestGate {
                started: Arc::new(Semaphore::new(0)),
                release: Arc::new(Semaphore::new(0)),
            };
            let mut http = Self::new(responses);
            http.gate = Some(gate.clone());
            (http, gate)
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().expect("lock poisoned").clone()
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (parts, body) = request.into_parts();
            self.requests
                .lock()
                .expect("lock poisoned")
                .push(CapturedRequest {
                    method: parts.method,
                    uri: parts.uri,
                    headers: parts.headers,
                    body: body.to_vec(),
                });
            if let Some(gate) = &self.gate {
                gate.started.add_permits(1);
                gate.release
                    .acquire()
                    .await
                    .expect("release semaphore must remain open")
                    .forget();
            }
            self.responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock response queue is empty"))
        }
    }

    #[derive(Debug)]
    struct SecretTransportError;

    impl HttpSend for SecretTransportError {
        async fn http_send(&self, _request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            Err(
                Error::unexpected("transport retained subject_token=source-secret")
                    .set_retryable(true),
            )
        }
    }

    #[derive(Clone)]
    struct FixedCredentialProvider {
        credential: Credential,
        calls: Arc<AtomicUsize>,
    }

    impl Debug for FixedCredentialProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("FixedCredentialProvider")
                .finish_non_exhaustive()
        }
    }

    impl FixedCredentialProvider {
        fn new(credential: Credential) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    credential,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl ProvideCredential for FixedCredentialProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.credential.clone()))
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must be valid")
    }

    fn source_token(access_token: &str, expires_at: Option<Timestamp>) -> Credential {
        Credential::with_token(Token {
            access_token: access_token.to_string(),
            expires_at,
        })
    }

    fn viewer_bucket_grant() -> CredentialAccessBoundaryGrant {
        CredentialAccessBoundaryGrant::for_bucket(
            "example-bucket",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        )
    }

    fn response(status: http::StatusCode, body: impl Into<Bytes>) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(body.into())
            .expect("response must build")
    }

    fn success_response(
        intermediary_token: &str,
        expires_in: Option<u64>,
    ) -> http::Response<Bytes> {
        success_response_with_key(
            intermediary_token,
            GOOGLE_AUTH_LIBRARY_SESSION_KEY,
            expires_in,
        )
    }

    fn success_response_with_key(
        intermediary_token: &str,
        session_key: &str,
        expires_in: Option<u64>,
    ) -> http::Response<Bytes> {
        let mut value = serde_json::json!({
            "access_token": intermediary_token,
            "issued_token_type": ACCESS_BOUNDARY_INTERMEDIARY_TOKEN_TYPE,
            "token_type": "Bearer",
            "access_boundary_session_key": session_key,
        });
        if let Some(expires_in) = expires_in {
            value["expires_in"] = expires_in.into();
        }
        response(
            http::StatusCode::OK,
            serde_json::to_vec(&value).expect("response JSON must serialize"),
        )
    }

    fn form_fields(request: &CapturedRequest) -> BTreeMap<String, String> {
        form_urlencoded::parse(&request.body).into_owned().collect()
    }

    fn output_token(credential: &Credential) -> &Token {
        assert!(credential.service_account.is_none());
        credential
            .token
            .as_ref()
            .expect("granted credential must contain a token")
    }

    fn decrypt_restrictions(
        credential: &Credential,
    ) -> (String, [u8; AES_GCM_NONCE_BYTES], ClientSideAccessBoundary) {
        let token = &output_token(credential).access_token;
        let (intermediary, encoded_restrictions) = token
            .split_once('.')
            .expect("client-issued token must contain two parts");
        let encrypted = URL_SAFE_NO_PAD
            .decode(encoded_restrictions)
            .expect("restrictions must be unpadded base64url");
        let key = TinkAesGcmKey::parse(GOOGLE_AUTH_LIBRARY_SESSION_KEY)
            .expect("official session key must parse");
        assert!(encrypted.starts_with(&key.output_prefix));
        let nonce_offset = key.output_prefix.len();
        let nonce: [u8; AES_GCM_NONCE_BYTES] = encrypted
            [nonce_offset..nonce_offset + AES_GCM_NONCE_BYTES]
            .try_into()
            .expect("nonce must have the expected length");
        let ciphertext = &encrypted[nonce_offset + AES_GCM_NONCE_BYTES..];
        let plaintext = match key.key_value.len() {
            16 => Aes128Gcm::new_from_slice(&key.key_value)
                .expect("AES-128 key must initialize")
                .decrypt(&Array(nonce), ciphertext),
            32 => Aes256Gcm::new_from_slice(&key.key_value)
                .expect("AES-256 key must initialize")
                .decrypt(&Array(nonce), ciphertext),
            _ => panic!("unexpected test key length"),
        }
        .expect("restrictions must decrypt");
        let restrictions = ClientSideAccessBoundary::decode(plaintext.as_slice())
            .expect("restrictions must be a CAB protobuf");
        (intermediary.to_string(), nonce, restrictions)
    }

    fn encoded_tink_keyset(
        key_id: u32,
        status: i32,
        output_prefix_type: i32,
        type_url: &str,
        material_type: i32,
        version: u32,
        key_value: Vec<u8>,
    ) -> String {
        let value = AesGcmKeyProto { version, key_value }.encode_to_vec();
        STANDARD.encode(
            TinkKeyset {
                primary_key_id: key_id,
                keys: vec![TinkKeysetKey {
                    key_data: Some(TinkKeyData {
                        type_url: type_url.to_string(),
                        value,
                        key_material_type: material_type,
                    }),
                    status,
                    key_id,
                    output_prefix_type,
                }],
            }
            .encode_to_vec(),
        )
    }

    #[test]
    fn matches_google_auth_library_tink_aes_gcm_vector() {
        let key = TinkAesGcmKey::parse(GOOGLE_AUTH_LIBRARY_SESSION_KEY)
            .expect("official session key must parse");
        assert_eq!(
            key.output_prefix,
            [0x01, 0xa1, 0x61, 0x42, 0x76],
            "Tink prefix must contain the official primary key id"
        );
        assert_eq!(
            key.key_value.as_slice(),
            &[
                0xcc, 0x7c, 0xb3, 0x2b, 0xc6, 0x20, 0x61, 0xae, 0xe7, 0x2b, 0xeb, 0x76, 0xaf, 0xc8,
                0xd1, 0x0f, 0x59, 0x58, 0x84, 0x75, 0xa2, 0xa2, 0x57, 0x16, 0x70, 0xc5, 0xc4, 0x7b,
                0xb0, 0x5f, 0x84, 0x84,
            ]
        );

        let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let encrypted = key
            .encrypt(b"restriction", &nonce)
            .expect("vector must encrypt");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(encrypted),
            "AaFhQnYAAQIDBAUGBwgJCgvIc9p0EXthr8WYQl6sKvdE-kCKA-SIx7I0T1E"
        );
    }

    #[test]
    fn refresh_lock_registry_does_not_retain_sequential_partitions() {
        let state = IntermediaryState::default();
        let expires_at = timestamp("2030-01-01T01:00:00Z");
        for index in 0..1024 {
            let lease = state.refresh_lock(&IntermediaryCacheKey {
                endpoint: STS_ENDPOINT,
                source_authority: format!("source-{index}"),
                source_expires_at: expires_at,
            });
            assert_eq!(state.refresh_lock_len(), 1);
            drop(lease);
            assert_eq!(state.refresh_lock_len(), 0);
        }
    }

    #[tokio::test]
    async fn sends_exact_official_intermediary_exchange_shape() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source_expiry = timestamp("2030-01-01T02:00:00Z");
        let http = MockHttpSend::new([success_response("intermediary-token", Some(3600))]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[0; AES_GCM_NONCE_BYTES]]);
        let source = source_token("source+token/with=reserved", Some(source_expiry));

        operation
            .grant_credential(&Context::new().with_http_send(http.clone()), &source, None)
            .await
            .expect("client-side grant must succeed");

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, http::Method::POST);
        assert_eq!(request.uri, STS_ENDPOINT);
        assert_eq!(request.headers[ACCEPT], "application/json");
        assert_eq!(
            request.headers[CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        assert!(!request.headers.contains_key(AUTHORIZATION));
        assert_eq!(
            String::from_utf8(request.body.clone()).expect("form body must be UTF-8"),
            concat!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
                "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3A",
                "access_boundary_intermediary_token",
                "&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                "&subject_token=source%2Btoken%2Fwith%3Dreserved"
            )
        );
        let fields = form_fields(request);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields["grant_type"], TOKEN_EXCHANGE_GRANT_TYPE);
        assert_eq!(
            fields["requested_token_type"],
            ACCESS_BOUNDARY_INTERMEDIARY_TOKEN_TYPE
        );
        assert_eq!(fields["subject_token_type"], ACCESS_TOKEN_TYPE);
        assert_eq!(fields["subject_token"], "source+token/with=reserved");
        assert!(!fields.contains_key("options"));
        assert!(!fields.contains_key("audience"));
        assert!(!fields.contains_key("scope"));
    }

    #[tokio::test]
    async fn serializes_typed_prefix_grant_as_compiled_cel_protobuf() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "customer \"雪\"/",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER
                | CredentialAccessBoundaryPermissions::OBJECT_CREATOR,
        );
        let operation = ClientSideCredentialAccessBoundaryGranter::new(grant)
            .with_time(now)
            .with_nonces([[7; AES_GCM_NONCE_BYTES]]);
        let http = MockHttpSend::new([success_response("intermediary", Some(3600))]);
        let output = operation
            .grant_credential(
                &Context::new().with_http_send(http),
                &source_token("source", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect("client-side grant must succeed");

        let (intermediary, nonce, restrictions) = decrypt_restrictions(&output);
        assert_eq!(intermediary, "intermediary");
        assert_eq!(nonce, [7; AES_GCM_NONCE_BYTES]);
        assert_eq!(restrictions.access_boundary_rules.len(), 1);
        let rule = &restrictions.access_boundary_rules[0];
        assert_eq!(
            rule.available_resource,
            "//storage.googleapis.com/projects/_/buckets/example-bucket"
        );
        assert_eq!(
            rule.available_permissions,
            [
                "inRole:roles/storage.objectViewer",
                "inRole:roles/storage.objectCreator",
            ]
        );

        let root = rule
            .compiled_availability_condition
            .as_ref()
            .expect("prefix rule must have a compiled condition");
        let root_call = root.call_expr.as_ref().expect("root must be a call");
        assert_eq!(root_call.function, "_||_");
        assert!(root_call.target.is_none());
        assert_eq!(root_call.args.len(), 2);

        let resource_call = root_call.args[0]
            .call_expr
            .as_ref()
            .expect("first branch must be a call");
        assert_eq!(resource_call.function, "startsWith");
        let resource_select = resource_call
            .target
            .as_deref()
            .and_then(|expr| expr.select_expr.as_ref())
            .expect("resource startsWith target must be a select");
        assert_eq!(resource_select.field, "name");
        assert_eq!(
            resource_select
                .operand
                .as_deref()
                .and_then(|expr| expr.ident_expr.as_ref())
                .map(|ident| ident.name.as_str()),
            Some("resource")
        );
        assert_eq!(
            resource_call.args[0]
                .const_expr
                .as_ref()
                .and_then(|constant| constant.string_value.as_deref()),
            Some("projects/_/buckets/example-bucket/objects/customer \"雪\"/")
        );

        let list_call = root_call.args[1]
            .call_expr
            .as_ref()
            .expect("second branch must be a call");
        assert_eq!(list_call.function, "startsWith");
        let get_attribute = list_call
            .target
            .as_deref()
            .and_then(|expr| expr.call_expr.as_ref())
            .expect("list startsWith target must call getAttribute");
        assert_eq!(get_attribute.function, "getAttribute");
        assert_eq!(
            get_attribute
                .target
                .as_deref()
                .and_then(|expr| expr.ident_expr.as_ref())
                .map(|ident| ident.name.as_str()),
            Some("api")
        );
        assert_eq!(
            get_attribute.args[0]
                .const_expr
                .as_ref()
                .and_then(|constant| constant.string_value.as_deref()),
            Some("storage.googleapis.com/objectListPrefix")
        );
        assert_eq!(
            get_attribute.args[1]
                .const_expr
                .as_ref()
                .and_then(|constant| constant.string_value.as_deref()),
            Some("")
        );
        assert_eq!(
            list_call.args[0]
                .const_expr
                .as_ref()
                .and_then(|constant| constant.string_value.as_deref()),
            Some("customer \"雪\"/")
        );
    }

    #[tokio::test]
    async fn bucket_wide_and_multiple_rules_preserve_union_order() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let grant = viewer_bucket_grant().with_object_prefix_rule(
            "second-bucket",
            "tenant/",
            CredentialAccessBoundaryPermissions::OBJECT_USER,
        );
        let operation = ClientSideCredentialAccessBoundaryGranter::new(grant)
            .with_time(now)
            .with_nonces([[9; AES_GCM_NONCE_BYTES]]);
        let output = operation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "intermediary",
                    Some(3600),
                )])),
                &source_token("source", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect("client-side grant must succeed");

        let (_, _, restrictions) = decrypt_restrictions(&output);
        assert_eq!(restrictions.access_boundary_rules.len(), 2);
        assert_eq!(
            restrictions.access_boundary_rules[0].available_resource,
            "//storage.googleapis.com/projects/_/buckets/example-bucket"
        );
        assert!(
            restrictions.access_boundary_rules[0]
                .compiled_availability_condition
                .is_none()
        );
        assert_eq!(
            restrictions.access_boundary_rules[1].available_resource,
            "//storage.googleapis.com/projects/_/buckets/second-bucket"
        );
        assert!(
            restrictions.access_boundary_rules[1]
                .compiled_availability_condition
                .is_some()
        );
    }

    #[tokio::test]
    async fn rejects_invalid_grant_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ),
        )
        .with_time(now);
        let err = operation
            .grant_credential(
                &Context::new().with_http_send(http.clone()),
                &source_token("source", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect_err("invalid grant must fail");

        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_incompatible_sources_and_lifetimes_before_io() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([]);
        let ctx = Context::new().with_http_send(http.clone());
        let operation =
            ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let valid_token = Token {
            access_token: "source".to_string(),
            expires_at: Some(now + Duration::from_secs(2 * 60 * 60)),
        };
        let invalid_sources = [
            Credential::with_service_account(ServiceAccount {
                private_key: "private".to_string(),
                client_email: "service@example.com".to_string(),
            }),
            Credential {
                service_account: Some(ServiceAccount {
                    private_key: "private".to_string(),
                    client_email: "service@example.com".to_string(),
                }),
                token: Some(valid_token),
            },
            source_token("", Some(now + Duration::from_secs(2 * 60 * 60))),
            source_token("source", None),
            source_token("source", Some(now + DEFAULT_MINIMUM_TOKEN_LIFETIME)),
        ];
        for source in invalid_sources {
            let err = operation
                .grant_credential(&ctx, &source, None)
                .await
                .expect_err("incompatible source must fail");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        }

        let valid_source = source_token("source", Some(now + Duration::from_secs(13 * 60 * 60)));
        for lifetime in [
            Duration::ZERO,
            MAX_ACCESS_TOKEN_LIFETIME,
            MAX_ACCESS_TOKEN_LIFETIME + Duration::from_secs(1),
        ] {
            let err = operation
                .grant_credential(&ctx, &valid_source, Some(lifetime))
                .await
                .expect_err("invalid minimum lifetime must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn validates_exact_minimum_lifetime_boundary_after_rounding() {
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant());
        assert_eq!(
            operation
                .effective_minimum_lifetime(Some(MAX_MINIMUM_TOKEN_LIFETIME))
                .expect("the largest feasible whole-second lifetime must be accepted"),
            MAX_MINIMUM_TOKEN_LIFETIME
        );

        for lifetime in [
            MAX_MINIMUM_TOKEN_LIFETIME + Duration::from_nanos(1),
            MAX_ACCESS_TOKEN_LIFETIME,
            Duration::MAX,
        ] {
            let err = operation
                .effective_minimum_lifetime(Some(lifetime))
                .expect_err("a lifetime that rounds to twelve hours must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }
    }

    #[tokio::test]
    async fn accepts_maximum_intermediary_and_minimum_lifetime_boundaries() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:01Z");
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time)
            .with_nonces([[4; AES_GCM_NONCE_BYTES]]);
        let output = operation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "intermediary",
                    Some(MAX_ACCESS_TOKEN_LIFETIME.as_secs()),
                )])),
                &source_token(
                    "source",
                    Some(request_time + Duration::from_secs(13 * 60 * 60)),
                ),
                Some(MAX_MINIMUM_TOKEN_LIFETIME),
            )
            .await
            .expect("maximum feasible lifetime must succeed");

        assert_eq!(
            output_token(&output).expires_at,
            Some(timestamp("2030-01-01T12:00:01Z"))
        );
    }

    #[tokio::test]
    async fn anchors_clamps_and_requires_intermediary_expiration() {
        let request_time = timestamp("2030-01-01T00:00:00Z");
        let response_time = timestamp("2030-01-01T00:00:02Z");
        let source_expiry = timestamp("2030-01-01T02:00:00Z");
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(request_time)
            .with_time_after_request(response_time)
            .with_nonces([
                [1; AES_GCM_NONCE_BYTES],
                [2; AES_GCM_NONCE_BYTES],
                [3; AES_GCM_NONCE_BYTES],
            ]);
        let source = source_token("source", Some(source_expiry));

        let explicit = operation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "explicit",
                    Some(3600),
                )])),
                &source,
                None,
            )
            .await
            .expect("explicit expiration must succeed");
        assert_eq!(
            output_token(&explicit).expires_at,
            Some(timestamp("2030-01-01T01:00:02Z"))
        );

        let missing_expiration_operation =
            ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
                .with_time(request_time)
                .with_time_after_request(response_time);
        let err = missing_expiration_operation
            .grant_credential(
                &Context::new()
                    .with_http_send(MockHttpSend::new([success_response("inherited", None)])),
                &source,
                None,
            )
            .await
            .expect_err("client-issued CAB requires a service-account STS expiration");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);

        let clamped_operation =
            ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
                .with_time(request_time)
                .with_time_after_request(response_time)
                .with_nonces([[3; AES_GCM_NONCE_BYTES]]);
        let clamped = clamped_operation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "clamped",
                    Some(3 * 60 * 60),
                )])),
                &source,
                None,
            )
            .await
            .expect("STS expiration must clamp to source expiration");
        assert_eq!(output_token(&clamped).expires_at, Some(source_expiry));
    }

    #[tokio::test]
    async fn rejects_malformed_expiration_and_sts_responses() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));
        let malformed = [
            success_response("zero", Some(0)),
            success_response("too-long", Some(MAX_ACCESS_TOKEN_LIFETIME.as_secs() + 1)),
            response(
                http::StatusCode::OK,
                format!(
                    r#"{{"access_token":"negative","issued_token_type":"{ACCESS_BOUNDARY_INTERMEDIARY_TOKEN_TYPE}","token_type":"Bearer","expires_in":-1,"access_boundary_session_key":"{GOOGLE_AUTH_LIBRARY_SESSION_KEY}"}}"#
                ),
            ),
            response(
                http::StatusCode::OK,
                br#"{"access_token":"missing-fields"}"#.as_slice(),
            ),
            success_response_with_key("bad-key", "not base64!", Some(3600)),
        ];

        for response in malformed {
            let http = MockHttpSend::new([response]);
            let err = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
                .with_time(now)
                .grant_credential(&Context::new().with_http_send(http), &source, None)
                .await
                .expect_err("malformed response must fail");
            assert_eq!(err.kind(), ErrorKind::Unexpected);
            let debug = format!("{err:?}");
            assert!(!debug.contains("bad-key"));
            assert!(!debug.contains(GOOGLE_AUTH_LIBRARY_SESSION_KEY));
        }
    }

    #[tokio::test]
    async fn validates_tink_keyset_shape_and_algorithm() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));
        let keys = [
            encoded_tink_keyset(
                7,
                0,
                TINK_PREFIX,
                AES_GCM_KEY_TYPE_URL,
                TINK_KEY_MATERIAL_SYMMETRIC,
                0,
                vec![1; 32],
            ),
            encoded_tink_keyset(
                7,
                TINK_KEY_STATUS_ENABLED,
                0,
                AES_GCM_KEY_TYPE_URL,
                TINK_KEY_MATERIAL_SYMMETRIC,
                0,
                vec![1; 32],
            ),
            encoded_tink_keyset(
                7,
                TINK_KEY_STATUS_ENABLED,
                TINK_PREFIX,
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                TINK_KEY_MATERIAL_SYMMETRIC,
                0,
                vec![1; 32],
            ),
            encoded_tink_keyset(
                7,
                TINK_KEY_STATUS_ENABLED,
                TINK_PREFIX,
                AES_GCM_KEY_TYPE_URL,
                0,
                0,
                vec![1; 32],
            ),
            encoded_tink_keyset(
                7,
                TINK_KEY_STATUS_ENABLED,
                TINK_PREFIX,
                AES_GCM_KEY_TYPE_URL,
                TINK_KEY_MATERIAL_SYMMETRIC,
                1,
                vec![1; 32],
            ),
            encoded_tink_keyset(
                7,
                TINK_KEY_STATUS_ENABLED,
                TINK_PREFIX,
                AES_GCM_KEY_TYPE_URL,
                TINK_KEY_MATERIAL_SYMMETRIC,
                0,
                vec![1; 24],
            ),
        ];

        for key in keys {
            let err =
                ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
                    .with_time(now)
                    .grant_credential(
                        &Context::new().with_http_send(MockHttpSend::new([
                            success_response_with_key("intermediary", &key, Some(3600)),
                        ])),
                        &source,
                        None,
                    )
                    .await
                    .expect_err("invalid keyset must fail");
            assert_eq!(err.kind(), ErrorKind::Unexpected);
            assert!(!format!("{err:?}").contains(&key));
        }
    }

    #[tokio::test]
    async fn checks_post_io_and_post_generation_validity() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source_expiry = now + Duration::from_secs(60 * 60);

        let post_io = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_time_after_request(now + Duration::from_secs(31 * 60));
        let err = post_io
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "intermediary",
                    Some(3600),
                )])),
                &source_token("source", Some(source_expiry)),
                None,
            )
            .await
            .expect_err("intermediary must cover the minimum after I/O");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);

        let post_generation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_time_after_generation(now + Duration::from_secs(30 * 60))
            .with_nonces([[4; AES_GCM_NONCE_BYTES]]);
        let err = post_generation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "intermediary",
                    Some(60 * 60),
                )])),
                &source_token("source", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect_err("output must cover the minimum after local generation");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
    }

    #[tokio::test]
    async fn reuses_intermediary_but_never_caches_outputs() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([success_response("intermediary", Some(3600))]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[1; AES_GCM_NONCE_BYTES], [2; AES_GCM_NONCE_BYTES]]);
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));
        let ctx = Context::new().with_http_send(http.clone());

        let first = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("first grant must succeed");
        let second = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("second grant must succeed");

        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.cache_len().await, 1);
        assert_ne!(
            output_token(&first).access_token,
            output_token(&second).access_token
        );
        assert_eq!(
            output_token(&first).expires_at,
            output_token(&second).expires_at
        );
        assert_eq!(decrypt_restrictions(&first).1, [1; AES_GCM_NONCE_BYTES]);
        assert_eq!(decrypt_restrictions(&second).1, [2; AES_GCM_NONCE_BYTES]);
    }

    #[tokio::test]
    async fn refreshes_only_when_cached_intermediary_cannot_cover_minimum() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([
            success_response("intermediary-1", Some(3600)),
            success_response("intermediary-2", Some(3600)),
        ]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([
                [1; AES_GCM_NONCE_BYTES],
                [2; AES_GCM_NONCE_BYTES],
                [3; AES_GCM_NONCE_BYTES],
            ]);
        let source = source_token("source", Some(now + Duration::from_secs(3 * 60 * 60)));
        let ctx = Context::new().with_http_send(http.clone());

        let first = operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("initial grant must succeed");
        let still_fresh = operation
            .clone()
            .with_time(now + Duration::from_secs(20 * 60))
            .grant_credential(&ctx, &source, None)
            .await
            .expect("fresh intermediary must be reused");
        let refreshed = operation
            .clone()
            .with_time(now + Duration::from_secs(31 * 60))
            .grant_credential(&ctx, &source, None)
            .await
            .expect("near-expiry intermediary must refresh");

        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert_eq!(decrypt_restrictions(&first).0, "intermediary-1");
        assert_eq!(decrypt_restrictions(&still_fresh).0, "intermediary-1");
        assert_eq!(decrypt_restrictions(&refreshed).0, "intermediary-2");
    }

    #[tokio::test]
    async fn failed_refresh_never_returns_insufficient_cached_output() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([
            success_response("intermediary-1", Some(3600)),
            response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"backend_error","error_description":"do not return stale material"}"#,
            ),
        ]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[1; AES_GCM_NONCE_BYTES]]);
        let source = source_token("source", Some(now + Duration::from_secs(3 * 60 * 60)));
        let ctx = Context::new().with_http_send(http.clone());
        operation
            .grant_credential(&ctx, &source, None)
            .await
            .expect("initial grant must succeed");

        let err = operation
            .clone()
            .with_time(now + Duration::from_secs(31 * 60))
            .grant_credential(&ctx, &source, None)
            .await
            .expect_err("failed refresh must not return cached output");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert!(!format!("{err:?}").contains("do not return stale material"));
    }

    #[tokio::test]
    async fn partitions_and_bounds_intermediary_cache() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let responses = (0..INTERMEDIARY_CACHE_CAPACITY + 2)
            .map(|index| success_response(&format!("intermediary-{index}"), Some(3600)))
            .collect::<Vec<_>>();
        let http = MockHttpSend::new(responses);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces(
                (0..INTERMEDIARY_CACHE_CAPACITY + 2)
                    .map(|index| [index as u8; AES_GCM_NONCE_BYTES]),
            );
        let ctx = Context::new().with_http_send(http.clone());
        let source_expiry = now + Duration::from_secs(2 * 60 * 60);

        for index in 0..=INTERMEDIARY_CACHE_CAPACITY {
            operation
                .grant_credential(
                    &ctx,
                    &source_token(&format!("source-{index}"), Some(source_expiry)),
                    None,
                )
                .await
                .expect("partitioned grant must succeed");
        }
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            INTERMEDIARY_CACHE_CAPACITY + 1
        );
        assert_eq!(operation.cache_len().await, INTERMEDIARY_CACHE_CAPACITY);

        operation
            .grant_credential(&ctx, &source_token("source-0", Some(source_expiry)), None)
            .await
            .expect("oldest authority must be fetched after eviction");
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            INTERMEDIARY_CACHE_CAPACITY + 2
        );
        assert_eq!(operation.cache_len().await, INTERMEDIARY_CACHE_CAPACITY);

        let a = IntermediaryCacheKey {
            endpoint: STS_ENDPOINT,
            source_authority: "authority".to_string(),
            source_expires_at: source_expiry,
        };
        let b = IntermediaryCacheKey {
            endpoint: "https://sts.example.invalid/v1/token",
            source_authority: "authority".to_string(),
            source_expires_at: source_expiry,
        };
        assert!(a != b, "endpoint identity must partition cache keys");
    }

    #[tokio::test]
    async fn source_authority_partition_reuses_each_matching_entry() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([
            success_response("intermediary-a", Some(3600)),
            success_response("intermediary-b", Some(3600)),
        ]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([
                [1; AES_GCM_NONCE_BYTES],
                [2; AES_GCM_NONCE_BYTES],
                [3; AES_GCM_NONCE_BYTES],
            ]);
        let ctx = Context::new().with_http_send(http.clone());
        let expiry = now + Duration::from_secs(2 * 60 * 60);
        let source_a = source_token("source-a", Some(expiry));
        let source_b = source_token("source-b", Some(expiry));

        let first_a = operation
            .grant_credential(&ctx, &source_a, None)
            .await
            .expect("source A must succeed");
        let output_b = operation
            .grant_credential(&ctx, &source_b, None)
            .await
            .expect("source B must succeed");
        let second_a = operation
            .grant_credential(&ctx, &source_a, None)
            .await
            .expect("source A cache entry must be reused");

        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation.cache_len().await, 2);
        assert_eq!(decrypt_restrictions(&first_a).0, "intermediary-a");
        assert_eq!(decrypt_restrictions(&output_b).0, "intermediary-b");
        assert_eq!(decrypt_restrictions(&second_a).0, "intermediary-a");
    }

    #[tokio::test]
    async fn unrelated_source_partitions_refresh_independently() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (http, gate) = MockHttpSend::gated([
            success_response("intermediary-a", Some(3600)),
            success_response("intermediary-b", Some(3600)),
        ]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[1; AES_GCM_NONCE_BYTES], [2; AES_GCM_NONCE_BYTES]]);
        let ctx = Context::new().with_http_send(http.clone());
        let expiry = now + Duration::from_secs(2 * 60 * 60);

        let first = tokio::spawn({
            let operation = operation.clone();
            let ctx = ctx.clone();
            async move {
                operation
                    .grant_credential(&ctx, &source_token("source-a", Some(expiry)), None)
                    .await
            }
        });
        gate.wait_started().await;

        let second = tokio::spawn({
            let operation = operation.clone();
            let ctx = ctx.clone();
            async move {
                operation
                    .grant_credential(&ctx, &source_token("source-b", Some(expiry)), None)
                    .await
            }
        });
        let second_started =
            tokio::time::timeout(Duration::from_secs(1), gate.wait_started()).await;
        gate.release_one();
        gate.release_one();
        assert!(
            second_started.is_ok(),
            "an unrelated source partition must not wait for the first STS exchange"
        );

        first
            .await
            .expect("first grant task must not panic")
            .expect("first source partition must succeed");
        second
            .await
            .expect("second grant task must not panic")
            .expect("second source partition must succeed");
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation.cache_len().await, 2);
        assert_eq!(operation.refresh_lock_len(), 0);
    }

    #[tokio::test]
    async fn concurrent_grants_share_successful_intermediary_refresh() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (http, gate) = MockHttpSend::gated([success_response("intermediary", Some(3600))]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces((0..8).map(|index| [index; AES_GCM_NONCE_BYTES]));
        let ctx = Context::new().with_http_send(http.clone());
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let operation = operation.clone();
            let ctx = ctx.clone();
            let source = source.clone();
            tasks.push(tokio::spawn(async move {
                operation.grant_credential(&ctx, &source, None).await
            }));
        }

        gate.wait_started().await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        gate.release_one();

        let mut tokens = HashSet::new();
        for task in tasks {
            let output = task
                .await
                .expect("grant task must not panic")
                .expect("concurrent grant must succeed");
            tokens.insert(output_token(&output).access_token.clone());
        }
        assert_eq!(tokens.len(), 8);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.cache_len().await, 1);
        assert_eq!(operation.refresh_lock_len(), 0);
    }

    #[tokio::test]
    async fn waiter_retries_after_serialized_refresh_failure() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (http, gate) = MockHttpSend::gated([
            response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"backend_error"}"#,
            ),
            success_response("intermediary", Some(3600)),
        ]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[3; AES_GCM_NONCE_BYTES]]);
        let ctx = Context::new().with_http_send(http.clone());
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));

        let leader = tokio::spawn({
            let operation = operation.clone();
            let ctx = ctx.clone();
            let source = source.clone();
            async move { operation.grant_credential(&ctx, &source, None).await }
        });
        gate.wait_started().await;
        let waiter = tokio::spawn({
            let operation = operation.clone();
            let ctx = ctx.clone();
            async move { operation.grant_credential(&ctx, &source, None).await }
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);

        gate.release_one();
        let err = leader
            .await
            .expect("leader task must not panic")
            .expect_err("leader refresh must fail");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());

        gate.wait_started().await;
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        gate.release_one();
        let output = waiter
            .await
            .expect("waiter task must not panic")
            .expect("waiter must retry and succeed");
        assert_eq!(decrypt_restrictions(&output).0, "intermediary");
        assert_eq!(operation.cache_len().await, 1);
        assert_eq!(operation.refresh_lock_len(), 0);
    }

    #[tokio::test]
    async fn cancelled_refresh_releases_partition_lock_without_caching_partial_state() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let (http, gate) = MockHttpSend::gated([success_response("intermediary", Some(3600))]);
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[5; AES_GCM_NONCE_BYTES]]);
        let ctx = Context::new().with_http_send(http.clone());
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));

        let cancelled = {
            let operation = operation.clone();
            let ctx = ctx.clone();
            let source = source.clone();
            tokio::spawn(async move { operation.grant_credential(&ctx, &source, None).await })
        };
        gate.wait_started().await;
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("task must be cancelled")
                .is_cancelled()
        );
        assert_eq!(operation.cache_len().await, 0);
        assert_eq!(operation.refresh_lock_len(), 0);

        gate.release_one();
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            operation.grant_credential(&ctx, &source, None),
        )
        .await
        .expect("retry must not deadlock")
        .expect("retry after cancellation must succeed");
        assert_eq!(decrypt_restrictions(&output).0, "intermediary");
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation.cache_len().await, 1);
        assert_eq!(operation.refresh_lock_len(), 0);
    }

    #[tokio::test]
    async fn with_grant_shares_intermediary_for_distinct_authorization() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let http = MockHttpSend::new([success_response("intermediary", Some(3600))]);
        let bucket = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_time(now)
            .with_nonces([[1; AES_GCM_NONCE_BYTES], [2; AES_GCM_NONCE_BYTES]]);
        let prefix = bucket
            .clone()
            .with_grant(CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "tenant/",
                CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
            ));
        let ctx = Context::new().with_http_send(http.clone());
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));

        let bucket_output = bucket
            .grant_credential(&ctx, &source, None)
            .await
            .expect("bucket grant must succeed");
        let prefix_output = prefix
            .grant_credential(&ctx, &source, None)
            .await
            .expect("prefix grant must succeed");
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        assert!(
            decrypt_restrictions(&bucket_output).2.access_boundary_rules[0]
                .compiled_availability_condition
                .is_none()
        );
        assert!(
            decrypt_restrictions(&prefix_output).2.access_boundary_rules[0]
                .compiled_availability_condition
                .is_some()
        );
    }

    #[tokio::test]
    async fn granter_lifecycle_caches_source_and_intermediary_but_not_outputs() {
        let now = Timestamp::now();
        let source = source_token("source", Some(now + Duration::from_secs(2 * 60 * 60)));
        let (provider, provider_calls) = FixedCredentialProvider::new(source);
        let http = MockHttpSend::new([success_response("intermediary", Some(3600))]);
        let granter = Granter::new(
            Context::new().with_http_send(http.clone()),
            provider,
            ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
                .with_nonces([[1; AES_GCM_NONCE_BYTES], [2; AES_GCM_NONCE_BYTES]]),
        );

        let first = granter.grant(None).await.expect("first grant must succeed");
        let second = granter
            .grant(None)
            .await
            .expect("second grant must succeed");
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
        assert_ne!(
            output_token(&first).access_token,
            output_token(&second).access_token
        );
    }

    #[tokio::test]
    async fn generated_token_is_consumed_by_existing_google_signer() {
        let now = Timestamp::now();
        let operation = ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant())
            .with_nonces([[8; AES_GCM_NONCE_BYTES]]);
        let output = operation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([success_response(
                    "intermediary",
                    Some(3600),
                )])),
                &source_token("source", Some(now + Duration::from_secs(2 * 60 * 60))),
                None,
            )
            .await
            .expect("client-side grant must succeed");
        let expected = format!("Bearer {}", output_token(&output).access_token);
        let (provider, _) = FixedCredentialProvider::new(output);
        let signer = Signer::new(Context::new(), provider, RequestSigner::new("storage"));
        let mut parts =
            http::Request::get("https://storage.googleapis.com/example-bucket/customer/object")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;

        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume client-issued CAB token");
        assert_eq!(parts.headers[AUTHORIZATION], expected);
        assert!(parts.headers[AUTHORIZATION].is_sensitive());
    }

    #[tokio::test]
    async fn sts_and_transport_errors_are_semantic_and_redacted() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let source = source_token(
            "source-secret",
            Some(now + Duration::from_secs(2 * 60 * 60)),
        );
        let operation =
            ClientSideCredentialAccessBoundaryGranter::new(viewer_bucket_grant()).with_time(now);
        let err = operation
            .grant_credential(
                &Context::new().with_http_send(MockHttpSend::new([response(
                    http::StatusCode::BAD_REQUEST,
                    r#"{"error":"invalid_grant","error_description":"source-secret raw-response-secret"}"#,
                )])),
                &source,
                None,
            )
            .await
            .expect_err("STS error must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert!(format!("{err:?}").contains("invalid_grant"));
        assert!(!format!("{err:?}").contains("source-secret"));
        assert!(!format!("{err:?}").contains("raw-response-secret"));

        let err = operation
            .grant_credential(
                &Context::new().with_http_send(SecretTransportError),
                &source,
                None,
            )
            .await
            .expect_err("transport error must fail");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.is_retryable());
        assert!(!format!("{err:?}").contains("source-secret"));
        assert!(!format!("{err:?}").contains("transport retained"));
    }

    #[tokio::test]
    async fn debug_redacts_grant_request_and_all_credential_material() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "sensitive-bucket",
            "sensitive/prefix",
            CredentialAccessBoundaryPermissions::OBJECT_ADMIN,
        );
        let operation = ClientSideCredentialAccessBoundaryGranter::new(grant.clone())
            .with_time(now)
            .with_nonces([[6; AES_GCM_NONCE_BYTES]]);
        let source = source_token(
            "source-secret",
            Some(now + Duration::from_secs(2 * 60 * 60)),
        );
        let http = MockHttpSend::new([success_response("intermediary-secret", Some(3600))]);
        let output = operation
            .grant_credential(&Context::new().with_http_send(http.clone()), &source, None)
            .await
            .expect("client-side grant must succeed");
        let request = http
            .requests()
            .into_iter()
            .next()
            .expect("request must be captured");
        let key =
            TinkAesGcmKey::parse(GOOGLE_AUTH_LIBRARY_SESSION_KEY).expect("official key must parse");

        for (debug, secret) in [
            (format!("{grant:?}"), "sensitive-bucket"),
            (format!("{grant:?}"), "sensitive/prefix"),
            (format!("{operation:?}"), "sensitive-bucket"),
            (format!("{source:?}"), "source-secret"),
            (format!("{request:?}"), "source-secret"),
            (format!("{output:?}"), "intermediary-secret"),
            (format!("{key:?}"), "cc7c"),
            (
                format!("{:?}", CredentialAccessBoundaryPermissions::OBJECT_ADMIN),
                "storage.objectAdmin",
            ),
        ] {
            assert!(!debug.contains(secret), "{debug}");
        }
        assert_eq!(
            format!("{operation:?}"),
            "ClientSideCredentialAccessBoundaryGranter { .. }"
        );
    }
}
