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

use reqsign_core::SigningCredential;
use reqsign_core::time::Timestamp;
use std::fmt::{Debug, Formatter};
use std::time::Duration;

const REDACTED: &str = "REDACTED";

/// Credential enum for different Azure Storage authentication methods.
#[derive(Clone)]
pub enum Credential {
    /// Shared Key authentication with account name and key
    SharedKey {
        /// Azure storage account name.
        account_name: String,
        /// Azure storage account key.
        account_key: String,
    },
    /// SAS (Shared Access Signature) token authentication
    SasToken {
        /// SAS token.
        token: String,
        /// Optional absolute expiration time for this SAS token.
        expires_at: Option<Timestamp>,
    },
    /// Bearer token for OAuth authentication
    BearerToken {
        /// Bearer token.
        token: String,
        /// Expiration time for this credential.
        expires_in: Option<Timestamp>,
    },
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::SharedKey { .. } => f
                .debug_struct("Credential::SharedKey")
                .field("account_name", &REDACTED)
                .field("account_key", &REDACTED)
                .finish(),
            Credential::SasToken { expires_at, .. } => f
                .debug_struct("Credential::SasToken")
                .field("token", &REDACTED)
                .field("expires_at", expires_at)
                .finish(),
            Credential::BearerToken { expires_in, .. } => f
                .debug_struct("Credential::BearerToken")
                .field("token", &REDACTED)
                .field("expires_in", expires_in)
                .finish(),
        }
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + Duration::from_secs(20))
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        match self {
            Credential::SharedKey {
                account_name,
                account_key,
            } => !account_name.is_empty() && !account_key.is_empty(),
            Credential::SasToken { token, expires_at } => {
                !token.is_empty() && expires_at.is_none_or(|expires| expires > timestamp)
            }
            Credential::BearerToken { token, expires_in } => {
                if token.is_empty() {
                    return false;
                }
                expires_in.is_none_or(|expires| expires > timestamp)
            }
        }
    }
}

impl Credential {
    /// Create a new credential with shared key authentication.
    pub fn with_shared_key(account_name: &str, account_key: &str) -> Self {
        Self::SharedKey {
            account_name: account_name.to_string(),
            account_key: account_key.to_string(),
        }
    }

    /// Create a new credential with SAS token authentication.
    pub fn with_sas_token(sas_token: &str) -> Self {
        Self::SasToken {
            token: sas_token.to_string(),
            expires_at: None,
        }
    }

    /// Create a new credential with an expiring SAS token.
    pub fn with_sas_token_expires_at(sas_token: &str, expires_at: Timestamp) -> Self {
        Self::SasToken {
            token: sas_token.to_string(),
            expires_at: Some(expires_at),
        }
    }

    /// Create a new credential with bearer token authentication.
    pub fn with_bearer_token(bearer_token: &str, expires_in: Option<Timestamp>) -> Self {
        Self::BearerToken {
            token: bearer_token.to_string(),
            expires_in,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_bearer_cache_freshness_from_exact_validity() {
        let now = Timestamp::now();
        let credential =
            Credential::with_bearer_token("token", Some(now + Duration::from_secs(10)));

        assert!(!credential.is_valid());
        assert!(credential.is_valid_at(now + Duration::from_secs(5)));
        assert!(!credential.is_valid_at(now + Duration::from_secs(10)));
    }

    #[test]
    fn separates_sas_cache_freshness_from_exact_validity() {
        let now = Timestamp::now();
        let credential = Credential::with_sas_token_expires_at(
            "sv=2020-12-06&sig=secret",
            now + Duration::from_secs(10),
        );

        assert!(!credential.is_valid());
        assert!(credential.is_valid_at(now + Duration::from_secs(5)));
        assert!(!credential.is_valid_at(now + Duration::from_secs(10)));
    }

    #[test]
    fn debug_fully_redacts_credential_material() {
        let debug = [
            format!(
                "{:?}",
                Credential::with_shared_key(
                    "accountprefixmiddlesuffixaccount",
                    "keyprefix-middle-keysuffix",
                )
            ),
            format!(
                "{:?}",
                Credential::with_sas_token("sv=2020-12-06&sig=sasprefix-middle-sassignaturesuffix",)
            ),
            format!(
                "{:?}",
                Credential::with_bearer_token("bearerprefix-middle-bearersuffix", None,)
            ),
        ]
        .join("\n");

        assert!(debug.contains("Credential::SharedKey"));
        assert!(debug.contains("Credential::SasToken"));
        assert!(debug.contains("Credential::BearerToken"));
        assert!(debug.contains(REDACTED));
        for fragment in [
            "accountprefix",
            "suffixaccount",
            "keyprefix",
            "keysuffix",
            "sasprefix",
            "sassignaturesuffix",
            "bearerprefix",
            "bearersuffix",
        ] {
            assert!(!debug.contains(fragment));
        }
    }
}
