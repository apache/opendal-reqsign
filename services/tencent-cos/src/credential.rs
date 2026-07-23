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
use reqsign_core::utils::Redact;
use std::fmt::{Debug, Formatter};
use std::time::Duration;

/// Credential for Tencent COS.
#[derive(Default, Clone)]
pub struct Credential {
    /// Secret ID
    pub secret_id: String,
    /// Secret Key
    pub secret_key: String,
    /// Security token for temporary credentials
    pub security_token: Option<String>,
    /// Expiration time for this credential
    pub expires_in: Option<Timestamp>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("secret_id", &Redact::from(&self.secret_id))
            .field("secret_key", &Redact::from(&self.secret_key))
            .field("security_token", &Redact::from(&self.security_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + Duration::from_secs(120))
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        if self.secret_id.is_empty() || self.secret_key.is_empty() {
            return false;
        }

        self.expires_in.is_none_or(|expires| expires > timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_cache_freshness_from_exact_validity() {
        let now = Timestamp::now();
        let credential = Credential {
            secret_id: "secret-id".to_string(),
            secret_key: "secret-key".to_string(),
            security_token: Some("token".to_string()),
            expires_in: Some(now + Duration::from_secs(30)),
        };

        assert!(!credential.is_valid());
        assert!(credential.is_valid_at(now + Duration::from_secs(10)));
        assert!(!credential.is_valid_at(now + Duration::from_secs(30)));
    }
}
