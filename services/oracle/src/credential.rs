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

/// Credential that holds the API private key information.
#[derive(Default, Clone)]
pub struct Credential {
    /// TenantID for Oracle Cloud Infrastructure.
    pub tenancy: String,
    /// UserID for Oracle Cloud Infrastructure.
    pub user: String,
    /// API Private Key file path for credential.
    pub key_file: String,
    /// Fingerprint of the API Key.
    pub fingerprint: String,
    /// Deadline after which the credential source should be reloaded.
    pub expires_in: Option<Timestamp>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("tenancy", &self.tenancy)
            .field("user", &self.user)
            .field("key_file", &Redact::from(&self.key_file))
            .field("fingerprint", &self.fingerprint)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl Credential {
    fn has_required_fields(&self) -> bool {
        !self.tenancy.is_empty()
            && !self.user.is_empty()
            && !self.key_file.is_empty()
            && !self.fingerprint.is_empty()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.has_required_fields()
            && self
                .expires_in
                .is_none_or(|refresh_at| refresh_at > Timestamp::now() + Duration::from_secs(120))
    }

    fn is_valid_at(&self, _timestamp: Timestamp) -> bool {
        self.has_required_fields()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_deadline_only_controls_cache_freshness() {
        let now = Timestamp::now();
        let credential = Credential {
            tenancy: "tenancy".to_string(),
            user: "user".to_string(),
            key_file: "key.pem".to_string(),
            fingerprint: "fingerprint".to_string(),
            expires_in: Some(now + Duration::from_secs(30)),
        };

        assert!(!credential.is_valid());
        assert!(credential.is_valid_at(now + Duration::from_secs(3600)));
    }
}
