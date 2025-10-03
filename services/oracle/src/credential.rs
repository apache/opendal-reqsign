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
    /// Expiration time for this credential.
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

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        if self.tenancy.is_empty()
            || self.user.is_empty()
            || self.key_file.is_empty()
            || self.fingerprint.is_empty()
        {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > Timestamp::now() + Duration::from_secs(120))
        {
            return valid;
        }

        true
    }
}
