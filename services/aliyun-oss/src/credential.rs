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
use reqsign_core::time::{Timestamp, now};
use reqsign_core::utils::Redact;
use std::fmt::{Debug, Formatter};

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
pub struct Credential {
    /// Access key id for aliyun services.
    pub access_key_id: String,
    /// Access key secret for aliyun services.
    pub access_key_secret: String,
    /// Security token for aliyun services.
    pub security_token: Option<String>,
    /// Expiration time for this credential.
    pub expires_in: Option<Timestamp>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("access_key_secret", &Redact::from(&self.access_key_secret))
            .field("security_token", &Redact::from(&self.security_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        if (self.access_key_id.is_empty() || self.access_key_secret.is_empty())
            && self.security_token.is_none()
        {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > now() + jiff::SignedDuration::from_mins(2))
        {
            return valid;
        }

        true
    }
}
