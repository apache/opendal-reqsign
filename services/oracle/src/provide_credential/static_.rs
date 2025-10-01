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

use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, Result};

/// StaticCredentialProvider provides static credentials that are provided at initialization time.
#[derive(Debug)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a new StaticCredentialProvider with the given credentials.
    pub fn new(user: &str, tenancy: &str, key_file: &str, fingerprint: &str) -> Self {
        Self {
            credential: Credential {
                user: user.to_string(),
                tenancy: tenancy.to_string(),
                key_file: key_file.to_string(),
                fingerprint: fingerprint.to_string(),
                expires_in: None,
            },
        }
    }
}

#[async_trait]
impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(self.credential.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::OsEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    #[tokio::test]
    async fn test_static_credential_provider() -> anyhow::Result<()> {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);

        let provider = StaticCredentialProvider::new(
            "test_user",
            "test_tenancy",
            "/path/to/key",
            "test_fingerprint",
        );
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.user, "test_user");
        assert_eq!(cred.tenancy, "test_tenancy");
        assert_eq!(cred.key_file, "/path/to/key");
        assert_eq!(cred.fingerprint, "test_fingerprint");
        assert!(cred.expires_in.is_none());

        Ok(())
    }
}
