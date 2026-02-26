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

use std::time::Duration;

use reqsign_core::{Context, Result, SignRequest};

use crate::credential::Credential;

/// RequestSigner for OpenStack services.
///
/// Signs requests by inserting the `X-Auth-Token` header with the
/// Keystone authentication token.
#[derive(Debug, Default)]
pub struct RequestSigner;

#[async_trait::async_trait]
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        _expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let mut value: http::HeaderValue = cred.token.parse().map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse token as header value").with_source(e)
        })?;
        value.set_sensitive(true);

        req.headers.insert("x-auth-token", value);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sign_request_inserts_token() {
        let signer = RequestSigner;
        let ctx = Context::new();

        let cred = Credential {
            token: "test-token-123".to_string(),
            expires_at: None,
            service_catalog: vec![],
        };

        let req = http::Request::builder()
            .method("GET")
            .uri("https://swift.example.com/v1/AUTH_test/container/object")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();

        signer
            .sign_request(&ctx, &mut parts, Some(&cred), None)
            .await
            .unwrap();

        assert_eq!(
            parts.headers.get("x-auth-token").unwrap().to_str().unwrap(),
            "test-token-123"
        );
    }

    #[tokio::test]
    async fn test_sign_request_no_credential() {
        let signer = RequestSigner;
        let ctx = Context::new();

        let req = http::Request::builder()
            .method("GET")
            .uri("https://swift.example.com/v1/AUTH_test/container/object")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();

        signer
            .sign_request(&ctx, &mut parts, None, None)
            .await
            .unwrap();

        assert!(parts.headers.get("x-auth-token").is_none());
    }
}
