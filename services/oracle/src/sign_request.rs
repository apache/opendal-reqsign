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
use base64::{engine::general_purpose, Engine as _};
use http::request::Parts;
use http::{
    header::{AUTHORIZATION, DATE},
    HeaderValue,
};
use log::debug;
use reqsign_core::time::{format_http_date, now};
use reqsign_core::Result;
use reqsign_core::{Context, SignRequest, SigningRequest};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use std::fmt::Write;
use std::time::Duration;

/// RequestSigner that implements Oracle Cloud Infrastructure API signing.
///
/// - [Oracle Cloud Infrastructure API Signing](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm)
#[derive(Debug)]
pub struct RequestSigner {}

impl RequestSigner {
    /// Create a new builder for Oracle signer.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RequestSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        _expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let now = now();
        let mut signing_req = SigningRequest::build(req)?;

        // Construct string to sign
        let string_to_sign = {
            let mut f = String::new();
            writeln!(f, "date: {}", format_http_date(now))?;
            writeln!(
                f,
                "(request-target): {} {}",
                signing_req.method.as_str().to_lowercase(),
                signing_req.path
            )?;
            write!(f, "host: {}", signing_req.authority)?;
            f
        };

        debug!("string to sign: {}", &string_to_sign);

        // Read private key from file
        let private_key_content = ctx.file_read_as_string(&cred.key_file).await?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_content).map_err(|e| {
            reqsign_core::Error::credential_invalid(format!("Failed to read private key: {e}"))
        })?;

        // Sign the string
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key
            .try_sign(string_to_sign.as_bytes())
            .map_err(|e| reqsign_core::Error::unexpected(format!("Failed to sign: {e}")))?;
        let encoded_signature = general_purpose::STANDARD.encode(signature.to_bytes());

        // Set headers
        signing_req
            .headers
            .insert(DATE, HeaderValue::from_str(&format_http_date(now))?);

        // Build authorization header
        let mut auth_value = String::new();
        write!(auth_value, "Signature version=\"1\",")?;
        write!(auth_value, "headers=\"date (request-target) host\",")?;
        write!(
            auth_value,
            "keyId=\"{}/{}/{}\",",
            cred.tenancy, cred.user, cred.fingerprint
        )?;
        write!(auth_value, "algorithm=\"rsa-sha256\",")?;
        write!(auth_value, "signature=\"{encoded_signature}\"")?;

        signing_req
            .headers
            .insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

        signing_req.apply(req)
    }
}
