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
use base64::{Engine as _, engine::general_purpose};
use http::header::{AUTHORIZATION, DATE};
use http::request::Parts;
use log::debug;
use reqsign_core::Result;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, SignRequest, SigningCredential, SigningRequest};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
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
impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        Timestamp::now()
    }

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

        let now = Timestamp::now();
        if !cred.is_valid_at(now) {
            return Err(reqsign_core::Error::credential_invalid(
                "credential is not valid for the requested signing operation",
            ));
        }

        let request_target = req
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string();
        let mut signing_req = SigningRequest::build(req)?;

        // Construct string to sign
        let string_to_sign = build_string_to_sign(&signing_req, &request_target, now)?;

        debug!("string to sign: {}", string_to_sign);

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
            .insert(DATE, now.format_http_date().parse()?);

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
            .insert(AUTHORIZATION, auth_value.parse()?);

        signing_req.apply(req)
    }
}

fn build_string_to_sign(
    request: &SigningRequest,
    request_target: &str,
    now: Timestamp,
) -> Result<String> {
    let mut value = String::new();
    writeln!(value, "date: {}", now.format_http_date())?;
    writeln!(
        value,
        "(request-target): {} {}",
        request.method.as_str().to_lowercase(),
        request_target
    )?;
    write!(value, "host: {}", request.authority)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::FileRead;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;

    const RAW_QUERY: &str = "slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

    #[derive(Debug)]
    struct StaticFileRead(Vec<u8>);

    impl FileRead for StaticFileRead {
        async fn file_read(&self, _path: &str) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    fn credential() -> Credential {
        Credential {
            tenancy: "tenancy".to_string(),
            user: "user".to_string(),
            key_file: "key.pem".to_string(),
            fingerprint: "fingerprint".to_string(),
            expires_in: None,
        }
    }

    #[tokio::test]
    async fn request_target_and_wire_uri_preserve_raw_query() -> Result<()> {
        let original_uri = format!("https://example.com/object%2Fname?{RAW_QUERY}");
        let mut canonical_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        let signing_req = SigningRequest::build(&mut canonical_parts)?;
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let string_to_sign = build_string_to_sign(
            &signing_req,
            canonical_parts.uri.path_and_query().unwrap().as_str(),
            now,
        )?;
        assert!(
            string_to_sign.contains(&format!("(request-target): get /object%2Fname?{RAW_QUERY}"))
        );

        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("key generation must work");
        let private_key = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private key must encode")
            .as_bytes()
            .to_vec();
        let ctx = Context::new().with_file_read(StaticFileRead(private_key));
        let mut parts = http::Request::get(&original_uri).body(())?.into_parts().0;

        RequestSigner::new()
            .sign_request(&ctx, &mut parts, Some(&credential()), None)
            .await?;

        assert_eq!(parts.uri.to_string(), original_uri);
        assert!(parts.headers.contains_key(AUTHORIZATION));
        Ok(())
    }

    #[tokio::test]
    async fn invalid_private_key_leaves_request_unchanged() -> Result<()> {
        let original_uri = format!("https://example.com/object?{RAW_QUERY}");
        let ctx = Context::new().with_file_read(StaticFileRead(b"invalid".to_vec()));
        let mut parts = http::Request::get(&original_uri)
            .header("x-original", "value")
            .body(())?
            .into_parts()
            .0;
        let original = parts.clone();

        assert!(
            RequestSigner::new()
                .sign_request(&ctx, &mut parts, Some(&credential()), None)
                .await
                .is_err()
        );
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
        Ok(())
    }
}
