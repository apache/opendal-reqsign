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

use std::fmt::Write;
use std::time::Duration;

use http::request::Parts;
use http::{HeaderValue, header};
use log::debug;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, SigningKey};
use reqsign_aws_core::Credential;
use reqsign_aws_core::signing::{
    append_query_fragment, append_query_pairs, canonical_request_string, canonicalize_headers,
    canonicalize_query,
};
use reqsign_core::hash::{hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential, SigningRequest};
use zeroize::Zeroizing;

use crate::SigningRegionSet;

const ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256";
const X_AMZ_REGION_SET: &str = "x-amz-region-set";
const CREDENTIAL_OPERATION_HEADROOM: Duration = Duration::from_secs(10);

/// Request signer implementing
/// [AWS Signature Version 4A](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).
#[derive(Debug)]
pub struct RequestSigner {
    service: String,
    region_set: SigningRegionSet,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a SigV4a request signer.
    pub fn new(service: &str, region_set: SigningRegionSet) -> Self {
        Self {
            service: service.to_string(),
            region_set,
            time: None,
        }
    }

    /// Specify the signing time.
    ///
    /// This method is only available to tests because production signing must
    /// always use the current time.
    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    fn get_time(&self) -> Timestamp {
        self.time.unwrap_or_else(Timestamp::now)
    }

    fn required_valid_until_at(
        &self,
        signing_time: Timestamp,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        signing_time + expires_in.unwrap_or(CREDENTIAL_OPERATION_HEADROOM)
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        self.required_valid_until_at(self.get_time(), expires_in)
    }

    async fn sign_request(
        &self,
        _: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(credential) = credential else {
            return Ok(());
        };

        let now = self.get_time();
        let required_until = self.required_valid_until_at(now, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }

        let original_uri = req.uri.clone();
        let mut signing_request = SigningRequest::build(req)?;
        canonicalize_headers(&mut signing_request, credential, expires_in, now)?;

        if expires_in.is_none() {
            let region_set = HeaderValue::from_str(self.region_set.as_str()).map_err(|e| {
                Error::request_invalid("AWS signing region set is not a valid header value")
                    .with_source(e)
            })?;
            signing_request.headers.insert(X_AMZ_REGION_SET, region_set);
        }

        let authentication_query = authentication_query(
            &signing_request,
            credential,
            expires_in,
            now,
            &self.service,
            &self.region_set,
        );
        let canonical_query = canonicalize_query(&signing_request, &authentication_query);
        let canonical_request = canonical_request_string(&signing_request, &canonical_query)?;
        let encoded_request = hex_sha256(canonical_request.as_bytes());

        let scope = format!("{}/{}/aws4_request", now.format_date(), self.service);
        debug!("calculated scope: {scope}");

        let string_to_sign = string_to_sign(now, &scope, &encoded_request)?;
        debug!("calculated string to sign: {string_to_sign}");

        let signing_key =
            generate_signing_key(&credential.access_key_id, &credential.secret_access_key)?;
        let signature = calculate_signature(&signing_key, string_to_sign.as_bytes());

        let final_uri = if expires_in.is_some() {
            let unsigned_uri = append_query_pairs(&original_uri, &authentication_query)?;
            Some(append_query_fragment(
                &unsigned_uri,
                &format!("X-Amz-Signature={signature}"),
            )?)
        } else {
            let mut authorization = HeaderValue::from_str(&format!(
                "{ALGORITHM} Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
                credential.access_key_id,
                signing_request.header_name_to_vec_sorted().join(";"),
            ))
            .map_err(|e| {
                Error::unexpected(format!("failed to create authorization header: {e}"))
            })?;
            authorization.set_sensitive(true);
            signing_request
                .headers
                .insert(header::AUTHORIZATION, authorization);
            None
        };

        signing_request.apply(req)?;
        if let Some(uri) = final_uri {
            req.uri = uri;
        }
        Ok(())
    }
}

fn authentication_query(
    request: &SigningRequest,
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    service: &str,
    region_set: &SigningRegionSet,
) -> Vec<(String, String)> {
    let Some(expires_in) = expires_in else {
        return Vec::new();
    };

    let mut query = vec![
        ("X-Amz-Algorithm".to_string(), ALGORITHM.to_string()),
        (
            "X-Amz-Credential".to_string(),
            format!(
                "{}/{}/{}/aws4_request",
                credential.access_key_id,
                now.format_date(),
                service
            ),
        ),
        ("X-Amz-Date".to_string(), now.format_iso8601()),
        (
            "X-Amz-Expires".to_string(),
            expires_in.as_secs().to_string(),
        ),
        (
            "X-Amz-Region-Set".to_string(),
            region_set.as_str().to_string(),
        ),
        (
            "X-Amz-SignedHeaders".to_string(),
            request.header_name_to_vec_sorted().join(";"),
        ),
    ];

    if let Some(token) = &credential.session_token {
        query.push(("X-Amz-Security-Token".to_string(), token.clone()));
    }
    query
}

fn string_to_sign(now: Timestamp, scope: &str, encoded_request: &str) -> Result<String> {
    let mut output = String::with_capacity(160);
    writeln!(output, "{ALGORITHM}")
        .map_err(|e| Error::unexpected(format!("failed to write algorithm: {e}")))?;
    writeln!(output, "{}", now.format_iso8601())
        .map_err(|e| Error::unexpected(format!("failed to write timestamp: {e}")))?;
    writeln!(output, "{scope}")
        .map_err(|e| Error::unexpected(format!("failed to write scope: {e}")))?;
    write!(output, "{encoded_request}")
        .map_err(|e| Error::unexpected(format!("failed to write encoded request: {e}")))?;
    Ok(output)
}

fn calculate_signature(signing_key: &SigningKey, string_to_sign: &[u8]) -> String {
    let signature: DerSignature = signing_key.sign(string_to_sign);
    hex::encode(signature.as_bytes())
}

fn generate_signing_key(access_key_id: &str, secret_access_key: &str) -> Result<SigningKey> {
    let mut input_key = Zeroizing::new(Vec::with_capacity(secret_access_key.len() + 5));
    input_key.extend_from_slice(b"AWS4A");
    input_key.extend_from_slice(secret_access_key.as_bytes());

    for counter in 1_u8..=254 {
        let mut input = Zeroizing::new(Vec::with_capacity(
            ALGORITHM.len() + access_key_id.len() + 11,
        ));
        input.extend_from_slice(&1_u32.to_be_bytes());
        input.extend_from_slice(ALGORITHM.as_bytes());
        input.push(0);
        input.extend_from_slice(access_key_id.as_bytes());
        input.push(counter);
        input.extend_from_slice(&256_u32.to_be_bytes());

        let digest = Zeroizing::new(hmac_sha256(input_key.as_slice(), input.as_slice()));
        let mut scalar = Zeroizing::new([0_u8; 32]);
        scalar.copy_from_slice(digest.as_slice());
        increment_big_endian(scalar.as_mut());

        // P-256 accepts k0 + 1 exactly when the KDF output k0 is in the
        // specification's [0, n - 2] range.
        if let Ok(signing_key) = SigningKey::from_slice(scalar.as_ref()) {
            return Ok(signing_key);
        }
    }

    Err(Error::unexpected(
        "failed to derive a valid SigV4a signing key",
    ))
}

fn increment_big_endian(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result as AnyResult;
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
        SigningSettings,
    };
    use aws_sigv4::sign::v4a;
    use http::Request;
    use p256::ecdsa::DerSignature;
    use p256::ecdsa::signature::Verifier;
    use pretty_assertions::assert_eq;
    use reqsign_core::ErrorKind;

    // AWS CRT SigV4a get-vanilla test vector.
    const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
    const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const HEADER_STRING_TO_SIGN: &str = "AWS4-ECDSA-P256-SHA256\n20150830T123600Z\n20150830/service/aws4_request\ncf59db423e841c8b7e3444158185aa261b724a5c27cbe762676f3eed19f4dc02";
    const RAW_QUERY: &str =
        "slash=%2F&literal-plus=+&double=%252F&dup=first&dup=second&empty=&flag&";

    fn credential() -> Credential {
        Credential {
            access_key_id: ACCESS_KEY_ID.to_string(),
            secret_access_key: SECRET_ACCESS_KEY.to_string(),
            ..Default::default()
        }
    }

    fn signer() -> RequestSigner {
        RequestSigner::new(
            "service",
            SigningRegionSet::new("us-east-1").expect("region set must be valid"),
        )
        .with_time(
            "2015-08-30T12:36:00Z"
                .parse()
                .expect("timestamp must be valid"),
        )
    }

    fn comparable_headers(request: &Request<()>) -> Vec<String> {
        let mut headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                let value = value.to_str().expect("header must be valid UTF-8");
                if name == header::AUTHORIZATION {
                    let (prefix, _) = value
                        .rsplit_once(", Signature=")
                        .expect("authorization must contain signature");
                    format!("{name}:{prefix}, Signature=<signature>")
                } else {
                    format!("{name}:{value}")
                }
            })
            .collect::<Vec<_>>();
        if !headers.iter().any(|value| value.starts_with("host:")) {
            headers.push(format!(
                "host:{}",
                request.uri().authority().expect("URI must have authority")
            ));
        }
        headers.sort();
        headers
    }

    fn comparable_query(request: &Request<()>) -> Vec<String> {
        let mut query =
            form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .map(|(key, value)| {
                    if key == "X-Amz-Signature" {
                        format!("{key}=<signature>")
                    } else {
                        format!("{key}={value}")
                    }
                })
                .collect::<Vec<_>>();
        query.sort();
        query
    }

    #[test]
    fn signing_key_matches_aws_public_key_vector() -> AnyResult<()> {
        let signing_key = generate_signing_key(ACCESS_KEY_ID, SECRET_ACCESS_KEY)?;
        let public_key = signing_key.verifying_key().to_encoded_point(false);

        assert_eq!(
            hex::encode(public_key.x().expect("uncompressed key has x")),
            "b6618f6a65740a99e650b33b6b4b5bd0d43b176d721a3edfea7e7d2d56d936b1"
        );
        assert_eq!(
            hex::encode(public_key.y().expect("uncompressed key has y")),
            "865ed22a7eadc9c5cb9d2cbaca1b3699139fedc5043dc6661864218330c8e518"
        );

        let signature = calculate_signature(&signing_key, HEADER_STRING_TO_SIGN.as_bytes());
        let signature_bytes = hex::decode(signature)?;
        let signature = DerSignature::try_from(signature_bytes.as_slice())
            .expect("generated signature must use DER encoding");
        signing_key
            .verifying_key()
            .verify(HEADER_STRING_TO_SIGN.as_bytes(), &signature)
            .expect("generated signature must verify");
        Ok(())
    }

    #[tokio::test]
    async fn signs_headers_with_regionless_scope() -> AnyResult<()> {
        let mut parts = Request::get("https://example.amazonaws.com/")
            .body(())?
            .into_parts()
            .0;
        signer()
            .sign_request(&Context::new(), &mut parts, Some(&credential()), None)
            .await?;

        assert_eq!(parts.headers[X_AMZ_REGION_SET], "us-east-1");
        assert_eq!(parts.headers["x-amz-date"], "20150830T123600Z");
        let authorization = parts.headers[header::AUTHORIZATION].to_str()?;
        assert!(authorization.starts_with(
            "AWS4-ECDSA-P256-SHA256 Credential=AKIDEXAMPLE/20150830/service/aws4_request"
        ));
        assert!(
            authorization
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set")
        );
        assert!(!authorization.contains("/us-east-1/service/"));
        Ok(())
    }

    #[tokio::test]
    async fn presigns_with_region_set_query() -> AnyResult<()> {
        let mut parts = Request::get("https://example.amazonaws.com/")
            .body(())?
            .into_parts()
            .0;
        signer()
            .sign_request(
                &Context::new(),
                &mut parts,
                Some(&credential()),
                Some(Duration::from_secs(3600)),
            )
            .await?;

        let query = parts.uri.query().expect("presigned request has query");
        assert!(query.contains("X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256"));
        assert!(query.contains("X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fservice%2Faws4_request"));
        assert!(query.contains("X-Amz-Region-Set=us-east-1"));
        assert!(query.contains("X-Amz-Signature="));
        assert!(!parts.headers.contains_key(X_AMZ_REGION_SET));
        Ok(())
    }

    #[tokio::test]
    async fn matches_aws_sdk_request_fields() -> AnyResult<()> {
        let now: Timestamp = "2015-08-30T12:36:00Z".parse()?;

        for expires_in in [None, Some(Duration::from_secs(3600))] {
            let mut expected =
                Request::get("https://example.amazonaws.com/object?key=value").body(())?;
            let mut settings = SigningSettings::default();
            settings.percent_encoding_mode = PercentEncodingMode::Double;
            settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
            if let Some(expires_in) = expires_in {
                settings.signature_location = SignatureLocation::QueryParams;
                settings.expires_in = Some(expires_in);
            }

            let identity = Credentials::new(
                ACCESS_KEY_ID,
                SECRET_ACCESS_KEY,
                None,
                None,
                "hardcoded-credentials",
            )
            .into();
            let params = v4a::SigningParams::builder()
                .identity(&identity)
                .region_set("us-east-1")
                .name("service")
                .time(now.as_system_time())
                .settings(settings)
                .build()?;
            let output = aws_sigv4::http_request::sign(
                SignableRequest::new(
                    expected.method().as_str(),
                    expected.uri().to_string(),
                    expected.headers().iter().map(|(name, value)| {
                        (
                            name.as_str(),
                            std::str::from_utf8(value.as_bytes())
                                .expect("header must be valid UTF-8"),
                        )
                    }),
                    SignableBody::UnsignedPayload,
                )?,
                &params.into(),
            )?;
            output.into_parts().0.apply_to_request_http1x(&mut expected);

            let (mut actual_parts, actual_body) =
                Request::get("https://example.amazonaws.com/object?key=value")
                    .body(())?
                    .into_parts();
            signer()
                .sign_request(
                    &Context::new(),
                    &mut actual_parts,
                    Some(&credential()),
                    expires_in,
                )
                .await?;
            let actual = Request::from_parts(actual_parts, actual_body);

            assert_eq!(comparable_headers(&actual), comparable_headers(&expected));
            assert_eq!(comparable_query(&actual), comparable_query(&expected));
        }
        Ok(())
    }

    #[tokio::test]
    async fn preserves_existing_wire_query() -> AnyResult<()> {
        let original_uri = format!("https://example.amazonaws.com/object%2Fname?{RAW_QUERY}");
        let mut header_parts = Request::get(&original_uri).body(())?.into_parts().0;
        signer()
            .sign_request(
                &Context::new(),
                &mut header_parts,
                Some(&credential()),
                None,
            )
            .await?;
        assert_eq!(header_parts.uri.to_string(), original_uri);

        let mut query_parts = Request::get(&original_uri).body(())?.into_parts().0;
        signer()
            .sign_request(
                &Context::new(),
                &mut query_parts,
                Some(&credential()),
                Some(Duration::from_secs(60)),
            )
            .await?;
        assert!(
            query_parts
                .uri
                .to_string()
                .starts_with(&format!("{original_uri}X-Amz-Algorithm="))
        );
        Ok(())
    }

    #[tokio::test]
    async fn error_does_not_mutate_request() -> AnyResult<()> {
        let mut parts = Request::get("https://example.amazonaws.com/")
            .header("x-original", "value")
            .body(())?
            .into_parts()
            .0;
        let original_uri = parts.uri.clone();
        let original_headers = parts.headers.clone();
        let expired = Credential {
            expires_in: Some(
                "2015-08-30T12:36:00Z"
                    .parse()
                    .expect("timestamp must be valid"),
            ),
            ..credential()
        };

        let error = signer()
            .sign_request(&Context::new(), &mut parts, Some(&expired), None)
            .await
            .expect_err("expired credential must fail");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(parts.uri, original_uri);
        assert_eq!(parts.headers, original_headers);
        Ok(())
    }
}
