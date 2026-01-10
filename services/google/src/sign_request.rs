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

use http::header;
use jsonwebtoken::{Algorithm, EncodingKey, Header as JwtHeader};
use log::debug;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::RandomizedSigner;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::time::Duration;

use reqsign_core::{
    Context, Result, SignRequest, SigningCredential, SigningMethod, SigningRequest,
    hash::hex_sha256, time::*,
};

use crate::constants::{DEFAULT_SCOPE, GOOG_QUERY_ENCODE_SET, GOOG_URI_ENCODE_SET, GOOGLE_SCOPE};
use crate::credential::{Credential, ServiceAccount, Token};

/// Claims is used to build JWT for Google Cloud.
#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

impl Claims {
    fn new(client_email: &str, scope: &str) -> Self {
        let current = Timestamp::now().as_second() as u64;

        Claims {
            iss: client_email.to_string(),
            scope: scope.to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: current + 3600,
            iat: current,
        }
    }
}

/// OAuth2 token response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// RequestSigner for Google service requests.
#[derive(Debug)]
pub struct RequestSigner {
    service: String,
    region: String,
    scope: Option<String>,
    signer_email: Option<String>,
}

impl Default for RequestSigner {
    fn default() -> Self {
        Self {
            service: String::new(),
            region: "auto".to_string(),
            scope: None,
            signer_email: None,
        }
    }
}

impl RequestSigner {
    /// Create a new builder with the specified service.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            region: "auto".to_string(),
            scope: None,
            signer_email: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set the signer service account email used for query signing via IAMCredentials `signBlob`.
    ///
    /// This is required when generating signed URLs without an embedded service account private key
    /// (e.g. ADC / WIF / impersonation tokens).
    pub fn with_signer_email(mut self, signer_email: impl Into<String>) -> Self {
        self.signer_email = Some(signer_email.into());
        self
    }

    /// Set the region for the builder.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    /// Exchange a service account for an access token.
    ///
    /// This method is used internally when a token is needed but only a service account
    /// is available. It creates a JWT and exchanges it for an OAuth2 access token.
    async fn exchange_token(&self, ctx: &Context, sa: &ServiceAccount) -> Result<Token> {
        let scope = self
            .scope
            .clone()
            .or_else(|| ctx.env_var(GOOGLE_SCOPE))
            .unwrap_or_else(|| DEFAULT_SCOPE.to_string());

        debug!("exchanging service account for token with scope: {scope}");

        // Create JWT
        let jwt = jsonwebtoken::encode(
            &JwtHeader::new(Algorithm::RS256),
            &Claims::new(&sa.client_email, &scope),
            &EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse RSA private key").with_source(e)
            })?,
        )
        .map_err(|e| reqsign_core::Error::unexpected("failed to encode JWT").with_source(e))?;

        // Exchange JWT for access token
        let body =
            format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={jwt}");
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "exchange token failed: {body}"
            )));
        }

        let token_resp: TokenResponse = serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse token response").with_source(e)
        })?;

        let expires_at = token_resp
            .expires_in
            .map(|expires_in| Timestamp::now() + Duration::from_secs(expires_in));

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    fn build_token_auth(
        &self,
        parts: &mut http::request::Parts,
        token: &Token,
    ) -> Result<SigningRequest> {
        let mut req = SigningRequest::build(parts)?;

        req.headers.insert(header::AUTHORIZATION, {
            let mut value: http::HeaderValue = format!("Bearer {}", &token.access_token)
                .parse()
                .map_err(|e| {
                    reqsign_core::Error::unexpected("failed to parse header value").with_source(e)
                })?;
            value.set_sensitive(true);
            value
        });

        Ok(req)
    }

    fn build_string_to_sign(
        &self,
        req: &mut SigningRequest,
        client_email: &str,
        now: Timestamp,
        expires_in: Duration,
    ) -> Result<String> {
        canonicalize_header(req)?;

        canonicalize_query(
            req,
            SigningMethod::Query(expires_in),
            client_email,
            now,
            &self.service,
            &self.region,
        )?;

        let creq = canonical_request_string(req)?;
        let encoded_req = hex_sha256(creq.as_bytes());

        let scope = format!(
            "{}/{}/{}/goog4_request",
            now.format_date(),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

        let string_to_sign = {
            let mut f = String::new();
            f.push_str("GOOG4-RSA-SHA256");
            f.push('\n');
            f.push_str(&now.format_iso8601());
            f.push('\n');
            f.push_str(&scope);
            f.push('\n');
            f.push_str(&encoded_req);
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        Ok(string_to_sign)
    }

    fn sign_with_service_account(private_key_pem: &str, string_to_sign: &str) -> Result<String> {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse private key").with_source(e)
        })?;
        let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());

        Ok(signature.to_string())
    }

    fn build_signed_query_with_service_account(
        &self,
        parts: &mut http::request::Parts,
        service_account: &ServiceAccount,
        expires_in: Duration,
    ) -> Result<SigningRequest> {
        let mut req = SigningRequest::build(parts)?;
        let now = Timestamp::now();

        let string_to_sign =
            self.build_string_to_sign(&mut req, &service_account.client_email, now, expires_in)?;
        let signature =
            Self::sign_with_service_account(&service_account.private_key, &string_to_sign)?;

        req.query.push(("X-Goog-Signature".to_string(), signature));

        Ok(req)
    }

    async fn sign_via_iamcredentials(
        &self,
        ctx: &Context,
        token: &Token,
        signer_email: &str,
        payload: &[u8],
    ) -> Result<String> {
        #[derive(Serialize)]
        struct SignBlobRequest<'a> {
            payload: &'a str,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SignBlobResponse {
            signed_blob: String,
        }

        let payload_b64 = reqsign_core::hash::base64_encode(payload);
        let body = serde_json::to_vec(&SignBlobRequest {
            payload: &payload_b64,
        })
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to encode signBlob request").with_source(e)
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{signer_email}:signBlob"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, {
                let mut value: http::HeaderValue = format!("Bearer {}", &token.access_token)
                    .parse()
                    .map_err(|e| {
                        reqsign_core::Error::unexpected("failed to parse header value")
                            .with_source(e)
                    })?;
                value.set_sensitive(true);
                value
            })
            .body(body.into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            let body = String::from_utf8_lossy(resp.body());
            return Err(reqsign_core::Error::unexpected(format!(
                "iamcredentials signBlob failed: {body}"
            )));
        }

        let sign_resp: SignBlobResponse = serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse signBlob response").with_source(e)
        })?;

        let signed = reqsign_core::hash::base64_decode(&sign_resp.signed_blob)?;

        Ok(hex_encode_upper(&signed))
    }

    async fn build_signed_query_via_iamcredentials(
        &self,
        ctx: &Context,
        parts: &mut http::request::Parts,
        token: &Token,
        signer_email: &str,
        expires_in: Duration,
    ) -> Result<SigningRequest> {
        let mut req = SigningRequest::build(parts)?;
        let now = Timestamp::now();

        let string_to_sign = self.build_string_to_sign(&mut req, signer_email, now, expires_in)?;
        let signature = self
            .sign_via_iamcredentials(ctx, token, signer_email, string_to_sign.as_bytes())
            .await?;

        req.query.push(("X-Goog-Signature".to_string(), signature));

        Ok(req)
    }
}

#[async_trait::async_trait]
impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let signing_req = match expires_in {
            // Query signing - prefer ServiceAccount, otherwise use IAMCredentials signBlob if possible.
            Some(expires) => {
                if let Some(sa) = cred.service_account.as_ref() {
                    self.build_signed_query_with_service_account(req, sa, expires)?
                } else if let (Some(token), Some(signer_email)) =
                    (cred.token.as_ref(), self.signer_email.as_deref())
                {
                    if !token.is_valid() {
                        return Err(reqsign_core::Error::credential_invalid(
                            "token required for iamcredentials signBlob query signing",
                        ));
                    }

                    self.build_signed_query_via_iamcredentials(
                        ctx,
                        req,
                        token,
                        signer_email,
                        expires,
                    )
                    .await?
                } else {
                    return Err(reqsign_core::Error::credential_invalid(
                        "service account or token + signer_email required for query signing",
                    ));
                }
            }
            // Header authentication - prefer valid token, otherwise exchange from SA
            None => {
                // Check if we have a valid token
                if let Some(token) = &cred.token {
                    if token.is_valid() {
                        self.build_token_auth(req, token)?
                    } else if let Some(sa) = &cred.service_account {
                        // Token expired, but we have SA, exchange for new token
                        debug!("token expired, exchanging service account for new token");
                        let new_token = self.exchange_token(ctx, sa).await?;
                        self.build_token_auth(req, &new_token)?
                    } else {
                        return Err(reqsign_core::Error::credential_invalid(
                            "token expired and no service account available",
                        ));
                    }
                } else if let Some(sa) = &cred.service_account {
                    // No token but have SA, exchange for token
                    debug!("no token available, exchanging service account for token");
                    let token = self.exchange_token(ctx, sa).await?;
                    self.build_token_auth(req, &token)?
                } else {
                    return Err(reqsign_core::Error::credential_invalid(
                        "no valid credential available",
                    ));
                }
            }
        };

        signing_req.apply(req).map_err(|e| {
            reqsign_core::Error::unexpected("failed to apply signing request").with_source(e)
        })
    }
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{:02X}", b).expect("writing to string must succeed");
    }
    out
}

fn canonical_request_string(req: &mut SigningRequest) -> Result<String> {
    // 256 is specially chosen to avoid reallocation for most requests.
    let mut f = String::with_capacity(256);

    // Insert method
    f.push_str(req.method.as_str());
    f.push('\n');

    // Insert encoded path
    let path = percent_decode_str(&req.path)
        .decode_utf8()
        .map_err(|e| reqsign_core::Error::unexpected("failed to decode path").with_source(e))?;
    f.push_str(&Cow::from(utf8_percent_encode(&path, &GOOG_URI_ENCODE_SET)));
    f.push('\n');

    // Insert query
    f.push_str(&SigningRequest::query_to_string(
        req.query.clone(),
        "=",
        "&",
    ));
    f.push('\n');

    // Insert signed headers
    let signed_headers = req.header_name_to_vec_sorted();
    for header in signed_headers.iter() {
        let value = &req.headers[*header];
        f.push_str(header);
        f.push(':');
        f.push_str(value.to_str().expect("header value must be valid"));
        f.push('\n');
    }
    f.push('\n');
    f.push_str(&signed_headers.join(";"));
    f.push('\n');
    f.push_str("UNSIGNED-PAYLOAD");

    debug!("canonical request string: {f}");
    Ok(f)
}

fn canonicalize_header(req: &mut SigningRequest) -> Result<()> {
    for (_, value) in req.headers.iter_mut() {
        SigningRequest::header_value_normalize(value)
    }

    // Insert HOST header if not present.
    if req.headers.get(header::HOST).is_none() {
        req.headers.insert(
            header::HOST,
            req.authority.as_str().parse().map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse host header").with_source(e)
            })?,
        );
    }

    Ok(())
}

fn canonicalize_query(
    req: &mut SigningRequest,
    method: SigningMethod,
    client_email: &str,
    now: Timestamp,
    service: &str,
    region: &str,
) -> Result<()> {
    if let SigningMethod::Query(expire) = method {
        req.query
            .push(("X-Goog-Algorithm".into(), "GOOG4-RSA-SHA256".into()));
        req.query.push((
            "X-Goog-Credential".into(),
            format!(
                "{}/{}/{}/{}/goog4_request",
                client_email,
                now.format_date(),
                region,
                service
            ),
        ));
        req.query.push(("X-Goog-Date".into(), now.format_iso8601()));
        req.query
            .push(("X-Goog-Expires".into(), expire.as_secs().to_string()));
        req.query.push((
            "X-Goog-SignedHeaders".into(),
            req.header_name_to_vec_sorted().join(";"),
        ));
    }

    // Return if query is empty.
    if req.query.is_empty() {
        return Ok(());
    }

    // Sort by param name
    req.query.sort();

    req.query = req
        .query
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, &GOOG_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(v, &GOOG_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use bytes::Bytes;
    use http::header;
    use reqsign_core::HttpSend;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct Recorded {
        payload_b64: Option<String>,
    }

    #[derive(Clone, Debug, Default)]
    struct MockHttpSend {
        recorded: Arc<Mutex<Recorded>>,
    }

    #[async_trait]
    impl HttpSend for MockHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(
                req.uri().to_string(),
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test-signer@example.com:signBlob"
            );
            assert_eq!(
                req.headers()
                    .get(header::CONTENT_TYPE)
                    .expect("content-type must exist")
                    .to_str()
                    .expect("content-type must be valid string"),
                "application/json"
            );
            assert_eq!(
                req.headers()
                    .get(header::AUTHORIZATION)
                    .expect("authorization must exist")
                    .to_str()
                    .expect("authorization must be valid string"),
                "Bearer test-access-token"
            );

            let value: serde_json::Value =
                serde_json::from_slice(req.body()).expect("body must be valid json");
            let payload_b64 = value
                .get("payload")
                .and_then(|v| v.as_str())
                .expect("payload must exist")
                .to_string();

            self.recorded.lock().unwrap().payload_b64 = Some(payload_b64);

            // base64([0x01, 0x02, 0x03]) -> hex signature "010203"
            let body = br#"{"signedBlob":"AQID"}"#;
            Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(body.as_slice().into())
                .expect("response must build"))
        }
    }

    fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
        query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == key { Some(v) } else { None }
        })
    }

    fn parse_goog_date_to_timestamp(v: &str) -> Timestamp {
        let year = &v[0..4];
        let month = &v[4..6];
        let day = &v[6..8];
        let hour = &v[9..11];
        let minute = &v[11..13];
        let second = &v[13..15];
        let rfc3339 = format!("{year}-{month}-{day}T{hour}:{minute}:{second}Z");
        rfc3339.parse().expect("date must parse")
    }

    #[tokio::test]
    async fn test_signed_url_via_iamcredentials_sign_blob() -> Result<()> {
        let mock_http = MockHttpSend::default();
        let ctx = Context::new().with_http_send(mock_http.clone());

        let signer = RequestSigner::new("storage").with_signer_email("test-signer@example.com");

        let cred = Credential::with_token(Token {
            access_token: "test-access-token".to_string(),
            expires_at: None,
        });

        let expires_in = Duration::from_secs(60);

        let mut builder = http::Request::builder();
        builder = builder.method(http::Method::GET);
        builder = builder.uri("https://storage.googleapis.com/test-bucket/test-object");
        let req = builder.body(Bytes::new()).expect("request must build");
        let (mut parts, _body) = req.into_parts();

        signer
            .sign_request(&ctx, &mut parts, Some(&cred), Some(expires_in))
            .await?;

        let query = parts.uri.query().expect("signed url must have query");
        assert_eq!(
            query_get(query, "X-Goog-Signature").expect("signature must exist"),
            "010203"
        );

        let goog_date = query_get(query, "X-Goog-Date").expect("date must exist");
        let now = parse_goog_date_to_timestamp(goog_date);

        let mut builder = http::Request::builder();
        builder = builder.method(http::Method::GET);
        builder = builder.uri("https://storage.googleapis.com/test-bucket/test-object");
        let req = builder.body(Bytes::new()).expect("request must build");
        let (mut parts_for_rebuild, _body) = req.into_parts();

        let mut signing_req = SigningRequest::build(&mut parts_for_rebuild)?;
        let string_to_sign = signer.build_string_to_sign(
            &mut signing_req,
            "test-signer@example.com",
            now,
            expires_in,
        )?;
        let expected_payload_b64 = reqsign_core::hash::base64_encode(string_to_sign.as_bytes());

        let recorded_payload_b64 = mock_http
            .recorded
            .lock()
            .unwrap()
            .payload_b64
            .clone()
            .expect("payload must be recorded");

        assert_eq!(recorded_payload_b64, expected_payload_b64);

        Ok(())
    }
}
