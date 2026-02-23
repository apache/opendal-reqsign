//! OpenStack Keystone Signer

use anyhow::Result;
use log::debug;

use super::credential::Credential;
use crate::request::SignableRequest;

/// Signer for OpenStack services authenticated via Keystone.
///
/// Signs requests by inserting the `X-Auth-Token` header from a
/// previously obtained Keystone credential.
pub struct Signer {}

impl Signer {
    /// Create a new signer.
    pub fn new() -> Self {
        Self {}
    }

    /// Sign the request with the given credential.
    ///
    /// Inserts the `X-Auth-Token` header into the request.
    pub fn sign(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<()> {
        let mut ctx = req.build()?;

        debug!(
            "signing request {} {} with OpenStack token",
            ctx.method, ctx.path
        );

        ctx.headers.insert("x-auth-token", cred.token.parse()?);

        req.apply(ctx)
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::*;
    use crate::time::now;

    #[test]
    fn test_sign_inserts_token_header() {
        let signer = Signer::new();
        let cred = Credential {
            token: "test-token-value".to_string(),
            expires_at: Some(
                now() + chrono::TimeDelta::from_std(std::time::Duration::from_secs(3600)).unwrap(),
            ),
            service_catalog: vec![],
        };

        let url = "https://swift.example.com/v1/AUTH_test/container/object"
            .parse()
            .unwrap();
        let mut req = http::Request::new(());
        *req.method_mut() = Method::GET;
        *req.uri_mut() = url;

        signer.sign(&mut req, &cred).unwrap();

        assert_eq!(
            req.headers().get("x-auth-token").unwrap(),
            "test-token-value"
        );
    }

    #[test]
    fn test_sign_preserves_existing_headers() {
        let signer = Signer::new();
        let cred = Credential {
            token: "my-token".to_string(),
            expires_at: None,
            service_catalog: vec![],
        };

        let url = "https://swift.example.com/v1/AUTH_test/container"
            .parse()
            .unwrap();
        let mut req = http::Request::new(());
        *req.method_mut() = Method::PUT;
        *req.uri_mut() = url;
        req.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());

        signer.sign(&mut req, &cred).unwrap();

        assert_eq!(req.headers().get("x-auth-token").unwrap(), "my-token");
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_signer_default() {
        let _signer = Signer::default();
    }
}
