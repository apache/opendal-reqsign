use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use anyhow::Result;
use log::debug;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;

use super::config::Config;
use crate::time::now;
use crate::time::parse_rfc3339;
use crate::time::DateTime;

/// Credential represents an OpenStack Keystone authentication token
/// with an optional service catalog for endpoint discovery.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// The X-Auth-Token value.
    pub token: String,
    /// The expiration time of the token.
    pub expires_at: Option<DateTime>,
    /// The service catalog returned by Keystone.
    pub service_catalog: Vec<CatalogEntry>,
}

impl Credential {
    /// Check if the credential is still valid.
    ///
    /// Returns false if the token is empty or expires within 2 minutes.
    pub fn is_valid(&self) -> bool {
        if self.token.is_empty() {
            return false;
        }

        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_at
            .map(|v| v > now() + chrono::TimeDelta::try_minutes(2).expect("in bounds"))
        {
            return valid;
        }

        true
    }

    /// Look up an endpoint URL from the service catalog.
    ///
    /// Searches for a service matching `service_type` and returns the URL
    /// of the first endpoint matching `interface` (e.g. "public", "internal", "admin").
    pub fn endpoint(&self, service_type: &str, interface: &str) -> Option<&str> {
        self.service_catalog
            .iter()
            .find(|entry| entry.service_type == service_type)
            .and_then(|entry| {
                entry
                    .endpoints
                    .iter()
                    .find(|ep| ep.interface == interface)
                    .map(|ep| ep.url.as_str())
            })
    }

    /// Look up an endpoint URL from the service catalog, filtered by region.
    ///
    /// Like [`endpoint()`](Self::endpoint), but only matches endpoints in the
    /// specified region.
    pub fn endpoint_in_region(
        &self,
        service_type: &str,
        interface: &str,
        region: &str,
    ) -> Option<&str> {
        self.service_catalog
            .iter()
            .find(|entry| entry.service_type == service_type)
            .and_then(|entry| {
                entry
                    .endpoints
                    .iter()
                    .find(|ep| ep.interface == interface && ep.region.as_deref() == Some(region))
                    .map(|ep| ep.url.as_str())
            })
    }
}

/// A service entry from the Keystone service catalog.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CatalogEntry {
    /// The service type (e.g. "object-store", "compute", "identity").
    #[serde(rename = "type")]
    pub service_type: String,
    /// The list of endpoints for this service.
    pub endpoints: Vec<Endpoint>,
}

/// A single endpoint within a catalog entry.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Endpoint {
    /// The interface type (e.g. "public", "internal", "admin").
    pub interface: String,
    /// The endpoint URL.
    pub url: String,
    /// The region identifier.
    #[serde(default)]
    pub region: Option<String>,
    /// The region ID.
    #[serde(default)]
    pub region_id: Option<String>,
}

/// Loader will load credential by authenticating against Keystone.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    client: Client,
    config: Config,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Create a new loader via client and config.
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            config,
            credential: Arc::default(),
        }
    }

    /// Load credential.
    ///
    /// Returns a cached credential if still valid, otherwise authenticates
    /// against Keystone to obtain a fresh token.
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        match self.credential.lock().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Ok(Some(cred)),
            _ => (),
        }

        let cred = if let Some(cred) = self.load_inner().await? {
            cred
        } else {
            return Ok(None);
        };

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = Some(cred.clone());

        Ok(Some(cred))
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        let (auth_url, username, password) = match (
            &self.config.auth_url,
            &self.config.username,
            &self.config.password,
        ) {
            (Some(auth_url), Some(username), Some(password)) => (auth_url, username, password),
            _ => {
                debug!("OpenStack auth_url, username, or password not configured, skipping");
                return Ok(None);
            }
        };

        let user_domain_name = self.config.user_domain_name.as_deref().unwrap_or("Default");

        let scope = self.config.project_name.as_ref().map(|project_name| {
            let project_domain_name = self
                .config
                .project_domain_name
                .as_deref()
                .unwrap_or(user_domain_name);
            keystone_v3::Scope {
                project: keystone_v3::Project {
                    name: project_name.clone(),
                    domain: keystone_v3::Domain {
                        name: project_domain_name.to_string(),
                    },
                },
            }
        });

        let auth_request = keystone_v3::AuthRequest {
            auth: keystone_v3::Auth {
                identity: keystone_v3::Identity {
                    methods: vec!["password".to_string()],
                    password: keystone_v3::Password {
                        user: keystone_v3::User {
                            name: username.clone(),
                            password: password.clone(),
                            domain: keystone_v3::Domain {
                                name: user_domain_name.to_string(),
                            },
                        },
                    },
                },
                scope,
            },
        };

        let url = format!("{}/auth/tokens", auth_url.trim_end_matches('/'));

        debug!("authenticating with Keystone at {url} as user {username}");

        let resp = self
            .client
            .post(&url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&auth_request)?)
            .send()
            .await?;

        if resp.status() != http::StatusCode::CREATED {
            let content = resp.text().await?;
            return Err(anyhow!(
                "Keystone authentication failed (status): {content}"
            ));
        }

        let token = resp
            .headers()
            .get("x-subject-token")
            .ok_or_else(|| anyhow!("Keystone response missing X-Subject-Token header"))?
            .to_str()
            .map_err(|e| anyhow!("X-Subject-Token header is not valid UTF-8: {e}"))?
            .to_string();

        let token_response: keystone_v3::TokenResponse =
            serde_json::from_slice(&resp.bytes().await?)?;

        let expires_at = parse_rfc3339(&token_response.token.expires_at)?;

        debug!(
            "Keystone authentication successful, token expires at {expires_at:?}, \
             catalog has {} services",
            token_response.token.catalog.len()
        );

        Ok(Some(Credential {
            token,
            expires_at: Some(expires_at),
            service_catalog: token_response.token.catalog,
        }))
    }
}

/// Keystone v3 authentication request/response types.
mod keystone_v3 {
    use super::*;

    /// Top-level authentication request body.
    #[derive(Serialize)]
    pub(super) struct AuthRequest {
        pub(super) auth: Auth,
    }

    /// The auth block with identity and optional scope.
    #[derive(Serialize)]
    pub(super) struct Auth {
        pub(super) identity: Identity,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(super) scope: Option<Scope>,
    }

    /// Identity section — only password method is supported.
    #[derive(Serialize)]
    pub(super) struct Identity {
        pub(super) methods: Vec<String>,
        pub(super) password: Password,
    }

    /// Password credentials.
    #[derive(Serialize)]
    pub(super) struct Password {
        pub(super) user: User,
    }

    /// User credentials with domain.
    #[derive(Serialize)]
    pub(super) struct User {
        pub(super) name: String,
        pub(super) password: String,
        pub(super) domain: Domain,
    }

    /// Domain identifier.
    #[derive(Serialize)]
    pub(super) struct Domain {
        pub(super) name: String,
    }

    /// Scope for the token (project-scoped).
    #[derive(Serialize)]
    pub(super) struct Scope {
        pub(super) project: Project,
    }

    /// Project with domain.
    #[derive(Serialize)]
    pub(super) struct Project {
        pub(super) name: String,
        pub(super) domain: Domain,
    }

    /// The top-level token response from Keystone.
    #[derive(Deserialize)]
    pub(super) struct TokenResponse {
        pub(super) token: TokenBody,
    }

    /// The token body containing expiry and catalog.
    #[derive(Deserialize)]
    pub(super) struct TokenBody {
        pub(super) expires_at: String,
        #[serde(default)]
        pub(super) catalog: Vec<super::CatalogEntry>,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_credential_is_valid_empty_token() {
        let cred = Credential::default();
        assert!(!cred.is_valid());
    }

    #[test]
    fn test_credential_is_valid_no_expiry() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: None,
            service_catalog: vec![],
        };
        assert!(cred.is_valid());
    }

    #[test]
    fn test_credential_is_valid_future_expiry() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: Some(
                now() + chrono::TimeDelta::from_std(Duration::from_secs(3600)).unwrap(),
            ),
            service_catalog: vec![],
        };
        assert!(cred.is_valid());
    }

    #[test]
    fn test_credential_is_valid_expires_within_grace() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: Some(now() + chrono::TimeDelta::from_std(Duration::from_secs(30)).unwrap()),
            service_catalog: vec![],
        };
        assert!(!cred.is_valid());
    }

    #[test]
    fn test_credential_is_valid_expired() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: Some(
                now() - chrono::TimeDelta::from_std(Duration::from_secs(3600)).unwrap(),
            ),
            service_catalog: vec![],
        };
        assert!(!cred.is_valid());
    }

    #[test]
    fn test_credential_endpoint_lookup() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: None,
            service_catalog: vec![
                CatalogEntry {
                    service_type: "object-store".to_string(),
                    endpoints: vec![
                        Endpoint {
                            interface: "public".to_string(),
                            url: "https://swift.example.com/v1/AUTH_test".to_string(),
                            region: Some("RegionOne".to_string()),
                            region_id: None,
                        },
                        Endpoint {
                            interface: "internal".to_string(),
                            url: "http://swift-internal:8080/v1/AUTH_test".to_string(),
                            region: Some("RegionOne".to_string()),
                            region_id: None,
                        },
                    ],
                },
                CatalogEntry {
                    service_type: "identity".to_string(),
                    endpoints: vec![Endpoint {
                        interface: "public".to_string(),
                        url: "https://keystone.example.com/v3".to_string(),
                        region: Some("RegionOne".to_string()),
                        region_id: None,
                    }],
                },
            ],
        };

        assert_eq!(
            cred.endpoint("object-store", "public"),
            Some("https://swift.example.com/v1/AUTH_test")
        );
        assert_eq!(
            cred.endpoint("object-store", "internal"),
            Some("http://swift-internal:8080/v1/AUTH_test")
        );
        assert_eq!(
            cred.endpoint("identity", "public"),
            Some("https://keystone.example.com/v3")
        );
        assert_eq!(cred.endpoint("compute", "public"), None);
        assert_eq!(cred.endpoint("object-store", "admin"), None);
    }

    #[test]
    fn test_credential_endpoint_in_region() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: None,
            service_catalog: vec![CatalogEntry {
                service_type: "object-store".to_string(),
                endpoints: vec![
                    Endpoint {
                        interface: "public".to_string(),
                        url: "https://swift-us.example.com/v1/AUTH_test".to_string(),
                        region: Some("us-east-1".to_string()),
                        region_id: None,
                    },
                    Endpoint {
                        interface: "public".to_string(),
                        url: "https://swift-eu.example.com/v1/AUTH_test".to_string(),
                        region: Some("eu-west-1".to_string()),
                        region_id: None,
                    },
                ],
            }],
        };

        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "us-east-1"),
            Some("https://swift-us.example.com/v1/AUTH_test")
        );
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "eu-west-1"),
            Some("https://swift-eu.example.com/v1/AUTH_test")
        );
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "ap-southeast-1"),
            None
        );
    }

    #[test]
    fn test_catalog_entry_deserialize() {
        let json = r#"{
            "type": "object-store",
            "endpoints": [
                {
                    "interface": "public",
                    "url": "https://swift.example.com/v1/AUTH_test",
                    "region": "RegionOne",
                    "region_id": "RegionOne"
                }
            ]
        }"#;

        let entry: CatalogEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.service_type, "object-store");
        assert_eq!(entry.endpoints.len(), 1);
        assert_eq!(entry.endpoints[0].interface, "public");
    }

    #[test]
    fn test_keystone_v3_token_response_deserialize() {
        let json = r#"{
            "token": {
                "expires_at": "2025-01-15T12:00:00Z",
                "catalog": [
                    {
                        "type": "object-store",
                        "endpoints": [
                            {
                                "interface": "public",
                                "url": "https://swift.example.com/v1/AUTH_test",
                                "region": "RegionOne"
                            }
                        ]
                    }
                ]
            }
        }"#;

        let resp: keystone_v3::TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token.expires_at, "2025-01-15T12:00:00Z");
        assert_eq!(resp.token.catalog.len(), 1);
        assert_eq!(resp.token.catalog[0].service_type, "object-store");
    }

    #[test]
    fn test_keystone_v3_auth_request_serialize() {
        let req = keystone_v3::AuthRequest {
            auth: keystone_v3::Auth {
                identity: keystone_v3::Identity {
                    methods: vec!["password".to_string()],
                    password: keystone_v3::Password {
                        user: keystone_v3::User {
                            name: "testuser".to_string(),
                            password: "testpass".to_string(),
                            domain: keystone_v3::Domain {
                                name: "Default".to_string(),
                            },
                        },
                    },
                },
                scope: Some(keystone_v3::Scope {
                    project: keystone_v3::Project {
                        name: "myproject".to_string(),
                        domain: keystone_v3::Domain {
                            name: "Default".to_string(),
                        },
                    },
                }),
            },
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["auth"]["identity"]["methods"][0], "password");
        assert_eq!(
            json["auth"]["identity"]["password"]["user"]["name"],
            "testuser"
        );
        assert_eq!(json["auth"]["scope"]["project"]["name"], "myproject");
    }
}
