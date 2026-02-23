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

use reqsign_core::{SigningCredential, time::Timestamp, utils::Redact};
use std::fmt::{self, Debug};
use std::time::Duration;

/// Credential represents an OpenStack Keystone authentication token
/// with an optional service catalog for endpoint discovery.
#[derive(Clone, Default)]
pub struct Credential {
    /// The X-Auth-Token value.
    pub token: String,
    /// The expiration time of the token.
    pub expires_at: Option<Timestamp>,
    /// The service catalog returned by Keystone.
    pub service_catalog: Vec<CatalogEntry>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("token", &Redact::from(&self.token))
            .field("expires_at", &self.expires_at)
            .field("service_catalog", &self.service_catalog)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        if self.token.is_empty() {
            return false;
        }

        match self.expires_at {
            Some(expires_at) => {
                // Consider token invalid if it expires within 2 minutes
                let buffer = Duration::from_secs(120);
                Timestamp::now() < expires_at - buffer
            }
            None => true,
        }
    }
}

impl Credential {
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
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct CatalogEntry {
    /// The service type (e.g. "object-store", "compute", "identity").
    #[serde(rename = "type")]
    pub service_type: String,
    /// The list of endpoints for this service.
    pub endpoints: Vec<Endpoint>,
}

/// A single endpoint within a catalog entry.
#[derive(Clone, Debug, Default, serde::Deserialize)]
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

/// Keystone v3 authentication request/response types.
pub(crate) mod keystone_v3 {
    use serde::{Deserialize, Serialize};

    /// Top-level authentication request body.
    #[derive(Serialize)]
    pub(crate) struct AuthRequest {
        pub(crate) auth: Auth,
    }

    /// The auth block with identity and optional scope.
    #[derive(Serialize)]
    pub(crate) struct Auth {
        pub(crate) identity: Identity,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) scope: Option<Scope>,
    }

    /// Identity section — only password method is supported.
    #[derive(Serialize)]
    pub(crate) struct Identity {
        pub(crate) methods: Vec<String>,
        pub(crate) password: Password,
    }

    /// Password credentials.
    #[derive(Serialize)]
    pub(crate) struct Password {
        pub(crate) user: User,
    }

    /// User credentials with domain.
    #[derive(Serialize)]
    pub(crate) struct User {
        pub(crate) name: String,
        pub(crate) password: String,
        pub(crate) domain: Domain,
    }

    /// Domain identifier.
    #[derive(Serialize)]
    pub(crate) struct Domain {
        pub(crate) name: String,
    }

    /// Scope for the token (project-scoped).
    #[derive(Serialize)]
    pub(crate) struct Scope {
        pub(crate) project: Project,
    }

    /// Project with domain.
    #[derive(Serialize)]
    pub(crate) struct Project {
        pub(crate) name: String,
        pub(crate) domain: Domain,
    }

    /// The top-level token response from Keystone.
    #[derive(Deserialize)]
    pub(crate) struct TokenResponse {
        pub(crate) token: TokenBody,
    }

    /// The token body containing expiry and catalog.
    #[derive(Deserialize)]
    pub(crate) struct TokenBody {
        pub(crate) expires_at: String,
        #[serde(default)]
        pub(crate) catalog: Vec<super::CatalogEntry>,
    }
}

#[cfg(test)]
mod tests {
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
            expires_at: Some(Timestamp::now() + Duration::from_secs(3600)),
            service_catalog: vec![],
        };
        assert!(cred.is_valid());
    }

    #[test]
    fn test_credential_is_valid_expires_within_grace() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: Some(Timestamp::now() + Duration::from_secs(30)),
            service_catalog: vec![],
        };
        assert!(!cred.is_valid());
    }

    #[test]
    fn test_credential_is_valid_expired() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: Some(Timestamp::now() - Duration::from_secs(3600)),
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
        assert_eq!(
            entry.endpoints[0].url,
            "https://swift.example.com/v1/AUTH_test"
        );
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
                    Endpoint {
                        interface: "internal".to_string(),
                        url: "http://swift-internal-us:8080/v1/AUTH_test".to_string(),
                        region: Some("us-east-1".to_string()),
                        region_id: None,
                    },
                ],
            }],
        };

        // Match region + interface
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "us-east-1"),
            Some("https://swift-us.example.com/v1/AUTH_test")
        );
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "eu-west-1"),
            Some("https://swift-eu.example.com/v1/AUTH_test")
        );
        assert_eq!(
            cred.endpoint_in_region("object-store", "internal", "us-east-1"),
            Some("http://swift-internal-us:8080/v1/AUTH_test")
        );

        // Wrong region
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "ap-southeast-1"),
            None
        );
        // Wrong interface in region
        assert_eq!(
            cred.endpoint_in_region("object-store", "admin", "us-east-1"),
            None
        );
        // Wrong service type
        assert_eq!(
            cred.endpoint_in_region("compute", "public", "us-east-1"),
            None
        );
    }

    #[test]
    fn test_credential_endpoint_empty_catalog() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: None,
            service_catalog: vec![],
        };

        assert_eq!(cred.endpoint("object-store", "public"), None);
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "RegionOne"),
            None
        );
    }

    #[test]
    fn test_credential_endpoint_service_with_no_endpoints() {
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: None,
            service_catalog: vec![CatalogEntry {
                service_type: "object-store".to_string(),
                endpoints: vec![],
            }],
        };

        assert_eq!(cred.endpoint("object-store", "public"), None);
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "RegionOne"),
            None
        );
    }

    #[test]
    fn test_credential_endpoint_no_region_field() {
        // When endpoint has no region, region-aware lookup should not match
        let cred = Credential {
            token: "test-token".to_string(),
            expires_at: None,
            service_catalog: vec![CatalogEntry {
                service_type: "object-store".to_string(),
                endpoints: vec![Endpoint {
                    interface: "public".to_string(),
                    url: "https://swift.example.com/v1/AUTH_test".to_string(),
                    region: None,
                    region_id: None,
                }],
            }],
        };

        // Non-region lookup should still find it
        assert_eq!(
            cred.endpoint("object-store", "public"),
            Some("https://swift.example.com/v1/AUTH_test")
        );
        // Region-aware lookup should not match
        assert_eq!(
            cred.endpoint_in_region("object-store", "public", "RegionOne"),
            None
        );
    }

    #[test]
    fn test_keystone_v3_token_response_deserialize() {
        let json = r#"{
            "token": {
                "expires_at": "2025-01-15T12:00:00.000000Z",
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
        assert_eq!(resp.token.expires_at, "2025-01-15T12:00:00.000000Z");
        assert_eq!(resp.token.catalog.len(), 1);
        assert_eq!(resp.token.catalog[0].service_type, "object-store");
    }
}
