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

//! Google Service Signer
//!
//! Generic service-account impersonation accepts any token-only Google source
//! provider and can feed its output into a signer or Credential Access Boundary
//! grant.
//!
//! Typed server-side Cloud Storage Credential Access Boundary downscoping is
//! always available. Enable the `credential-access-boundary-client-side`
//! feature for local client-side token generation.

mod constants;

mod credential;
pub use credential::{Credential, ServiceAccount, Token};

mod credential_access_boundary;
#[cfg(feature = "credential-access-boundary-client-side")]
pub use credential_access_boundary::ClientSideCredentialAccessBoundaryGranter;
pub use credential_access_boundary::{
    CredentialAccessBoundaryGrant, CredentialAccessBoundaryPermissions,
    ServerSideCredentialAccessBoundaryGranter,
};

mod service_account_impersonation;
pub use service_account_impersonation::{
    ServiceAccountImpersonationCredentialProvider, ServiceAccountImpersonationGrant,
    ServiceAccountImpersonationGranter,
};

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, EnvCredentialProvider,
    ExternalAccountConfig, ExternalAccountCredentialProvider, FileCredentialProvider,
    ServiceAccountTokenCredentialProvider, StaticCredentialProvider, TokenCredentialProvider,
    VmMetadataCredentialProvider, WellKnownCredentialProvider,
};
