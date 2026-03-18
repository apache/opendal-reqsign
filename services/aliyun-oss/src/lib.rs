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

//! Aliyun OSS signing implementation for reqsign.
//!
//! This crate provides signing support for Alibaba Cloud Object Storage Service (OSS),
//! enabling secure authentication for all OSS operations.
//!
//! ## Overview
//!
//! Aliyun OSS uses a custom signing algorithm based on HMAC-SHA1. This crate implements
//! the complete signing process along with credential loading from various sources
//! including environment variables, configuration files, and STS tokens.
//!
//! `RequestSigner` defaults to V1 signing and also accepts an optional region
//! for future signing versions that require it.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_aliyun_oss::{
//!     AssumeRoleCredentialProvider, AssumeRoleWithOidcCredentialProvider,
//!     ConfigFileCredentialProvider, CredentialsFileCredentialProvider, DefaultCredentialProvider,
//!     EnvCredentialProvider, OssProfileCredentialProvider, RequestSigner,
//!     StaticCredentialProvider,
//! };
//! use reqsign_core::{Context, Signer, Result};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create context
//!     let ctx = Context::new()
//!         .with_file_read(TokioFileRead::default())
//!         .with_http_send(ReqwestHttpSend::default());
//!
//!     // Create credential loader with the default assume_role -> env ->
//!     // OSS profile -> shared credentials file -> config file -> oidc chain.
//!     let loader = DefaultCredentialProvider::builder()
//!         .assume_role(AssumeRoleCredentialProvider::new())
//!         .env(EnvCredentialProvider::new())
//!         .oss_profile(OssProfileCredentialProvider::new())
//!         .credentials_file(CredentialsFileCredentialProvider::new())
//!         .config_file(ConfigFileCredentialProvider::new())
//!         .oidc(AssumeRoleWithOidcCredentialProvider::new())
//!         .build();
//!
//!     // Or use static credentials
//!     // let loader = StaticCredentialProvider::new(
//!     //     "your-access-key-id",
//!     //     "your-access-key-secret",
//!     // );
//!
//!     // Create request builder
//!     let builder = RequestSigner::new("bucket");
//!     // For future signing versions, region can be wired now:
//!     // let builder = RequestSigner::new("bucket").with_region("oss-cn-beijing");
//!
//!     // Create the signer
//!     let signer = Signer::new(ctx, loader, builder);
//!
//!     // Sign requests
//!     let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!         .body(())
//!         .unwrap()
//!         .into_parts()
//!         .0;
//!
//!     signer.sign(&mut req, None).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Credential Sources
//!
//! ### Environment Variables
//!
//! ```bash
//! export ALIBABA_CLOUD_ACCESS_KEY_ID=your-access-key-id
//! export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-access-key-secret
//! export ALIBABA_CLOUD_SECURITY_TOKEN=your-sts-token  # Optional, for STS
//! export OSS_ACCESS_KEY_ID=your-access-key-id         # Alias
//! export OSS_ACCESS_KEY_SECRET=your-access-key-secret # Alias
//! export OSS_SESSION_TOKEN=your-sts-token             # Alias
//! ```
//!
//! ### OSS Profile File
//!
//! The crate can load credentials from the OSS profile file
//! (typically `~/.oss/credentials`).
//!
//! ### Alibaba Shared Credential and Config Files
//!
//! The crate can also load static credentials from Alibaba shared SDK files
//! (`~/.alibabacloud/credentials.ini`, `~/.aliyun/credentials.ini`) and the
//! Alibaba CLI config file (`~/.aliyun/config.json`).
//!
//! ## OSS Operations
//!
//! ### Object Operations
//!
//! ```no_run
//! # use http::Request;
//! // Get object
//! let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//!
//! // Put object
//! let req = Request::put("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!     .header("Content-Type", "text/plain")
//!     .body(b"Hello, OSS!")
//!     .unwrap();
//!
//! // Delete object
//! let req = Request::delete("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ### Bucket Operations
//!
//! ```no_run
//! # use http::Request;
//! // List objects
//! let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?prefix=photos/")
//!     .body(())
//!     .unwrap();
//!
//! // Get bucket info
//! let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?bucketInfo")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ## Advanced Features
//!
//! ### STS AssumeRole
//!
//! ```no_run
//! use reqsign_aliyun_oss::{
//!     AssumeRoleCredentialProvider, DefaultCredentialProvider, StaticCredentialProvider,
//! };
//!
//! // Use an explicit base access key source to call STS AssumeRole.
//! let loader = DefaultCredentialProvider::builder()
//!     .no_env()
//!     .no_oss_profile()
//!     .no_credentials_file()
//!     .no_config_file()
//!     .assume_role(
//!         AssumeRoleCredentialProvider::new()
//!             .with_base_provider(StaticCredentialProvider::new(
//!                 "your-access-key-id",
//!                 "your-access-key-secret",
//!             ))
//!             .with_role_arn("acs:ram::123456789012:role/example")
//!             .with_role_session_name("my-session"),
//!     )
//!     .no_oidc()
//!     .build();
//! ```
//!
//! Or rely on the default static base chain by setting
//! `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`,
//! `ALIBABA_CLOUD_ROLE_ARN`, and optionally `ALIBABA_CLOUD_EXTERNAL_ID`.
//!
//! ### Custom Endpoints
//!
//! ```no_run
//! # use http::Request;
//! // Internal endpoint (VPC)
//! let req = Request::get("https://bucket.oss-cn-beijing-internal.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//!
//! // Accelerate endpoint
//! let req = Request::get("https://bucket.oss-accelerate.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ## Examples
//!
//! Check out the examples directory:
//! - [Basic OSS operations](examples/oss_operations.rs)
//! - [STS authentication](examples/sts_auth.rs)

mod constants;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::*;
