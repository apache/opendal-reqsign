//! Signing API requests without effort.
//!
//! # Example
//!
//! ```rust,no_run
//! use anyhow::Result;
//! use reqsign::AwsConfig;
//! use reqsign::AwsDefaultLoader;
//! use reqsign::AwsV4Signer;
//! use reqwest::Client;
//! use reqwest::Request;
//! use reqwest::Url;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Signer can load region and credentials from environment by default.
//!     let client = Client::new();
//!     let config = AwsConfig::default().from_profile().from_env();
//!     let loader = AwsDefaultLoader::new(client.clone(), config);
//!     let signer = AwsV4Signer::new("s3", "us-east-1");
//!     // Construct request
//!     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
//!     let mut req = reqwest::Request::new(http::Method::GET, url);
//!     // Signing request with Signer
//!     let credential = loader.load().await?.unwrap();
//!     signer.sign(&mut req, &credential)?;
//!     // Sending already signed request.
//!     let resp = client.execute(req).await?;
//!     println!("resp got status: {}", resp.status());
//!     Ok(())
//! }
//! ```
//!
//! # Available Services
//!
//! - [Aliyun OSS][crate::AliyunOssSigner] for Aliyun OSS.
//! - [AWS SigV4][crate::AwsV4Signer] for AWS services like S3.
//! - [Azure Storage][crate::AzureStorageSigner] for Azure Storage services like Azure Blob Service.
//! - [Google][crate::GoogleSigner] for All google cloud services like Google Cloud Storage Service.
//! - [Huawei Cloud OBS][crate::HuaweicloudObsSigner] for Huawei Cloud Object Storage Service (OBS).
//!
//! # Features
//!
//! reqsign support [`http::Request`] by default. Other request types support are hided
//! under feature gates to reduce dependencies.
//!
//! - `reqwest_request`: Enable to support signing [`reqwest::Request`]
//! - `reqwest_blocking_request`: Enable to support signing [`reqwest::blocking::Request`]

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

#[cfg(feature = "services-aliyun")]
mod aliyun;
#[cfg(feature = "services-aliyun")]
pub use aliyun::*;

#[cfg(feature = "services-aws")]
mod aws;
#[cfg(feature = "services-aws")]
pub use aws::*;

#[cfg(feature = "services-azblob")]
mod azure;
#[cfg(feature = "services-azblob")]
pub use azure::*;

#[cfg(feature = "services-google")]
mod google;
#[cfg(feature = "services-google")]
pub use google::*;

#[cfg(feature = "services-huaweicloud")]
mod huaweicloud;
#[cfg(feature = "services-huaweicloud")]
pub use huaweicloud::*;

#[cfg(feature = "services-openstack")]
mod openstack;
#[cfg(feature = "services-openstack")]
pub use openstack::*;

#[cfg(feature = "services-oracle")]
mod oracle;
#[cfg(feature = "services-oracle")]
pub use oracle::*;

#[cfg(feature = "services-tencent")]
mod tencent;
#[cfg(feature = "services-tencent")]
pub use tencent::*;

mod ctx;
mod dirs;
mod hash;
mod request;
mod time;
