# reqsign &emsp; [![Build Status]][actions] [![Latest Version]][crates.io] [![Crate Downloads]][crates.io]

[Build Status]: https://img.shields.io/github/actions/workflow/status/Xuanwo/reqsign/ci.yml?branch=main
[actions]: https://github.com/Xuanwo/reqsign/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/reqsign.svg
[crates.io]: https://crates.io/crates/reqsign
[Crate Downloads]: https://img.shields.io/crates/d/reqsign.svg

Signing API requests without effort.

---

Most API is simple. But they could be complicated when they are hidden from complex abstraction. `reqsign` bring the simple API back: build, sign, send.

## Quick Start

### Option 1: Use Default Signer (Recommended)

The simplest way to use `reqsign` is with the default signers provided by each service:

```rust
use anyhow::Result;
use reqsign::aws;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a default signer for S3 in us-east-1
    // This will automatically:
    // - Load credentials from environment variables, config files, or IAM roles
    // - Set up the default HTTP client and file reader
    let signer = aws::default_signer("s3", "us-east-1");
    
    // Build your request
    let mut req = http::Request::builder()
        .method("GET")
        .uri("https://s3.amazonaws.com/testbucket")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    
    // Sign the request
    signer.sign(&mut req, None).await?;
    
    // Send the request with your preferred HTTP client
    println!("Request has been signed!");
    Ok(())
}
```

### Option 2: Custom Assembly

For more control over the components, you can manually assemble the signer:

```rust
use anyhow::Result;
use reqsign::{Context, Signer};
use reqsign_aws_v4::{DefaultCredentialProvider, RequestSigner};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> Result<()> {
    // Build your own context with specific implementations
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(reqsign::OsEnv);
    
    // Configure credential provider
    let credential_provider = DefaultCredentialProvider::new();
    
    // Configure request signer for S3
    let request_signer = RequestSigner::new("s3", "us-east-1");
    
    // Assemble the signer
    let signer = Signer::new(ctx, credential_provider, request_signer);
    
    // Build and sign the request
    let mut req = http::Request::builder()
        .method("GET")
        .uri("https://s3.amazonaws.com/testbucket")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    
    // Sign the request
    signer.sign(&mut req, None).await?;
    
    println!("Request has been signed!");
    Ok(())
}
```

### Customizing Default Signers

You can also customize the default signers using the `with_*` methods:

```rust
use reqsign::aws;
use reqsign_aws_v4::StaticCredentialProvider;

// Start with default signer and customize specific components
let signer = aws::default_signer("s3", "us-east-1")
    .with_credential_provider(StaticCredentialProvider::new(
        "my-access-key",
        "my-secret-key",
        None,  // Optional session token
    ));
```

### More Services Examples

#### Azure Storage

```rust
use reqsign::azure;

// Default signer for Azure Storage
let signer = azure::default_signer();

// With custom credentials
use reqsign_azure_storage::StaticCredentialProvider;
let signer = azure::default_signer()
    .with_credential_provider(StaticCredentialProvider::new(
        "account-name",
        "account-key",
    ));
```

#### Google Cloud

```rust
use reqsign::google;

// Default signer for Google Cloud Storage
let signer = google::default_signer("storage.googleapis.com");
```

#### Aliyun OSS

```rust
use reqsign::aliyun;

// Default signer for Aliyun OSS
let signer = aliyun::default_signer();
```

## Features

- Pure rust with minimal dependencies.
- Test again official SDK and services.
- Supported services
  - Aliyun OSS: `reqsign-aliyun-oss`
  - AWS services (SigV4): `reqsign-aws-v4`
  - Azure Storage services: `reqsign-azure-storage`
  - Google services: `reqsign-google`
  - Huawei Cloud OBS: `reqsign-huaweicloud-obs`
  - Oracle Cloud: `reqsign-oracle`
  - Tencent COS: `reqsign-tencent-cos`

## Contributing

Check out the [CONTRIBUTING.md](./CONTRIBUTING.md) guide for more details on getting started with contributing to this project.

## Getting help

Submit [issues](https://github.com/Xuanwo/reqsign/issues/new/choose) for bug report or asking questions in [discussion](https://github.com/Xuanwo/reqsign/discussions/new?category=q-a).

## Acknowledge

Inspired a lot from:

- [aws-sigv4](https://crates.io/crates/aws-sigv4) for AWS SigV4 support.
- [azure_storage_blobs](https://crates.io/crates/azure_storage_blobs) for Azure Storage support.

#### License

<sup>
Licensed under <a href="./LICENSE">Apache License, Version 2.0</a>.
</sup>
