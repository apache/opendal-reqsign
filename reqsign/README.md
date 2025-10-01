# reqsign

Signing HTTP requests for AWS, Azure, Google, Huawei, Aliyun, Tencent and Oracle services.

## Features

This crate provides a unified interface for signing HTTP requests across multiple cloud providers:

- **AWS**: Signature V4 for AWS services
- **Azure**: Azure Storage services
- **Google**: Google Cloud services
- **Aliyun**: Aliyun Object Storage Service (OSS)
- **Huawei Cloud**: Object Storage Service (OBS)
- **Tencent Cloud**: Cloud Object Storage (COS)
- **Oracle**: Oracle Cloud services

## Quick Start

Add `reqsign` to your `Cargo.toml`:

```toml
[dependencies]
reqsign = "0.17"
```

By default, this includes the `default-context` feature which provides a ready-to-use context implementation using `reqwest` and `tokio`.

To use specific services only:

```toml
[dependencies]
reqsign = { version = "0.17", default-features = false, features = ["aws", "default-context"] }
```

## Examples

### Option 1: Using Default Signers (Recommended)

The easiest way to get started is using the default signers provided for each service:

```rust,ignore
use anyhow::Result;
use reqsign::aws;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a default signer for AWS S3 in us-east-1
    // This will automatically:
    // - Set up HTTP client and file reader
    // - Load credentials from environment, config files, or instance metadata
    let signer = aws::default_signer("s3", "us-east-1");

    // Build and sign a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;

    println!("Request signed successfully!");
    Ok(())
}
```

### Option 2: Custom Assembly

For more control, you can manually assemble the signer components:

```rust,ignore
use anyhow::Result;
use reqsign::{Context, Signer, default_context};
use reqsign::aws::{DefaultCredentialProvider, RequestSigner};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a context with default implementations
    let ctx = default_context();

    // Or build your own context with specific implementations
    let ctx = Context::new()
        .with_file_read(reqsign_file_read_tokio::TokioFileRead)
        .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
        .with_env(reqsign::OsEnv);

    // Configure credential provider and request signer
    let credential_provider = DefaultCredentialProvider::new();
    let request_signer = RequestSigner::new("s3", "us-east-1");

    // Assemble the signer
    let signer = Signer::new(ctx, credential_provider, request_signer);

    // Build and sign a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;

    println!("Request signed successfully!");
    Ok(())
}
```

### Customizing Default Signers

You can customize the default signers using the `with_*` methods:

```rust,ignore
use reqsign::aws;
use reqsign::aws::StaticCredentialProvider;

// Start with default signer and customize components
let signer = aws::default_signer("s3", "us-east-1")
    .with_credential_provider(StaticCredentialProvider::new(
        "my-access-key",
        "my-secret-key",
        None,  // Optional session token
    ))
    .with_context(my_custom_context);
```

### Examples for Other Services

```rust,ignore
// Azure Storage
use reqsign::azure;
let signer = azure::default_signer();

// Google Cloud
use reqsign::google;
let signer = google::default_signer("storage.googleapis.com");

// Aliyun OSS
use reqsign::aliyun;
let signer = aliyun::default_signer("mybucket");

// Huawei Cloud OBS
use reqsign::huaweicloud;
let signer = huaweicloud::default_signer("mybucket");

// Tencent COS
use reqsign::tencent;
let signer = tencent::default_signer();

// Oracle Cloud
use reqsign::oracle;
let signer = oracle::default_signer();
```

## Feature Flags

- `default`: Enables `default-context`
- `default-context`: Provides a default context implementation using `reqwest` and `tokio`
- `aliyun`: Enable Aliyun OSS support
- `aws`: Enable AWS services support
- `azure`: Enable Azure Storage support
- `google`: Enable Google Cloud support
- `huaweicloud`: Enable Huawei Cloud OBS support
- `oracle`: Enable Oracle Cloud support
- `tencent`: Enable Tencent COS support

## WASM Support

This crate supports WebAssembly (WASM) targets. However, the `default-context` feature is not available on WASM due to platform limitations. When targeting WASM, you should:

1. Disable default features
2. Use the existing context implementations from `reqsign-file-read-tokio` and `reqsign-http-send-reqwest` crates
3. Or implement your own WASM-compatible context

Example for WASM:
```toml
[dependencies]
reqsign = { version = "0.17", default-features = false, features = ["aws"] }
reqsign-http-send-reqwest = "0.1"
```
