# reqsign-aliyun-oss

Aliyun OSS signing implementation for reqsign.

---

This crate provides signing support for Alibaba Cloud Object Storage Service (OSS), enabling secure authentication for all OSS operations.

## Quick Start

```rust
use reqsign_aliyun_oss::{
    AssumeRoleWithOidcCredentialProvider, ConfigFileCredentialProvider,
    CredentialsFileCredentialProvider, DefaultCredentialProvider, EnvCredentialProvider,
    OssProfileCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use reqsign_core::{Context, Result, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> Result<()> {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default());

    let loader = DefaultCredentialProvider::builder()
        .env(EnvCredentialProvider::new())
        .oss_profile(OssProfileCredentialProvider::new())
        .credentials_file(CredentialsFileCredentialProvider::new())
        .config_file(ConfigFileCredentialProvider::new())
        .oidc(AssumeRoleWithOidcCredentialProvider::new())
        .build();

    // Or use static credentials:
    // let loader = StaticCredentialProvider::new(
    //     "your-access-key-id",
    //     "your-access-key-secret",
    // );

    let signer = Signer::new(ctx, loader, RequestSigner::new("bucket"));

    let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;
    Ok(())
}
```

## Features

- **HMAC-SHA1 Signing**: Complete implementation of Aliyun's signing algorithm
- **Multiple Credential Sources**: Environment variables, OSS profile files, Alibaba shared credential/config files, and OIDC-based STS exchange
- **STS Support**: Temporary credentials via Security Token Service
- **All OSS Operations**: Object, bucket, and multipart operations

## Credential Sources

### Environment Variables

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=your-access-key-id
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-access-key-secret
export ALIBABA_CLOUD_SECURITY_TOKEN=your-sts-token  # Optional
export OSS_ACCESS_KEY_ID=your-access-key-id         # Alias
export OSS_ACCESS_KEY_SECRET=your-access-key-secret # Alias
export OSS_SESSION_TOKEN=your-sts-token             # Alias
```

### OSS Profile File

Reads from `~/.oss/credentials` by default:

```ini
[default]
access_key_id = your-access-key-id
access_key_secret = your-access-key-secret
session_token = optional-session-token

[prod]
access_key_id = prod-access-key-id
access_key_secret = prod-access-key-secret
```

Override the file path with `OSS_CREDENTIAL_PROFILES_FILE` and the selected profile with `OSS_PROFILE`.

### Alibaba Shared Credentials File

Reads from `~/.alibabacloud/credentials.ini` first and falls back to `~/.aliyun/credentials.ini`:

```ini
[default]
enable = true
type = access_key
access_key_id = your-access-key-id
access_key_secret = your-access-key-secret

[prod]
enable = true
type = sts_token
access_key_id = prod-access-key-id
access_key_secret = prod-access-key-secret
sts_token = optional-session-token
```

Override the file path with `ALIBABA_CLOUD_CREDENTIALS_FILE` and the selected profile with `ALIBABA_CLOUD_PROFILE`.

Only direct static modes are loaded in this crate today: `access_key` and `sts_token`.

### Alibaba CLI Config File

Reads from `~/.aliyun/config.json` by default:

```json
{
  "current": "default",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "your-access-key-id",
      "access_key_secret": "your-access-key-secret"
    }
  ]
}
```

Override the file path with `ALIBABA_CLOUD_CONFIG_FILE` and the selected profile with `ALIBABA_CLOUD_PROFILE`.

Only direct static modes are loaded in this crate today: `AK` and `StsToken`.

### STS AssumeRole with OIDC

For Kubernetes/ACK environments:

```rust
use reqsign_aliyun_oss::{AssumeRoleWithOidcCredentialProvider, DefaultCredentialProvider};

// Set ALIBABA_CLOUD_ROLE_ARN, ALIBABA_CLOUD_OIDC_PROVIDER_ARN,
// and ALIBABA_CLOUD_OIDC_TOKEN_FILE in the environment.
let loader = DefaultCredentialProvider::builder()
    .no_env()
    .no_oss_profile()
    .no_credentials_file()
    .no_config_file()
    .oidc(
        AssumeRoleWithOidcCredentialProvider::new().with_role_session_name("my-session"),
    )
    .build();
```

The session name defaults to `reqsign`. To customize it, set `ALIBABA_CLOUD_ROLE_SESSION_NAME` or use `AssumeRoleWithOidcCredentialProvider::with_role_session_name`.

## OSS Operations

### Object Operations

```rust
// Get object
let req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
    .body(())?;

// Put object
let req = http::Request::put("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
    .header("Content-Type", "text/plain")
    .body(content)?;

// Delete object
let req = http::Request::delete("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
    .body(())?;

// Copy object
let req = http::Request::put("https://bucket.oss-cn-beijing.aliyuncs.com/new-object.txt")
    .header("x-oss-copy-source", "/source-bucket/source-object.txt")
    .body(())?;
```

### Bucket Operations

```rust
// List objects
let req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/")
    .body(())?;

// List with parameters
let req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?prefix=photos/&max-keys=100")
    .body(())?;

// Get bucket info
let req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?bucketInfo")
    .body(())?;

// Get bucket location
let req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?location")
    .body(())?;
```

### Multipart Upload

```rust
// Initiate multipart upload
let req = http::Request::post("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt?uploads")
    .body(())?;

// Upload part
let req = http::Request::put("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt?partNumber=1&uploadId=xxx")
    .body(part_data)?;
```

## Endpoints

### Public Endpoints

```rust
// Standard endpoint
"https://bucket.oss-cn-beijing.aliyuncs.com"

// Dual-stack endpoint (IPv4/IPv6)
"https://bucket.oss-cn-beijing.dualstack.aliyuncs.com"
```

### Internal Endpoints (VPC)

```rust
// For better performance within Aliyun VPC
"https://bucket.oss-cn-beijing-internal.aliyuncs.com"
```

### Accelerate Endpoints

```rust
// Global acceleration
"https://bucket.oss-accelerate.aliyuncs.com"

// Overseas acceleration
"https://bucket.oss-accelerate-overseas.aliyuncs.com"
```

## Examples

Check out the examples directory:
- [Basic OSS operations](examples/oss_operations.rs) - Common OSS operations

```bash
cargo run --example oss_operations
```

## Regions

Common OSS regions:
- `oss-cn-beijing` - Beijing
- `oss-cn-shanghai` - Shanghai
- `oss-cn-shenzhen` - Shenzhen
- `oss-cn-hangzhou` - Hangzhou
- `oss-cn-hongkong` - Hong Kong
- `oss-ap-southeast-1` - Singapore
- `oss-us-west-1` - US West
- `oss-eu-central-1` - Frankfurt

## Advanced Configuration

### Custom Credentials

```rust
use reqsign_aliyun_oss::StaticCredentialProvider;

let loader = StaticCredentialProvider::new("your-access-key-id", "your-access-key-secret");
```

### Force Specific Loader

```rust
use reqsign_aliyun_oss::DefaultCredentialProvider;

let loader = DefaultCredentialProvider::builder().no_oidc().build();
```

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
