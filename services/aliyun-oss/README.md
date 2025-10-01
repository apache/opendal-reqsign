# reqsign-aliyun-oss

Aliyun OSS signing implementation for reqsign.

---

This crate provides signing support for Alibaba Cloud Object Storage Service (OSS), enabling secure authentication for all OSS operations.

## Quick Start

```rust
use reqsign_aliyun_oss::{Builder, Config, DefaultLoader};
use reqsign_core::{Context, Signer};

// Create context and signer
let ctx = Context::default();
let config = Config::default()
    .region("oss-cn-beijing")
    .from_env();
let loader = DefaultLoader::new(config);
let builder = Builder::new();
let signer = Signer::new(ctx, loader, builder);

// Sign requests
let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
```

## Features

- **HMAC-SHA1 Signing**: Complete implementation of Aliyun's signing algorithm
- **Multiple Credential Sources**: Environment, config files, ECS RAM roles
- **STS Support**: Temporary credentials via Security Token Service
- **All OSS Operations**: Object, bucket, and multipart operations

## Credential Sources

### Environment Variables

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=your-access-key-id
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-access-key-secret
export ALIBABA_CLOUD_SECURITY_TOKEN=your-sts-token  # Optional
```

### Configuration File

Reads from `~/.aliyun/config.json`:

```json
{
  "current": "default",
  "profiles": [{
    "name": "default",
    "mode": "AK",
    "access_key_id": "your-access-key-id",
    "access_key_secret": "your-access-key-secret",
    "region_id": "cn-beijing"
  }]
}
```

### ECS RAM Role

Automatically used when running on Aliyun ECS with RAM role attached:

```rust
let config = Config::default()
    .region("oss-cn-beijing");
// Credentials loaded automatically from metadata service
```

### STS AssumeRole with OIDC

For Kubernetes/ACK environments:

```rust
let config = Config::default()
    .role_arn("acs:ram::123456789012:role/MyRole")
    .oidc_provider_arn("acs:ram::123456789012:oidc-provider/MyProvider")
    .oidc_token_file_path("/var/run/secrets/token");

let loader = AssumeRoleWithOidcLoader::new(config);
```

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
let config = Config::default()
    .access_key_id("your-access-key-id")
    .access_key_secret("your-access-key-secret")
    .security_token("optional-sts-token")
    .region("oss-cn-beijing");
```

### Force Specific Loader

```rust
// Use only config loader
use reqsign_aliyun_oss::ConfigLoader;

let loader = ConfigLoader::new(config);
```

## License

Licensed under [Apache License, Version 2.0](./LICENSE).