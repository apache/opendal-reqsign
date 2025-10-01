# reqsign-aws-v4

AWS SigV4 signing implementation for reqsign.

---

This crate provides AWS Signature Version 4 (SigV4) signing capabilities for authenticating requests to AWS services like S3, DynamoDB, Lambda, and more.

## Quick Start

```rust
use reqsign_aws_v4::{Builder, Config, DefaultLoader};
use reqsign_core::{Context, Signer};

// Create context and signer
let ctx = Context::default();
let config = Config::default().from_env().from_profile();
let loader = DefaultLoader::new(config);
let builder = Builder::new("s3", "us-east-1");
let signer = Signer::new(ctx, loader, builder);

// Sign requests
let mut req = http::Request::get("https://s3.amazonaws.com/mybucket/mykey")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
```

## Features

- **Complete SigV4 Implementation**: Full AWS Signature Version 4 support
- **Multiple Credential Sources**: Environment, files, IAM roles, and more
- **Service Agnostic**: Works with any AWS service using SigV4
- **Async Support**: Built for modern async Rust applications

## Credential Sources

This crate supports loading credentials from:

1. **Environment Variables**
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_SESSION_TOKEN=your_session_token  # Optional
   ```

2. **Credential File** (`~/.aws/credentials`)
   ```ini
   [default]
   aws_access_key_id = your_access_key
   aws_secret_access_key = your_secret_key
   
   [production]
   aws_access_key_id = prod_access_key
   aws_secret_access_key = prod_secret_key
   ```

3. **IAM Roles** (EC2, ECS, Lambda)
   - Automatically detected and used when running on AWS infrastructure

4. **AssumeRole with STS**
   ```rust
   let config = Config::default()
       .role_arn("arn:aws:iam::123456789012:role/MyRole")
       .role_session_name("my-session");
   ```

5. **Web Identity Tokens** (EKS/Kubernetes)
   - Automatically detected in EKS environments

## Supported Services

Works with any AWS service using SigV4:

- **Storage**: S3, EBS, EFS
- **Database**: DynamoDB, RDS, DocumentDB
- **Compute**: EC2, Lambda, ECS
- **Messaging**: SQS, SNS, EventBridge
- **Analytics**: Kinesis, Athena, EMR
- And many more...

## Examples

### S3 Operations

```rust
// List buckets
let req = http::Request::get("https://s3.amazonaws.com/")
    .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
    .body(())?;

// Get object
let req = http::Request::get("https://bucket.s3.amazonaws.com/key")
    .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
    .body(())?;
```

### DynamoDB Operations

```rust
// List tables
let req = http::Request::post("https://dynamodb.us-east-1.amazonaws.com/")
    .header("x-amz-target", "DynamoDB_20120810.ListTables")
    .header("content-type", "application/x-amz-json-1.0")
    .body(json!({}))?;
```

Check out more examples:
- [S3 signing example](examples/s3_sign.rs)
- [DynamoDB signing example](examples/dynamodb_sign.rs)

## Advanced Configuration

### Custom Profile

```rust
let config = Config::default()
    .profile("production")
    .from_profile();
```

### Assume Role

```rust
let config = Config::default()
    .role_arn("arn:aws:iam::123456789012:role/MyRole")
    .external_id("unique-external-id")
    .duration_seconds(3600);
```

### Direct Credentials

```rust
let config = Config::default()
    .access_key_id("AKIAIOSFODNN7EXAMPLE")
    .secret_access_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    .session_token("optional-session-token");
```

## License

Licensed under [Apache License, Version 2.0](./LICENSE).