# reqsign-aws-v4

AWS SigV4 signing implementation for `reqsign`.

## Quick Start

```rust,no_run
use reqsign_aws_v4::{DefaultCredentialProvider, RequestSigner};
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let signer = Signer::new(
        ctx,
        DefaultCredentialProvider::new(),
        RequestSigner::new("s3", "us-east-1"),
    );

    let mut req = http::Request::get("https://s3.amazonaws.com/mybucket/mykey")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;
    Ok(())
}
```

## Default Credential Chain

`DefaultCredentialProvider::new()` builds the documented AWS default chain:

1. `env`
2. `profile`
3. `sso`
4. `web_identity`
5. `process`
6. `ecs`
7. `imds`

On `wasm32`, the non-portable `sso` and `process` slots are not available.

## Select a Profile

Use `with_profile(...)` to select one profile consistently for the shared
profile, SSO, and process credential sources. The explicit selection takes
precedence over `AWS_PROFILE`.

```rust,no_run
use reqsign_aws_v4::DefaultCredentialProvider;

let provider = DefaultCredentialProvider::builder()
    .with_profile("production")
    .build();
```

## Customize Slots

Use `DefaultCredentialProvider::builder()` to replace or remove individual slots.
Each slot is represented by `Option<T>` internally: `slot(provider)` enables it,
`no_slot()` removes it, and `build()` only pushes `Some(...)` slots into the
chain.

```rust,no_run
use reqsign_aws_v4::{DefaultCredentialProvider, ProfileCredentialProvider};

let provider = DefaultCredentialProvider::builder()
    .no_env()
    .profile(ProfileCredentialProvider::new().with_profile("production"))
    .no_imds()
    .build();
```

For advanced composition, use `DefaultCredentialProvider::with_chain(...)` or
prepend a higher-priority source with `DefaultCredentialProvider::push_front(...)`.

## S3 Access Grants

Use `S3AccessGrantsGranter` to authorize one typed `GetDataAccess` request with
an existing AWS credential and return the temporary credential issued by S3
Access Grants. The result can be passed directly to the existing AWS signer.

```rust,no_run
use std::time::Duration;

use reqsign_aws_v4::{
    DefaultCredentialProvider, S3AccessGrantsConfig, S3AccessGrantsGrant,
    S3AccessGrantsGranter, S3AccessGrantsPermission, S3AccessGrantsPrivilege,
    S3AccessGrantsTarget,
};
use reqsign_core::{Context, Granter};
use reqsign_http_send_reqwest::ReqwestHttpSend;

# async fn example() -> reqsign_core::Result<()> {
let grant = S3AccessGrantsGrant::new(
    S3AccessGrantsTarget::for_prefix("example-bucket", "customer-a/"),
    S3AccessGrantsPermission::Read,
    S3AccessGrantsPrivilege::Minimal,
);
let granter = Granter::new(
    Context::new().with_http_send(ReqwestHttpSend::default()),
    DefaultCredentialProvider::new(),
    S3AccessGrantsGranter::new(
        S3AccessGrantsConfig::new("111122223333", "us-east-2"),
        grant,
    ),
);
let credential = granter.grant(Some(Duration::from_secs(900))).await?;
# let _ = credential;
# Ok(())
# }
```

## Examples

- [S3 signing example](examples/s3_sign.rs)
- [DynamoDB signing example](examples/dynamodb_sign.rs)
- [S3 Express signing example](examples/s3_express_sign.rs)
