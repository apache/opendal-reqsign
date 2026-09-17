# reqsign-huaweicloud-obs

Huawei Cloud Object Storage Service signing implementation for reqsign.

The default credential provider reads `HUAWEI_CLOUD_ACCESS_KEY_ID` and
`HUAWEI_CLOUD_SECRET_ACCESS_KEY`, with an optional
`HUAWEI_CLOUD_SECURITY_TOKEN`.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_huaweicloud_obs::{DefaultCredentialProvider, RequestSigner};

let context = Context::new().with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new("bucket"),
);
```

Use `StaticCredentialProvider` for credentials supplied directly by an
application, or `DefaultCredentialProvider::builder()` to replace or remove
the environment credential slot.

## Examples

- [Credential-chain logging](examples/chain_logging.rs)
- [Custom credential chain](examples/custom_chain.rs)

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
