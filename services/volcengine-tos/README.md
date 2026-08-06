# reqsign-volcengine-tos

Volcengine Object Storage request signing implementation for reqsign.

This crate supports both header authentication and presigned query
authentication. Its default credential provider reads credentials from the
environment.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_volcengine_tos::{DefaultCredentialProvider, RequestSigner};

let context = Context::new().with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new("cn-beijing"),
);
```

Set `VOLCENGINE_ACCESS_KEY_ID` and `VOLCENGINE_SECRET_ACCESS_KEY`, and
optionally `VOLCENGINE_SESSION_TOKEN`. Use `StaticCredentialProvider` when the
credentials are supplied directly by an application.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
