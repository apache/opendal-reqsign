# reqsign-oracle

Oracle Cloud Infrastructure request signing implementation for reqsign.

The default credential provider checks OCI environment variables and then the
OCI configuration file at `~/.oci/config`. The config path and profile can be
selected with `OCI_CONFIG_FILE` and `OCI_PROFILE`.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_oracle::{DefaultCredentialProvider, RequestSigner};

let context = Context::new()
    .with_file_read(TokioFileRead)
    .with_env(OsEnv);

let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new(),
);
```

The environment provider reads `OCI_USER`, `OCI_TENANCY`, `OCI_KEY_FILE`, and
`OCI_FINGERPRINT`. Use `StaticCredentialProvider` or
`DefaultCredentialProvider::builder()` for explicit configuration.

## Examples

- [Credential-chain logging](examples/oracle_chain_logging.rs)

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
