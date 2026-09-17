# reqsign-google

Google Cloud Platform signing implementation for reqsign.

This crate signs Google Cloud requests with OAuth 2.0 access tokens or service
account credentials. Its default Application Default Credentials chain checks
`GOOGLE_APPLICATION_CREDENTIALS`, the well-known gcloud credentials file, and
the Compute Engine metadata service.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_google::{DefaultCredentialProvider, RequestSigner};
use reqsign_http_send_reqwest::ReqwestHttpSend;

let context = Context::new()
    .with_file_read(TokioFileRead)
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);

let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new("storage"),
);
```

The crate also supports server-side Cloud Storage Credential Access Boundary
downscoping. Enable the `credential-access-boundary-client-side` feature for
local client-side token generation.

For query signing, credential providers preserve a target service account email
when they can determine it from impersonation or VM metadata configuration. The
request signer uses that identity with IAMCredentials `signBlob`. An email set
with `RequestSigner::with_signer_email` takes precedence over the
provider-discovered identity.

## Examples

- [Credential-chain logging](examples/chain_logging.rs)
- [Custom credential chain](examples/custom_chain.rs)

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
