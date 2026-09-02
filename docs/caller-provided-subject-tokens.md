# Caller-provided subject tokens

Host applications that already receive an OIDC or other external assertion can
bind that assertion directly to an AWS, Azure, or Google credential provider.
The host must authenticate and authorize the incoming identity before passing
its token to reqsign. Reqsign only performs the configured cloud exchange and
request signing.

`SubjectToken` is opaque to reqsign. An absolute `expires_at` is checked before
exchange I/O; an unknown expiration remains subject to authoritative service
validation. Subject tokens are never added to a default credential chain.

## Per-request AWS example

Create a new provider and signer for each independently authenticated request
identity. Cloned signers share their exchanged-credential cache, while
`Signer::with_credential_provider` creates a new empty cache.

```rust
use reqsign::{Context, Signer, SubjectToken, time::Timestamp};
use reqsign::aws::{
    AssumeRoleWithWebIdentityCredentialProvider, Credential, RequestSigner,
};

fn signer_for_request(
    context: Context,
    oidc_token: String,
    token_expires_at: Timestamp,
) -> Signer<Credential> {
    let provider = AssumeRoleWithWebIdentityCredentialProvider::new()
        .with_role_arn("arn:aws:iam::123456789012:role/request-role")
        .with_subject_token(
            SubjectToken::new(oidc_token).with_expires_at(token_expires_at),
        );

    Signer::new(context, provider, RequestSigner::new("s3", "us-east-1"))
}
```

The equivalent Azure provider setup is:

```rust
use reqsign::SubjectToken;
use reqsign::azure::WorkloadIdentityCredentialProvider;

let provider = WorkloadIdentityCredentialProvider::new()
    .with_tenant_id("tenant-id")
    .with_client_id("client-id")
    .with_subject_token(SubjectToken::new(oidc_token));
```

Google keeps the exchange configuration separate from the token source:

```rust
use reqsign::SubjectToken;
use reqsign::google::{ExternalAccountConfig, ExternalAccountCredentialProvider};

let config = ExternalAccountConfig::new(
    "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
    "urn:ietf:params:oauth:token-type:jwt",
    "https://sts.googleapis.com/v1/token",
);
let provider = ExternalAccountCredentialProvider::from_subject_token(
    config,
    SubjectToken::new(oidc_token),
);
```

Use `with_subject_token_provider` on AWS or Azure and
`ExternalAccountCredentialProvider::from_subject_token_provider` on Google when
the token must be loaded asynchronously. `FileSubjectTokenProvider` preserves
file-backed workloads through `Context`; `StaticSubjectTokenProvider` binds an
in-memory token to one provider identity.
