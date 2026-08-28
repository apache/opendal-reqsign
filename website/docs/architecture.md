---
title: Architecture
sidebar_label: Architecture
description: How Reqsign is put together — Context, ProvideCredential, SignRequest, Signer, and Granter — and the three levels at which you can plug in.
---

<!--
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
-->

One page on how Reqsign is put together. Everything you compose is one of
five pieces:

```text
Signer
├── Context            where I/O comes from (files, HTTP, env, commands)
├── ProvideCredential  where credentials come from
└── SignRequest        the provider's wire protocol

Granter                same shape, for downscoping credentials
├── Context
├── ProvideCredential  (source credentials)
└── GrantCredential    the provider's granting operation
```

Signers and credential types stay **service-specific on purpose** — the
differences between SigV4, Shared Key, and OAuth are real, and hiding them
breaks correctness. What every provider shares is this composition pattern.

## Signer

`Signer` composes the three pieces and adds a credential cache:

```rust
use reqsign_core::Signer;

let signer = Signer::new(ctx, credential_provider, request_signer);
signer.sign(&mut req, None).await?;
```

Each `sign` call: checks the cached credential (still valid, and usable
until the operation's deadline?); asks the provider for a fresh one if not;
then hands the request head and credential to the request signer, which
mutates `req` in place.

The exact behavior of `sign` — wire-ready URI ownership, atomicity on error,
`expires_in` semantics — is contractual; see
[Signing contracts](/docs/reference/signing-contracts/).

Builders swap any component while keeping the others:

```rust
let signer = signer
    .with_context(custom_ctx)
    .with_credential_provider(static_provider) // clears the credential cache
    .with_request_signer(other_signer);
```

## Context

`Context` answers "where does I/O come from?" Credential providers need to
read files, call metadata endpoints, inspect environment variables, and
sometimes run CLIs — but Reqsign never hard-codes how. Every capability is a
trait slot:

| Capability | Trait | Default (`default-context`) |
| --- | --- | --- |
| Read files | `FileRead` | `TokioFileRead` |
| Send HTTP requests | `HttpSend` | `ReqwestHttpSend` |
| Read environment | `Env` | `OsEnv` |
| Execute commands | `CommandExecute` | `TokioCommandExecute` |

`Context::new()` wires **no-op stubs**, not silent fallbacks: a credential
source that needs HTTP against a stub context returns an error instead of
quietly doing nothing, so you always know which capabilities you granted.
The facade's `default_context()` returns the full assembly in the table.

```rust
use reqsign::{Context, OsEnv};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

let ctx = Context::new()
    .with_file_read(TokioFileRead)
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);
```

Why traits instead of feature flags: tests inject static env maps and canned
HTTP responses without process-global mutation; sandboxes withhold
capabilities by simply not providing them; and WASM targets provide
browser-backed implementations. See
[Custom runtimes & WASM](/docs/guides/custom-runtimes/).

## ProvideCredential

One trait behind every credential source — an env reader, a config-file
parser, an IMDS client, an OIDC exchanger:

```rust
pub trait ProvideCredential {
    type Credential;

    async fn provide_credential(&self, ctx: &Context)
        -> Result<Option<Self::Credential>>;
}
```

The `Option` is the chain protocol:

- `Ok(Some(credential))` — this source resolved a credential; use it.
- `Ok(None)` — this source has nothing to offer (env var unset, file
  missing); **try the next source**.
- `Err(e)` — this source should have worked but failed (malformed file,
  network error); surface the error.

Chains compose providers in order and take the first `Some`; because "not
configured" is `None` rather than an error, a chain of ten sources stays
quiet until one applies.

`type Credential` is deliberately not a universal struct: AWS needs an
access key pair plus optional session token; Azure models `SharedKey`,
`SasToken`, and `BearerToken` as an enum. Each service crate defines the
credential its signer consumes, and the type system keeps mismatches
impossible. Working with chains and writing your own provider:
[Loading credentials](/docs/guides/credentials/).

## SignRequest

`SignRequest` implements a provider's wire protocol: given a request head
and a credential, produce that provider's exact authentication format.

```rust
pub trait SignRequest {
    type Credential;

    fn required_valid_until(
        &self,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp;

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()>;
}
```

`reqsign_aws_v4::RequestSigner` produces SigV4's canonical request and
`Authorization` header — or `X-Amz-*` query parameters when `expires_in` is
set. `reqsign_azure_storage::RequestSigner` produces Shared Key headers or
appends a SAS token. The trait is shared; the wire behavior deliberately is
not.

`required_valid_until` is how signing stays ahead of expiration: before
signing, the signer asks how long the credential must remain usable — "now"
for a header signature, the full window for a presigned URL — and refreshes
a cached credential that cannot cover it.

## Credential caching and validity

Credential loading can be expensive (an IMDS round-trip, an OIDC exchange),
so `Signer` and `Granter` cache what they load. Two methods on
`SigningCredential` govern reuse:

```rust
pub trait SigningCredential {
    /// May a cached credential be reused? Implementations may include a
    /// proactive refresh window.
    fn is_valid(&self) -> bool;

    /// Is the credential usable at this exact timestamp? No buffers.
    fn is_valid_at(&self, ts: Timestamp) -> bool;
}
```

The two checks have different jobs: `is_valid` answers the *caching*
question (refresh early rather than mid-flight); `is_valid_at` answers the
*operation* question against a deadline (a credential fine for header
signing can be insufficient for a one-hour presign window). Both must reject
credentials lacking the fields required for authentication.

The reuse rule on every `sign` or `grant`:

1. A cached credential is reused only if `is_valid()` **and** it satisfies
   the operation's deadline.
2. Otherwise the provider is asked for a fresh credential, which only needs
   to satisfy the exact deadline.
3. Provider errors are returned as-is — no internal retry, no silent
   fallback to the previous cached credential. Retry policy belongs to you.

Replacing a signer's credential provider — or a granter's context or source
provider — clears the cache: a credential loaded under one configuration is
never reused under another.

## Granter and GrantCredential

Signing proves a request is yours; granting gets you a *narrower* credential
first. Providers each have an operation for this (S3 Access Grants, S3
Express CreateSession, Azure user delegation SAS, GCP Credential Access
Boundary); Reqsign unifies their shape without hiding their semantics:

```rust
pub trait GrantCredential {
    type Credential: SigningCredential;

    fn required_valid_until(
        &self,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp;

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential>;
}
```

```rust
use reqsign_core::Granter;

let granter = Granter::new(ctx, source_provider, granting_operation);
let scoped = granter.grant(Some(Duration::from_secs(900))).await?;
```

`Granter` caches the *source* credential with the same rules as `Signer`,
and a granted result owns independent material — it never aliases the cached
source, so using it after the source rotates is safe. The walkthrough lives
in [Granting scoped access](/docs/guides/granting/).

## Compiles everywhere: dyn pairs and MaybeSend

Two mechanics keep this composition model portable:

- Every async trait `Foo` has a `FooDyn` counterpart with a blanket
  implementation, so `Signer` stores `Arc<dyn FooDyn>` internally while you
  implement the ergonomic non-dyn trait.
- Trait futures are `MaybeSend`: `Send` on native targets, relaxed on
  `wasm32-unknown-unknown`, which is why the crate compiles for the browser
  without an `async_trait` dependency.

## Where to plug in

The same components are reachable at three levels — pick by how much you
want to control:

**The facade** (`reqsign` crate) — one dependency, feature flags per
provider, `default_signer` entries that wire everything. Best for
applications; still customizable through `with_*` builders.

**Custom assembly** — the same components, wired explicitly. What
`default_signer` does for you, written out:

```rust
use reqsign::{Context, OsEnv, Signer};
use reqsign_aws_v4::{DefaultCredentialProvider, RequestSigner};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

let ctx = Context::new()
    .with_file_read(TokioFileRead)
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);

let signer = Signer::new(
    ctx,
    DefaultCredentialProvider::new(),
    RequestSigner::new("s3", "us-east-1"),
);
```

**Service crates directly** — libraries supporting exactly one provider can
skip the facade and depend on `reqsign-core` plus that service crate,
letting the application choose context implementations:

```toml
[dependencies]
reqsign-core = "3"
reqsign-aws-v4 = "3"
```

| You are building | Use |
| --- | --- |
| An application talking to one or more clouds | facade + `default_signer` |
| An application with a custom runtime or HTTP stack | facade + custom assembly |
| A library exposing one provider | that service crate directly |
| A WASM target | either, without `default-context` — see [Custom runtimes & WASM](/docs/guides/custom-runtimes/) |
