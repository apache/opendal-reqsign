---
title: Loading credentials
sidebar_label: Loading credentials
description: Use each provider's default credential chain, adjust its slots, or implement your own credential source.
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

Everything about getting credentials into a signer: use the default chain,
bend it, or replace it entirely.

## Use the default chain

Every service crate ships a `DefaultCredentialProvider` composing that
provider's documented default chain — the same sources the official CLIs and
SDKs consult, in a documented order. Each
[provider page](/docs/providers/) lists its exact sources.

```rust
use reqsign_aws_v4::DefaultCredentialProvider;

// The documented default chain for AWS:
// env → profiles → SSO → OIDC → process → ECS → IMDS
let provider = DefaultCredentialProvider::new();
```

Every `DefaultCredentialProvider` exposes the same four entry points:

```rust
DefaultCredentialProvider::new();                // the documented default chain
DefaultCredentialProvider::builder();            // default slots, then adjust
DefaultCredentialProvider::with_chain(chain);    // bypass defaults entirely
DefaultCredentialProvider::push_front(provider); // prepend a high-priority source
```

## Adjust the chain

The builder pre-populates the default slots. Each slot has exactly two
methods — one to replace it, one to remove it:

```rust
use reqsign_aws_v4::{DefaultCredentialProvider, EnvCredentialProvider};

// Replace the env slot, drop IMDS, keep everything else as documented.
let provider = DefaultCredentialProvider::builder()
    .env(EnvCredentialProvider::new())
    .no_imds()
    .build();
```

There are no `configure_*` or `disable_*(bool)` methods by design: a removed
slot stays removed, and every slot is controlled by one positive and one
removal method.

## Fixed credentials

When the credential is decided elsewhere — tests, WASM, a control plane that
injects keys — skip chains entirely:

```rust
use reqsign::aws;
use reqsign_aws_v4::StaticCredentialProvider;

let signer = aws::default_signer("s3", "us-east-1")
    .with_credential_provider(StaticCredentialProvider::new(
        "AKIDEXAMPLE",
        "example-secret-key",
        None, // session token
    ));
```

Replacing a signer's credential provider clears its credential cache, so a
credential from the old chain is never reused with the new configuration.

## Implement your own source

When credentials come from somewhere Reqsign doesn't know — a secret
manager, a sidecar, an in-house vault — implement `ProvideCredential`:

```rust
use bytes::Bytes;
use reqsign_core::{Context, ProvideCredential, Result};
use reqsign_aws_v4::Credential;

#[derive(Debug)]
struct VaultCredentialProvider {
    endpoint: String,
}

impl ProvideCredential for VaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context)
        -> Result<Option<Self::Credential>>
    {
        // Use the Context for I/O so your provider stays runtime-agnostic
        // and testable — here, an HTTP call through ctx.
        let req = http::Request::get(&self.endpoint).body(Bytes::new())?;
        let resp = ctx.http_send(req).await?;

        // Return Ok(None) when this source has nothing to offer,
        // so a chain can continue to the next provider.
        if resp.status() == http::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let credential = parse_vault_response(resp.body())?;
        Ok(Some(credential))
    }
}
```

The return-value protocol is what makes chains compose: `Ok(Some(_))`
resolves, `Ok(None)` passes to the next source, `Err(_)` aborts with the
error. Report "not configured" as `None` and real failures as errors — see
[Architecture § ProvideCredential](/docs/architecture/#providecredential).

## Plug it in

Highest priority in front of the default chain:

```rust
use reqsign_aws_v4::DefaultCredentialProvider;

let provider = DefaultCredentialProvider::push_front(VaultCredentialProvider {
    endpoint: "http://127.0.0.1:8200/v1/aws/creds/my-role".into(),
});
```

Or a fully explicit chain that bypasses the defaults:

```rust
use reqsign_core::ProvideCredentialChain;

let chain = ProvideCredentialChain::new()
    .push(VaultCredentialProvider { endpoint })
    .push(EnvCredentialProvider::new());
let provider = DefaultCredentialProvider::with_chain(chain);
```

Then hand it to a default signer (`.with_credential_provider(provider)`) or
a custom `Signer::new`.

## Freshness

The credential type you return implements `SigningCredential`; set its
expiration so
[caching](/docs/architecture/#credential-caching-and-validity) refreshes it
on time. Credentials without an expiration are cached until the provider is
replaced.
