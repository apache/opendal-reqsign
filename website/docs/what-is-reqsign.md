---
title: What is Reqsign?
sidebar_label: What is Reqsign?
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

Reqsign is a Rust library that signs HTTP requests for cloud provider APIs. It
covers the three jobs a vendor SDK normally bundles with everything else:

1. **Load credentials** — from environment variables, config files, instance
   metadata, OIDC federation, CLIs, and more, through per-provider default
   chains you can replace or extend.
2. **Grant scoped access** — exchange broad credentials for downscoped ones
   (S3 Access Grants, S3 Express sessions, Azure user delegation SAS, GCP
   Credential Access Boundary) before a request is ever signed.
3. **Sign requests** — mutate a plain `http::request::Parts` in place, adding
   authentication headers or query parameters that match each provider's
   protocol exactly.

Everything else stays yours: the HTTP client, retries, connection pooling, and
the runtime. Reqsign never sends your requests.

```rust
use reqsign::aws;

// Credentials load from env, profiles, SSO, IMDS — the default chain.
let signer = aws::default_signer("s3", "us-east-1");

// Build the request with plain http types.
let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://s3.amazonaws.com/my-bucket/my-object")
    .body(())?
    .into_parts()
    .0;

// Sign in place, then send with the HTTP client you already use.
signer.sign(&mut req, None).await?;
```

## Who Reqsign is for

- **SDK and HTTP client authors** who need wire-correct signing without
  inheriting a vendor SDK's HTTP stack and dependency tree.
- **Infrastructure and library authors** embedding signing into storage
  engines, databases, proxies, or gateways, who care about runtime
  abstraction, credential injection, and failure atomicity.
- **WASM and custom-runtime users** who cannot assume a filesystem, process
  environment, or Tokio, and need every I/O dependency to be pluggable.

Reqsign is a signing layer, not a data-access API. Deciding between Reqsign
and a full vendor SDK? See the
[comparison](/docs/comparison/). (And if you want ready-made storage
access rather than signing primitives,
[Apache OpenDAL™](https://opendal.apache.org/) provides it — with Reqsign
signing its requests underneath.)

## What makes it different

- **Explicit protocols.** Signers and credential types stay service-specific
  because the differences between SigV4, Shared Key, and OAuth are real.
  What's shared is one composition pattern: `Context` + `ProvideCredential` +
  `SignRequest`, assembled into a `Signer`.
- **Documented wire contracts.** URI encoding ownership,
  [atomic request mutation](/docs/reference/signing-contracts/#atomic-request-mutation), credential
  [freshness](/docs/reference/signing-contracts/#credential-freshness) and
  [expiration](/docs/reference/signing-contracts/#expiration-semantics), and
  [secret redaction](/docs/reference/signing-contracts/#secret-redaction) are specified, not
  incidental.
- **A runtime you control.** [`Context`](/docs/architecture/#context) makes file
  reading, HTTP sending, environment access, and command execution pluggable —
  down to `wasm32-unknown-unknown`.

## Next steps

- [Install and sign your first request](/docs/getting-started/) — five minutes.
- [Browse the provider matrix](/docs/providers/) — what each cloud supports.
- [Understand the architecture](/docs/architecture/) — the five pieces you compose.
