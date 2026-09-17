---
title: Custom runtimes and WASM
sidebar_label: Custom runtimes & WASM
description: Replace any Context capability with your own implementation, down to running in the browser on wasm32-unknown-unknown.
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

Everything I/O-shaped in Reqsign flows through
[`Context`](/docs/architecture/#context). Replace any slot to run on your own
runtime, add instrumentation, sandbox capabilities — or compile to
WebAssembly, which is just the strictest custom runtime of all.

## The four traits

| Trait | Method | Used for |
| --- | --- | --- |
| `FileRead` | `file_read(path) -> Result<Vec<u8>>` | Config files, key files, token files |
| `HttpSend` | `http_send(Request<Bytes>) -> Result<Response<Bytes>>` | Metadata endpoints, STS/OIDC exchanges |
| `Env` | `var(key)`, `vars()`, `home_dir()` | Environment-based sources, path expansion |
| `CommandExecute` | `command_execute(cmd, args) -> Result<Output>` | CLI-backed sources (e.g. Azure CLI) |

(Signatures abbreviated — see
[docs.rs/reqsign-core](https://docs.rs/reqsign-core) for the precise forms;
all futures are `MaybeSend`.)

The ready-made components the facade uses are ordinary implementations of
these traits: `TokioFileRead`, `ReqwestHttpSend`, `TokioCommandExecute`,
plus `OsEnv` from `reqsign-core`. Mix them freely with your own.

## Example: an instrumented HTTP sender

```rust
use bytes::Bytes;
use reqsign_core::{Context, HttpSend, Result};
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[derive(Debug)]
struct TracedHttpSend(ReqwestHttpSend);

impl HttpSend for TracedHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>)
        -> Result<http::Response<Bytes>>
    {
        let uri = req.uri().clone();
        let started = std::time::Instant::now();
        let resp = self.0.http_send(req).await;
        log::debug!("credential fetch {} took {:?}", uri, started.elapsed());
        resp
    }
}

let ctx = Context::new().with_http_send(TracedHttpSend(ReqwestHttpSend::default()));
```

Slots you do not provide stay as no-op stubs that error when used — a
credential source that needs a missing capability fails loudly instead of
silently returning nothing. The same pattern gives you test doubles: an
`Env` over a `HashMap`, an `HttpSend` over canned responses — see
[Testing](/docs/guides/testing/).

## WASM

Reqsign's core and a defined subset of providers compile for
`wasm32-unknown-unknown` — signing from browsers, edge runtimes, and plugin
sandboxes. CI verifies this exact set on every commit:

- `reqsign-core`, `reqsign-aws-core`
- Providers: **AWS SigV4, AWS SigV4a, Azure Storage, Aliyun OSS, Tencent
  COS** (facade features `aws`, `aws-v4a`, `azure`, `aliyun`, `tencent`)

The [provider matrix](/docs/providers/) marks WASM status per provider;
treat providers outside this set as unsupported there until the catalog says
otherwise.

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown \
  --no-default-features --features aws,azure
```

Two mechanics keep the crate WASM-clean: no direct filesystem, environment,
or process access anywhere outside `Context` implementations, and trait
futures that are `MaybeSend` — `Send` on native targets, relaxed on WASM.

### Providing a browser runtime

There is no filesystem and no OS environment in a browser, so provide what
your credential sources actually need — usually just HTTP:

```rust
use bytes::Bytes;
use reqsign_core::{Context, HttpSend, Result, Signer};
use reqsign_aws_v4::{RequestSigner, StaticCredentialProvider};

#[derive(Debug)]
struct FetchHttpSend; // wraps fetch() via wasm-bindgen

impl HttpSend for FetchHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>)
        -> Result<http::Response<Bytes>>
    {
        todo!("drive the request through fetch()")
    }
}

let ctx = Context::new().with_http_send(FetchHttpSend);
let signer = Signer::new(
    ctx,
    StaticCredentialProvider::new("AKIDEXAMPLE", "example-secret-key", None),
    RequestSigner::new("s3", "us-east-1"),
);
```

Static or externally-injected credentials are the norm on WASM — chains that
read files or metadata endpoints have nothing to read in a browser.

:::warning Credentials in browsers
Anything delivered to a browser is readable by its user. Prefer
[granted, downscoped credentials](/docs/guides/granting/) or short-lived
tokens minted by your backend over long-lived keys.
:::
