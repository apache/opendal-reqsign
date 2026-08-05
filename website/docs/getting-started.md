---
title: Getting Started
sidebar_label: Getting Started
description: Install Reqsign and sign your first cloud request in five minutes.
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

Five minutes from an empty project to a signed AWS request. The same shape
works for every provider — only the entry point differs.

## 1. Install

Add the `reqsign` facade with the feature for each provider you need
(features are additive):

```bash
cargo add reqsign --features aws
cargo add tokio --features full
cargo add http anyhow
```

| Feature | Enables |
| --- | --- |
| `aws` | AWS SigV4 (alias of `aws-v4`) |
| `aws-v4a` | AWS SigV4a multi-region signing |
| `azure` | Azure Storage |
| `google` | Google Cloud |
| `google-credential-access-boundary-client-side` | Client-side CAB downscoping (implies `google`) |
| `aliyun` | Aliyun OSS |
| `huaweicloud` | Huawei Cloud OBS |
| `oracle` | Oracle Cloud |
| `tencent` | Tencent COS |
| `volcengine` | Volcengine TOS |
| `full` | Everything above |

The default `default-context` feature wires a ready-to-use runtime (Tokio
file reading, reqwest HTTP, Tokio command execution). Keep it unless you are
[bringing your own runtime](/docs/guides/custom-runtimes/). Requires
Rust 1.85.0+.

## 2. Sign your first request

This is the repository's compiled example — CI builds it on every commit:

```rust file=reqsign/examples/aws.rs
```

Three things happen here:

1. `aws::default_signer("s3", "us-east-1")` composes the default runtime
   context with AWS's full credential chain — environment variables, shared
   profiles, SSO, ECS, IMDS, and more. See
   [Loading credentials](/docs/guides/credentials/).
2. The request is built with the plain `http` crate. Reqsign signs
   `http::request::Parts` directly — there is no wrapper client to adopt.
3. `signer.sign(&mut req, None).await?` mutates the request head in place,
   adding the `Authorization` header and companions. Passing
   `Some(duration)` instead selects query authentication where the provider
   supports it — see [Presigning](/docs/guides/presigning/).

## 3. Run it

```bash
AWS_ACCESS_KEY_ID=AKIDEXAMPLE \
AWS_SECRET_ACCESS_KEY=example-secret \
cargo run
```

The example signs the request and prints a confirmation; sending it is your
HTTP client's job. Any placeholder credentials produce a structurally valid
signature — the service rejects them, but the wire format is real.

## Every provider, one pattern

Swap the entry point and the rest of the code stays the same. Each entry
composes that provider's own credential chain — the
[provider pages](/docs/providers/) document exactly which sources:

| Provider | Entry |
| --- | --- |
| [AWS SigV4](/docs/providers/aws-sigv4/) | `aws::default_signer(service, region)` |
| [AWS SigV4a](/docs/providers/aws-sigv4a/) | `aws::v4a::default_signer(service, region_set)` |
| [Azure Storage](/docs/providers/azure-storage/) | `azure::default_signer()` |
| [Google Cloud](/docs/providers/google/) | `google::default_signer(service)` |
| [Aliyun OSS](/docs/providers/aliyun-oss/) | `aliyun::default_signer(bucket)` |
| [Huawei Cloud OBS](/docs/providers/huaweicloud-obs/) | `huaweicloud::default_signer(bucket)` |
| [Oracle Cloud](/docs/providers/oracle/) | `oracle::default_signer()` |
| [Tencent COS](/docs/providers/tencent-cos/) | `tencent::default_signer()` |
| [Volcengine TOS](/docs/providers/volcengine-tos/) | `volcengine::default_signer(region)` |

A default signer is an ordinary `Signer`: replace any component and keep the
rest —

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

## Where to go next

- Wire up credentials your way: [Loading credentials](/docs/guides/credentials/).
- Hand out URLs instead of headers: [Presigning](/docs/guides/presigning/).
- Understand the pieces you just used: [Architecture](/docs/architecture/).
- Check what your provider supports: [provider matrix](/docs/providers/).
