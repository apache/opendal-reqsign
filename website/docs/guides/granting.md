---
title: Scoped credential granting
sidebar_label: Credential granting
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

Granting exchanges a broad credential for a narrower one *before* any request
is signed: scoped to a bucket, a prefix, a permission, a time window. Vendor
SDKs rarely give these operations a common shape; Reqsign's
[`Granter`](/docs/architecture/#granter-and-grantcredential) does, while keeping each provider's
semantics explicit.

## The operations

| Provider | Operation | Scopes to |
| --- | --- | --- |
| AWS SigV4 | S3 Access Grants (`GetDataAccess`) | A registered grant: location, prefix, permission |
| AWS SigV4 | S3 Express Session (`CreateSession`) | One directory bucket, read-only or read-write |
| Azure Storage | User delegation SAS | Container/blob, permissions, validity window |
| Google Cloud | Credential Access Boundary (server-side) | Buckets/prefixes via an STS exchange |
| Google Cloud | Credential Access Boundary (client-side) | Same, derived locally without an STS round-trip |

Each operation is listed with source references on its
[provider page](/docs/providers/).

## Walkthrough: S3 Express session credentials

```rust
use reqsign::{Context, Granter};
use reqsign_aws_v4::{
    DefaultCredentialProvider, S3ExpressSessionConfig,
    S3ExpressSessionGrant, S3ExpressSessionGranter,
    S3ExpressSessionMode, S3ExpressSessionPartition,
};

// Bind the operation: which bucket, which zone, which mode.
let config = S3ExpressSessionConfig::new(
    "my-bucket--usw2-az1--x-s3",
    "usw2-az1",
    "us-west-2",
    S3ExpressSessionPartition::Aws,
)?;
let grant = S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadOnly);

// Compose exactly like a Signer: context + source + operation.
let granter = Granter::new(
    ctx,
    DefaultCredentialProvider::new(),
    S3ExpressSessionGranter::new(config, grant),
);

// Exchange IAM credentials for bucket-scoped session credentials.
let scoped = granter.grant(None).await?;
```

## Using the granted credential

A granted credential implements `SigningCredential` — feed it to a signer
through a static provider, hand it to another process, or presign with it:

```rust
use reqsign::aws;
use reqsign_aws_v4::StaticCredentialProvider;

let signer = aws::default_signer("s3", "us-west-2")
    .with_credential_provider(StaticCredentialProvider::new(
        scoped.access_key_id(),
        scoped.secret_access_key(),
        scoped.session_token(),
    ));
```

## Semantics to rely on

- The **source** credential is cached and revalidated per grant; the granted
  result owns independent material and never aliases the cache.
- `expires_in` requests a validity window where the operation supports one;
  the operation's own maximum applies.
- Errors surface without internal retry or fallback to a stale source — your
  retry policy stays in charge.

Accessor method names on the credential types are provider-specific — see
[docs.rs](https://docs.rs/reqsign-aws-v4) for the exact API.
