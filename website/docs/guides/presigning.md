---
title: Presigning and query authentication
sidebar_label: Presigning & query auth
description: Move authentication from headers into the URL and hand out presigned requests safely.
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

Providers authenticate requests in two places. **Headers** are the default:
the signature travels with the request and dies with it. **The query
string** embeds authentication in the URI itself, so whoever holds the URL
can perform exactly that request with no credentials of their own — that is
what "presigned URLs" are.

```rust
// Header signing:
signer.sign(&mut req, None).await?;

// Query authentication, valid for 1 hour (where supported):
signer.sign(&mut req, Some(Duration::from_secs(3600))).await?;
```

| Situation | Mode |
| --- | --- |
| Your service makes the request itself | Header signing |
| A browser, another service, or a user uploads/downloads directly | Query authentication |
| The credential itself is already scoped (SAS) | Query by nature |

## Produce a presigned URL

```rust
use std::time::Duration;
use reqsign::aws;

let signer = aws::default_signer("s3", "us-east-1");

let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://s3.amazonaws.com/my-bucket/report.csv")
    .body(())?
    .into_parts()
    .0;

// The signature moves into the query string, valid for one hour.
signer.sign(&mut req, Some(Duration::from_secs(3600))).await?;

// req.uri is the shareable URL.
println!("{}", req.uri);
```

For AWS this produces `X-Amz-Algorithm`, `X-Amz-Credential`,
`X-Amz-Expires`, `X-Amz-Signature`, and companions in the query string.
Other providers use their own parameter sets; the shape of the call is
identical.

## `expires_in` is service-specific

Passing `Some(duration)` does **not** universally mean "presign" — the
configured service signer and credential type determine how the duration is
interpreted:

- AWS SigV4/SigV4a, Aliyun OSS, Tencent COS, Volcengine TOS, and Google
  Cloud Storage select query authentication with that validity window.
- Azure Storage SAS credentials authenticate through the query string by
  nature; shared keys and bearer tokens sign headers.
- Huawei Cloud OBS and Oracle Cloud bound credential validity but produce
  **no** query authentication — header signing is their only mode.

The [provider matrix](/docs/providers/) carries the authoritative
header/query flags, and the
[expiration contract](/docs/reference/signing-contracts/#expiration-semantics)
states the exact semantics.

## Before you ship one

- **The method and URI are part of the signature.** A URL presigned for
  `GET /report.csv` authorizes exactly that — not `PUT`, not another key.
- **Credential validity must cover the window.** The signer refreshes a
  cached credential that would expire before `expires_in` elapses, and
  errors if no credential can cover the window — a URL that dies early is a
  bug, not a surprise. See
  [Credential freshness](/docs/reference/signing-contracts/#credential-freshness).
- **Anyone with the URL is authorized.** Treat presigned URLs as secrets
  with a TTL: transmit over TLS, scope tightly, keep windows short.
- **Never re-encode a presigned URI.** The signature covers the encoded
  bytes; a second encoding pass breaks it. See
  [Wire-ready URIs](/docs/reference/signing-contracts/#wire-ready-uris).
- **Tighter blast radius:** [grant a downscoped
  credential](/docs/guides/granting/) first and presign with that.
