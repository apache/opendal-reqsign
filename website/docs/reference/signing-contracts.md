---
title: Signing contracts
sidebar_label: Signing contracts
description: The behavioral guarantees of sign and grant — URI ownership, atomicity, freshness, expiration, redaction, and error semantics.
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

Reqsign's behavior at the edges is specified, not incidental. This page is
the reference for the six contracts `sign` and `grant` uphold; each is
backed by the API documentation in `reqsign-core` and exercised by tests.

## Wire-ready URIs

**The contract:** `sign` takes a *wire-ready* request head. The URI you pass
is the URI that goes on the wire — built-in signers require an authority and
expect path and query data to be **percent-encoded exactly once** before the
call. Signing does not perform general-purpose URI encoding for the caller.

Signature protocols canonicalize the URI (SigV4 builds its canonical request
from the encoded path and sorted query). If the signer re-encoded your
input, an already-encoded `%2F` would double-encode while a raw space got
"helpfully" fixed — and the signed bytes would depend on who encoded last.
Exactly-once encoding, owned by the caller, removes the ambiguity: what you
signed is what you send.

```rust
// Object key: "reports/2026 Q1.csv" — encode once when building the URI:
let uri = "https://s3.amazonaws.com/my-bucket/reports/2026%20Q1.csv";
```

Rules of thumb: encode path segments and query values once, when
constructing the URI; never pass a decoded "pretty" URI expecting a fix-up;
never re-encode after signing (for presigned URLs this breaks the
signature); relative URIs are not signable. Some service crates export
percent-encoding helpers tuned to their provider's canonicalization (for
example `reqsign-volcengine-tos`'s `percent_encode_path`).

## Atomic request mutation

**The contract:** if credential loading or request signing returns an error,
the request is **unchanged**. On success, only `req.uri` and `req.headers`
may change; the method, version, and extensions retain their input values.

```rust
match signer.sign(&mut req, None).await {
    Ok(()) => { /* req is signed: uri and/or headers updated, nothing else */ }
    Err(e) => { /* req is byte-for-byte what you built */ }
}
```

Without atomicity, an error path could leave a half-signed request — an
`Authorization` header from one attempt, query parameters from another —
forcing callers to rebuild requests defensively around every failure. With
it: retries reuse the original request as-is, fallback signing is safe, and
a request never carries remnants of a signature that was not fully produced.
The guarantee covers the request head; bodies are never touched.

## Credential freshness

**The contract:** a cached credential is reused only when it is fresh
according to `SigningCredential::is_valid` **and** usable through the
operation's deadline (`required_valid_until`). A freshly loaded credential
only needs to satisfy the exact operation deadline. Provider errors are
returned without internal retry and without falling back to the previously
cached credential.

The two validity checks have different jobs — `is_valid()` answers the
*caching* question and may include a proactive refresh window;
`is_valid_at(ts)` answers the *operation* question with no buffers (see
[Architecture](/docs/architecture/#credential-caching-and-validity)).
Deadlines come from the operation: essentially "now" for header signing, the
full window for a presigned URL — so a credential expiring in five minutes
triggers a refresh rather than producing a URL that dies early.

## Expiration semantics

**The contract:** `expires_in` is a *service-specific validity input*. It
does not universally select query authentication — the configured service
signer and credential type determine how the duration is interpreted.

| Interpretation | Providers |
| --- | --- |
| Selects query authentication with that validity window | AWS SigV4/SigV4a, Aliyun OSS, Tencent COS, Volcengine TOS, Google Cloud Storage (V4 signed URLs) |
| Bounds credential validity; header signing regardless | Huawei Cloud OBS, Oracle Cloud |
| Requests a granted credential's validity window | Granting operations (subject to the operation's own maximum) |

Whatever the provider does with it, one obligation is universal: the
credential used must remain usable for the full window — the signer
refreshes or errors rather than producing an artifact that dies early. And
three things it never means: it never *shortens* a credential's own
lifetime; it never overrides a provider-side maximum (S3 presign caps at 7
days — exceeding a cap is a provider-side error, not silent truncation);
and `None` never means "no expiry" for the artifact (header signatures
still embed timestamps with provider-defined validity).

## Secret redaction

**The contract:** formatting Reqsign types with `Debug` does not reveal
secret material. Credential types implement `Debug` by hand, wrapping
sensitive fields in a `Redact` helper; composite types like `Signer` print
structure, not contents. Non-sensitive metadata (like expiration) prints
normally so logs stay useful.

```rust
log::debug!("loaded: {credential:?}");
// Credential { access_key_id: Redacted, secret_access_key: Redacted, ... }
```

Redaction covers *accidental* leaks — `{:?}` in a log line, a panic message,
an error chain. It cannot protect secrets you extract on purpose: accessor
methods return real values, and a signed request's `Authorization` header or
presigned URI **contains derived authentication material** — log a presigned
URI and you have logged a usable capability. Redact at your logging layer,
and give custom `ProvideCredential` implementations a manual `Debug` over
redacted fields too. Report suspected leaks through the
[ASF security process](https://www.apache.org/security/), never the public
issue tracker.

## Errors and retries

**The contract:** Reqsign surfaces errors; you own resilience. `sign` and
`grant` perform no internal retries, no fallback signers, and no silent
reuse of stale credentials. Combined with atomic mutation, any error leaves
you exactly where you started — free to retry, reroute, or fail.

`reqsign_core::Error` carries an `ErrorKind` designed for retry decisions:

| Kind | Meaning | Sensible default |
| --- | --- | --- |
| `CredentialInvalid` | Credential missing, expired, or unusable | Refresh source, then retry |
| `PermissionDenied` | Authenticated but not authorized | Do not retry |
| `ConfigInvalid` | Malformed profile/config input | Fix configuration; do not retry |
| `RequestInvalid` | The request cannot be signed as given | Fix the request; do not retry |
| `RateLimited` | A credential endpoint throttled us | Retry with backoff |
| `Unexpected` | Transient or unclassified failure | Retry with backoff, bounded |

Errors preserve their source chain (`std::error::Error::source`), so
transport details from a metadata fetch or STS exchange stay inspectable.

Why no built-in retry: Reqsign sits *inside* clients that already have retry
policies — an HTTP middleware, a storage layer, a job runner. A second,
inner retry loop multiplies attempts invisibly and turns rate limits into
storms. Most callers simply propagate signing errors to the layer that
already retries requests.
