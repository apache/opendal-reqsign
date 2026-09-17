---
title: Testing with mocks
sidebar_label: Testing
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

Reqsign is built to be tested without touching real clouds: credentials are
injectable, and every I/O path routes through
[`Context`](/docs/architecture/#context).

## Deterministic signing tests

Fix the credential; the signature becomes a function of the request:

```rust
use reqsign_core::{Context, Signer};
use reqsign_aws_v4::{RequestSigner, StaticCredentialProvider};

let signer = Signer::new(
    Context::new(), // no I/O needed with static credentials
    StaticCredentialProvider::new("AKIDEXAMPLE", "example-secret-key", None),
    RequestSigner::new("s3", "us-east-1"),
);

let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://s3.amazonaws.com/test-bucket/test-object")
    .body(())?
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
assert!(req.headers.contains_key("authorization"));
```

Use obviously fake material (`AKIDEXAMPLE`) in fixtures — never real keys,
not even expired ones.

## Mocking the environment

Credential chains read env vars and files through `Context`, so tests inject
them without process-global mutation:

```rust
use reqsign_core::{Context, Env};

#[derive(Debug)]
struct StaticEnv(std::collections::HashMap<String, String>);

impl Env for StaticEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    // ...remaining methods delegate similarly
}

let ctx = Context::new().with_env(StaticEnv(
    [("AWS_ACCESS_KEY_ID".into(), "AKIDEXAMPLE".into()),
     ("AWS_SECRET_ACCESS_KEY".into(), "example-secret-key".into())]
    .into(),
));
```

The same pattern applies to `HttpSend` (canned metadata/STS responses) and
`FileRead` (in-memory profiles). This is exactly how the repository tests
IMDS, ECS, SSO, and OIDC flows against local mock servers under
[`services/aws-v4/tests/mocks`](https://github.com/apache/opendal-reqsign/tree/main/services/aws-v4/tests/mocks).

## Integration tests against real services

Per-service integration suites live under `services/<name>/tests/` and stay
skipped unless their `REQSIGN_*` environment variables opt in — see each
suite's README for the exact gate. CI wires secrets for them; locally you can
run the mock-backed tests with plain `cargo test`.
