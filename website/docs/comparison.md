---
title: Reqsign vs vendor SDKs
sidebar_label: Reqsign vs vendor SDKs
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

If you are building your own HTTP client, SDK, proxy, or storage engine, the
real decision is between two ways of getting requests signed: pull in each
cloud's full SDK, or use a dedicated signing layer.

| | Reqsign | Vendor SDKs |
| --- | --- | --- |
| **Scope** | Signing, credential loading, scoped granting — nothing else | The cloud's full API surface: clients, request/response models, transports |
| **HTTP client** | Yours — Reqsign mutates a plain `http::request::Parts` and hands it back | Bundled; requests flow through the SDK's own stack |
| **Retries, pooling, middleware** | Yours | The SDK's |
| **Dependency footprint** | One signing crate per provider, plus the runtime pieces you opt into | Per-cloud SDK trees, each with its own HTTP and TLS choices |
| **Multi-cloud** | One composition pattern (`Context` + `ProvideCredential` + `SignRequest`) across nine providers, protocols kept explicit | One SDK per cloud, each with its own idioms |
| **Custom runtimes / WASM** | Pluggable I/O via [`Context`](/docs/architecture/#context), `wasm32-unknown-unknown` for a [verified subset](/docs/reference/versioning-and-targets/#targets) | Generally assumes the SDK's supported runtimes |
| **Beyond signing** | Out of scope by design | Pagination, waiters, service helpers, management APIs |

## When Reqsign fits

You own the HTTP layer and want to keep it: a database's storage backend, a
CLI, a gateway, an SDK of your own. You need wire-correct signatures,
production-grade credential chains, and perhaps presigning or downscoped
grants — without inheriting a vendor SDK's HTTP stack, retry policy, and
dependency tree per cloud.

## When a vendor SDK fits

You need broad coverage of one cloud's API surface — management operations,
typed request/response models, service-specific helpers — and the SDK's
bundled stack fits your application. Signing is a fraction of what those SDKs
do; Reqsign replaces only that fraction.

## Relationship to Apache OpenDAL

Reqsign is an independent library incubating as a subproject of
[Apache OpenDAL™](https://opendal.apache.org/), governed by the OpenDAL PMC.
The dependency points one way: OpenDAL's cloud storage services sign their
requests with Reqsign; Reqsign does not depend on OpenDAL.

The two serve different builders. Reqsign gives you signing primitives for a
client you are writing yourself. OpenDAL is a ready-made data access layer —
if what you actually want is to read and write storage behind one API rather
than construct requests, use OpenDAL and you get Reqsign's signing underneath
for free.
