/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Content model for the landing page. All copy and catalog data lives here so
// the section components stay presentational. Hero statistics and the provider
// grid derive from data/providers.json — the machine-checked capability
// catalog — so the page cannot drift from the code. Code samples mirror the
// compiled examples under reqsign/examples/ and in-tree doc tests.

import catalog from "../../../data/providers.json";

export const REPO_URL = "https://github.com/apache/opendal-reqsign";
export const DOCS_URL = "/docs/getting-started/";
export const PROVIDERS_URL = "/docs/providers/";
export const DISCORD_URL = "https://discord.gg/XQy8yGR2dg";
export const OPENDAL_URL = "https://opendal.apache.org/";

export const providers = catalog.providers;

// Derived, not hand-written: the numbers on the page are the catalog's.
const granterCount = providers.reduce(
  (n, p) => n + p.credential_granting.length,
  0
);
const wasmCount = providers.filter((p) => p.wasm.supported).length;

export const heroStats = [
  { value: `${providers.length}`, label: "cloud providers" },
  { value: `${granterCount}`, label: "granting operations" },
  { value: `${wasmCount}`, label: "WASM-ready providers" },
  { value: "0", label: "vendor SDKs required" },
];

// Hero quickstart tabs. Only providers with a compiled facade example under
// reqsign/examples/ appear here — do not add a tab without adding the example.
export const codeSamples = [
  {
    id: "aws",
    label: "AWS",
    language: "rust",
    install: "$ cargo add reqsign --features aws",
    code: `use reqsign::aws;

// Credentials load from env, profiles, SSO, IMDS — the default chain.
let signer = aws::default_signer("s3", "us-east-1");

// Build the request with plain http types. No wrapper client.
let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://s3.amazonaws.com/my-bucket/my-object")
    .body(())?
    .into_parts()
    .0;

// Sign in place, then send with the HTTP client you already use.
signer.sign(&mut req, None).await?;`,
  },
  {
    id: "azure",
    label: "Azure",
    language: "rust",
    install: "$ cargo add reqsign --features azure",
    code: `use reqsign::azure;

// Shared key, SAS, or Entra ID — resolved by the default chain.
let signer = azure::default_signer();

let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://myaccount.blob.core.windows.net/container/blob")
    .body(())?
    .into_parts()
    .0;

// Sign in place, then send with the HTTP client you already use.
signer.sign(&mut req, None).await?;`,
  },
  {
    id: "google",
    label: "Google",
    language: "rust",
    install: "$ cargo add reqsign --features google",
    code: `use reqsign::google;

// Service accounts, workload identity, VM metadata — the default chain.
let signer = google::default_signer("storage.googleapis.com");

let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://storage.googleapis.com/my-bucket/my-object")
    .body(())?
    .into_parts()
    .0;

// Sign in place, then send with the HTTP client you already use.
signer.sign(&mut req, None).await?;`,
  },
];

export const valueProps = [
  {
    index: "01",
    title: "Signing without a full SDK",
    body: "Build requests with plain http types, sign them in place, and send with any client. Encoded URIs, atomic request mutation, and expiration follow explicit, documented contracts.",
  },
  {
    index: "02",
    title: "Credentials that fit the provider",
    body: "Every provider keeps its own credential semantics. Default chains cover environment, config files, instance metadata, OIDC federation, CLIs, and credential processes.",
  },
  {
    index: "03",
    title: "Scoped access you can grant",
    body: "One Granter abstraction covers S3 Access Grants, S3 Express sessions, Azure user delegation SAS, and GCP Credential Access Boundary — downscoping that vendor SDKs rarely unify.",
  },
  {
    index: "04",
    title: "A runtime you control",
    body: "Context makes file reading, HTTP sending, environment, and command execution pluggable. Swap Tokio and reqwest for your own runtime, or compile to WebAssembly.",
  },
];

// The public composition contract, not an implementation diagram.
export const howItWorks = [
  {
    index: "01",
    title: "Build",
    body: "Construct the request with the http crate's plain types — reqsign never wraps your HTTP client.",
  },
  {
    index: "02",
    title: "Load or grant",
    body: "Resolve credentials through the provider's default chain, your own ProvideCredential, or a Granter that downscopes them first.",
  },
  {
    index: "03",
    title: "Sign, then send",
    body: "One sign call mutates the request head atomically — headers or query string — and hands it back for any client to send.",
  },
];

// Capability explorer. Each snippet mirrors a compiled example or in-tree doc
// test; each doc link lands on the guide that owns the topic.
export const capabilityThemes = [
  {
    title: "Default signer",
    blurb: "One call wires the default context and credential chain.",
    doc: "/docs/getting-started/#every-provider-one-pattern",
    code: `use reqsign::aws;
use reqsign_aws_v4::StaticCredentialProvider;

// The default signer composes the default context
// with the provider's full credential chain.
let signer = aws::default_signer("s3", "us-east-1");

// Override any component without leaving the default path.
let signer = aws::default_signer("s3", "us-east-1")
    .with_credential_provider(StaticCredentialProvider::new(
        "AKIDEXAMPLE",
        "example-secret-key",
        None,
    ));`,
  },
  {
    title: "Custom assembly",
    blurb: "Pick every component of the signer explicitly.",
    doc: "/docs/architecture/#where-to-plug-in",
    code: `use reqsign::{Context, OsEnv, Signer};
use reqsign_aws_v4::{DefaultCredentialProvider, RequestSigner};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

// Wire the runtime pieces yourself: files, HTTP, env.
let ctx = Context::new()
    .with_file_read(TokioFileRead)
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);

let signer = Signer::new(
    ctx,
    DefaultCredentialProvider::new(),
    RequestSigner::new("s3", "us-east-1"),
);`,
  },
  {
    title: "Presigning",
    blurb: "Produce query-authenticated URLs you can hand out.",
    doc: "/docs/guides/presigning/",
    code: `use std::time::Duration;
use reqsign::aws;

let signer = aws::default_signer("s3", "us-east-1");

let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://s3.amazonaws.com/my-bucket/report.csv")
    .body(())?
    .into_parts()
    .0;

// expires_in moves the signature into the query string
// for providers with query authentication (see /docs/providers).
signer.sign(&mut req, Some(Duration::from_secs(3600))).await?;

// req.uri now carries X-Amz-* parameters — share it as-is.`,
  },
  {
    title: "Credential granting",
    blurb: "Downscope credentials before a request is ever signed.",
    doc: "/docs/guides/granting/",
    code: `use reqsign::{Context, Granter};
use reqsign_aws_v4::{
    DefaultCredentialProvider, S3ExpressSessionConfig,
    S3ExpressSessionGrant, S3ExpressSessionGranter,
    S3ExpressSessionMode, S3ExpressSessionPartition,
};

// Exchange IAM credentials for bucket-scoped session
// credentials via S3 Express CreateSession.
let config = S3ExpressSessionConfig::new(
    "my-bucket--usw2-az1--x-s3",
    "usw2-az1",
    "us-west-2",
    S3ExpressSessionPartition::Aws,
)?;
let grant = S3ExpressSessionGrant::new(S3ExpressSessionMode::ReadOnly);

let granter = Granter::new(
    Context::new(),
    DefaultCredentialProvider::new(),
    S3ExpressSessionGranter::new(config, grant),
);
let scoped = granter.grant(None).await?;`,
  },
  {
    title: "Custom context & WASM",
    blurb: "Bring your own runtime — down to wasm32-unknown-unknown.",
    doc: "/docs/guides/custom-runtimes/#wasm",
    code: `use bytes::Bytes;
use reqsign_core::{Context, HttpSend, Result};

// Implement the Context traits over any transport you own —
// a browser fetch(), a proxy, a test double.
#[derive(Debug)]
struct MyHttpSend;

impl HttpSend for MyHttpSend {
    async fn http_send(
        &self,
        req: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>> {
        todo!("drive the request through your own transport")
    }
}

let ctx = Context::new().with_http_send(MyHttpSend);`,
  },
];

// Verified adoption. Reqsign does not keep a logo wall: entries here require a
// public, auditable dependency. OpenDAL's per-service crates (s3, gcs, azblob,
// cos, tos, ...) sign their storage requests with reqsign.
export const adoption = {
  name: "Apache OpenDAL™",
  href: OPENDAL_URL,
  claim:
    "Every cloud request OpenDAL's storage services sign — S3, GCS, Azure Blob, COS, TOS, and more — goes through Reqsign.",
};
