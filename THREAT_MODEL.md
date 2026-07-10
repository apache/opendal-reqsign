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

# Apache OpenDAL Reqsign Threat Model

## 1. Status

This document defines the security boundary for Apache OpenDAL Reqsign. The
documentation is for maintainers, security reporters, downstream users, Apache
OpenDAL integrators, direct `reqsign` users, and automated security scanners
that need to decide whether a report describes a Reqsign vulnerability or a
responsibility of the embedding application, a cloud provider, or a deployment.

The canonical disclosure process is documented in [SECURITY.md](./SECURITY.md).
Reports that may affect reqsign security should be sent privately to
`private@opendal.apache.org` before public disclosure. If you are unsure where
to send the report, use `security@apache.org`.

## 2. Purpose

Reqsign is an in-process Rust library for signing HTTP API requests. Reqsign
provides runtime-agnostic core traits, pluggable context adapters,
credential-provider chains, and service-specific signing implementations for
cloud providers.

Reqsign is not an identity provider, authorization service, key-management
system, TLS stack, network sandbox, process sandbox, or multi-tenant broker.
Reqsign does not decide whether a caller is allowed to access a resource but
signs the HTTP request that a trusted caller gives it, using credentials that
the trusted caller configured or allowed reqsign to discover.

The purpose of this document is to help maintainers triage security reports by
answering four questions:

1. What is Reqsign's security boundary?
2. What security properties does Reqsign provide?
3. What security responsibilities belong to OpenDAL, other embedding
   applications, configured credential sources, or cloud providers?
4. Which disposition should be used for a report: Reqsign vulnerability,
   hardening request, user misuse, or out-of-scope deployment issue?

The most important premises are:

> Reqsign trusts its caller to construct the request, choose the endpoint,
> choose service and region values, and configure credential-provider sources.

> Reqsign must still preserve its own library boundary: sign according to the
> selected service contract, isolate cached credentials, avoid credential leaks,
> respect explicit provider-chain configuration, and handle inputs without
> memory-safety violations.

OpenDAL is Reqsign's primary integration and can use Reqsign to sign requests
for custom keys and cloud-provider authentication. Other applications can also
embed Reqsign directly. In every embedding, the host application remains
responsible for its own user authentication, authorization, request construction,
endpoint selection, and user-facing API behavior. OpenDAL-specific storage
semantics, operator authorization, path policy, and backend trust decisions are
covered by OpenDAL's own security model. Reqsign is responsible for the
request-signing and credential-loading behavior described here.

## 3. System Model

A Reqsign deployment has these participants.

| Participant | Boundary summary |
| --- | --- |
| Host application | Trusted caller outside Reqsign's security boundary. |
| Reqsign | In-process signing library and the subject of this model. |
| Credential source | External source selected by the caller or documented Reqsign behavior. |
| Cloud provider or API service | External verifier and authorizer. |
| End user of the host application | Outside Reqsign's direct model. |
| Network attacker | Outside by default, except for Reqsign-owned leaks or transport weakening. |

### 3.1 Participant Details

- Host application: creates HTTP requests, configures Reqsign, selects service
  and region values, chooses credential sources, and decides which end-user
  input may reach Reqsign. Apache OpenDAL is the primary known host application,
  but the same boundary applies to other applications that embed Reqsign.
- Reqsign: signs HTTP requests and loads or receives signing credentials through
  its public APIs. This system model treats Reqsign as one library boundary.
- Credential sources: include configured local files, process environment,
  external commands, metadata endpoints, OAuth/token endpoints, and custom
  caller-provided credential sources.
- Cloud provider or API service: verifies the signed request and authorizes the
  resulting operation. Reqsign trusts provider-side authentication,
  authorization, token issuance, and response semantics.
- End user of the host application: must be authenticated, authorized, and
  sanitized by the host application before input is passed to Reqsign.
- Network attacker: is out of scope unless the report shows Reqsign weakens the
  configured transport or leaks secrets through Reqsign-owned behavior. TLS
  certificate validation, CA bundles, proxy policy, and socket behavior are
  delegated to the configured HTTP client and host environment.

### 3.2 Authority Model

Reqsign does not define a principal model. A configured Reqsign signing setup
signs with the authority of its configured credentials. Every request signed by
that setup uses the same Reqsign-level authority until the caller changes the
credential or signing configuration.

### 3.3 Interaction

A typical interaction looks like this:

```text
Credential source <----> Reqsign <----> Host application <----> End user
                            |
                            v
                    Signed HTTP request
                            |
                            v
                  Cloud provider or API service
```

### 3.4 External Boundaries

Host application policy, including OpenDAL storage semantics when Reqsign is
used through OpenDAL, cloud provider enforcement, and deployment controls are
separate boundaries.

### 3.5 Protected Assets And Properties

Reqsign protects:

- signing credentials, temporary tokens, private keys, shared keys, bearer
  tokens, and reusable derived signing material;
- the request fields that the selected signing contract is expected to cover,
  including method, scheme, authority, path, query, signed headers, payload hash,
  expiry, service, region, and account values;
- explicit caller configuration for credential sources, signing method, service,
  region, expiry, and context capabilities;
- credential isolation between independent signing setups, unless the caller
  explicitly shares a signer, provider, or context;
- redaction of secret values in Reqsign-owned errors, debug output, logs, test
  helpers, and examples.

## 4. Security Boundary

Reqsign's security boundary is the public library boundary plus the internal
state that Reqsign owns behind that boundary.

The following properties are in scope for Reqsign security.

### 4.1 Public API contract and memory safety

Reqsign must handle inputs accepted by public APIs without memory-safety
violations, data races, panics across FFI-like boundaries, or inconsistent
internal state.

Examples:

- `Signer::sign` must not use a poisoned, stale, or unrelated credential in a
  way that violates its documented cache behavior.
- `SigningRequest::build` and `SigningRequest::apply` must preserve request
  method, scheme, authority, path, query, and headers according to their API
  contract.
- Request parsing, canonicalization, percent decoding, header normalization,
  JSON parsing, XML parsing, JWT construction, and credential-file parsing must
  not create memory unsafety or uncontrolled panics reachable through public
  APIs.
- `MaybeSend` support must not introduce unsoundness in supported non-WASM and
  `wasm32-unknown-unknown` builds.

Reqsign does not decide whether the host application's end user is allowed to
sign a request. That policy belongs to the host application. Once the trusted
caller passes a request into Reqsign, Reqsign must not sign a different request
than the request implied by the selected signing implementation.

### 4.2 Credential isolation

Reqsign must not leak credentials between independent signers, credential
providers, services, or contexts inside the same process.

Expected behavior:

- A request signed through `Signer` B must not use credentials loaded by
  independent `Signer` A unless the caller explicitly shares a provider,
  context, or signer.
- Replacing a credential provider with `with_credential_provider` must clear the
  cached credential for that signer.
- A provider chain must not fall back to disabled or removed provider slots
  during `build()`.
- Default credential-provider builders must follow
  [docs/default-credential-provider-api.md](docs/default-credential-provider-api.md):
  explicit slot participation, positive `slot(provider)` methods, removal
  `no_slot()` methods, and no fallback-based re-enabling of removed slots.
- Temporary credentials must not be considered valid for signing or presigning
  past the validity checks implemented by their `SigningCredential`.

Sharing a `Signer`, provider, or `Context` across tenants, threads, async tasks,
or processes is a caller decision. It is in scope only if Reqsign violates its
own documented isolation or cache behavior.

### 4.3 Credential redaction and observability

Reqsign must avoid exposing credentials through `Debug` output, error chains,
log lines, tracing spans, metrics labels, panic messages, and test helpers that
are part of shipped library behavior.

Secrets include, at minimum:

- access keys, secret keys, shared keys, private keys, signing keys, bearer
  tokens, session tokens, OAuth refresh tokens, OIDC tokens, metadata-service
  authorization tokens, account keys, tenant secrets, and serialized service
  account JSON;
- derived signing material that can be reused to authenticate requests;
- presigned URLs or query strings when the signature grants meaningful access.

Expected behavior:

- Credential `Debug` implementations redact secret fields.
- Errors may identify the provider, slot, file path, status code, or credential
  type, but must not include secret values.
- Failed parsing of credential files, command output, token responses, or
  metadata responses must not include full secret-bearing payloads.
- Tests and examples should not encourage printing live credentials or
  presigned URLs in normal logs.

Request paths, endpoint hostnames, regions, account names, and provider names
can be sensitive in some deployments. Reqsign does not treat them as
credentials by default; callers that need stronger privacy must choose their
logging and tracing sinks accordingly.

### 4.4 Credential-provider source control

Reqsign's credential providers must use only the credential sources documented
or explicitly configured for that provider chain.

Examples:

- A `Context::new()` has no-op file, HTTP, environment, and command adapters.
  It must not silently read the process environment, local files, metadata
  endpoints, or external commands.
- The facade crate's `default_context()` may use OS environment variables, file
  reads, HTTP requests, and command execution through its default adapters.
  Those accesses must match the documented default providers for the selected
  service.
- `no_env()`, `no_profile()`, `no_imds()`, `no_process()`, `no_web_identity()`,
  `no_oidc()`, `no_vm_metadata()`, and similar removal methods must prevent the
  corresponding ambient source from participating.
- A profile, config, or token-file provider must not read a path other than the
  configured path or the documented default path.
- A process provider must execute only the configured command and arguments. It
  must not invoke a shell implicitly unless that is explicitly part of the
  documented API.
- A metadata or token provider must send requests only to the endpoint implied
  by the provider contract or explicit caller configuration.

If a trusted caller configures a malicious file path, command, environment
implementation, metadata endpoint, HTTP client, or custom provider, using that
source is caller responsibility. If Reqsign ignores explicit source removal,
mixes sources from another signer, or silently adds a credential source, that is
in scope.

### 4.5 Request canonicalization and signing correctness

Reqsign must construct and apply signatures according to the selected service's
signing contract.

Examples:

- AWS SigV4, Azure Storage shared-key signing, Google service-account or token
  flows, Aliyun OSS, Huawei Cloud OBS, Oracle Cloud, Tencent COS, and
  Volcengine TOS signers must canonicalize method, path, query parameters,
  headers, payload hash rules, expiry, date, service, region, account, and
  provider-specific fields as required by their implemented contract.
- Header-based signing must apply authorization data to headers without
  unintentionally moving authority to query parameters.
- Query-based signing and presigning must apply expiry and signed query
  parameters according to the provider's rules and must not leave stale
  signature material from a previous signing pass.
- Signing must use the request endpoint, authority, scheme, path, query, and
  headers selected by the trusted caller and signer implementation.
- A service-specific signer must not send credentials to an unrelated endpoint
  during signing-time credential refresh or token exchange.

Provider-side acceptance or rejection is not by itself the security boundary.
A compatibility bug that causes a legitimate request to fail may be a normal
bug. It becomes security-relevant when it grants unintended authority, signs a
meaningfully different request, exposes secret material, bypasses explicit
caller configuration, or violates an in-scope provider contract.

### 4.6 Custom key signing

Reqsign is designed to support custom request-signing implementations. OpenDAL
is a primary consumer of this capability for custom key signing, and other host
applications may provide their own custom signers too. Custom signers and
credential providers are trusted code from Reqsign's perspective, but Reqsign's
core abstractions must not make custom key signing unsound.

In scope:

- core trait objects must preserve the relationship between a credential type
  and its matching signer;
- `Signer` must pass the credential selected by its provider to the configured
  request signer without cross-service or cross-signer substitution;
- core request manipulation must not corrupt the request being signed;
- default helpers must not downgrade a custom caller's explicit `Context`,
  credential provider, or request signer.

Out of scope by default:

- a caller-provided `ProvideCredential`, `SignRequest`, `FileRead`, `HttpSend`,
  `Env`, or `CommandExecute` implementation intentionally leaks or misuses
  secrets;
- a custom signing algorithm chosen by the caller is cryptographically weak;
- a host application, including OpenDAL, authorizes the wrong end user to invoke
  a custom signer.

### 4.7 Local resource access

Reqsign can read local credential files and execute local credential-helper
commands when the caller configures adapters and providers that require those
features.

In scope:

- Reqsign-owned default path expansion and provider path selection must match
  documented provider behavior.
- Errors and debug output from local resource access must not leak secret file
  contents or command output containing credentials.
- Command execution must not add shell interpretation, glob expansion, argument
  injection, or working-directory changes unless documented.

Out of scope by default:

- host filesystem permissions;
- a caller-configured credential file containing attacker-controlled content;
- a caller-configured credential process that is malicious;
- a host application giving untrusted tenants control over credential-file
  paths or credential-process commands.

### 4.8 HTTP, metadata, and token-provider interactions

Reqsign providers may use HTTP to retrieve metadata credentials, exchange
tokens, refresh OAuth credentials, or call service-specific identity endpoints.

In scope:

- provider HTTP requests must include only the headers and body fields required
  by the provider contract;
- metadata-service authorization tokens must not be sent to unrelated hosts;
- token responses must be parsed without leaking full secret-bearing bodies in
  errors;
- explicit provider configuration that disables metadata or token sources must
  be respected.

Out of scope by default:

- TLS policy, CA bundle configuration, proxy behavior, DNS behavior, redirect
  policy, and timeout policy of the configured HTTP client;
- a trusted caller choosing an attacker-controlled endpoint;
- a metadata, OAuth, STS, or token service returning malicious or incorrect
  credentials, unless Reqsign violates parser robustness, credential isolation,
  or redaction while handling that response.

### 4.9 WASM compatibility

`reqsign-core` and the supported subset of services are expected to compile for
`wasm32-unknown-unknown`.

In scope:

- supported WASM builds must not accidentally enable OS environment access,
  local filesystem access, command execution, or network access through no-op
  context components;
- WASM-specific implementations must preserve the same credential isolation and
  redaction properties as native builds.

Out of scope by default:

- browser, worker, or embedding-runtime sandbox policy;
- JavaScript code outside Reqsign that provides custom context adapters;
- web platform credential storage selected by the host application.

## 5. Out Of Scope

The following are not Reqsign vulnerabilities by default.

### 5.1 Host application authentication and authorization

Reqsign does not authenticate end users, authorize operations, or decide whether
end-user input is allowed to become a request URL, header, query parameter,
service name, region, credential-source path, command, or endpoint.

Examples:

- A web service lets tenants submit arbitrary URLs and then signs those URLs
  with the service's cloud credentials.
- A host application, including OpenDAL, maps an untrusted path to the wrong
  object before calling Reqsign.
- A multi-tenant application shares one signer across tenants that should have
  separate credentials.

These may be serious vulnerabilities in the host application, but they are not
Reqsign vulnerabilities unless Reqsign violates one of the boundaries in
section 4.

### 5.2 Caller-selected malicious endpoints and providers

The trusted caller is responsible for choosing endpoints, HTTP clients, context
adapters, credential providers, request signers, service names, regions, and
accounts.

Examples:

- The caller configures an attacker-controlled S3-compatible endpoint and sends
  signed requests to it.
- The caller supplies a custom `HttpSend` implementation that logs request
  bodies and headers.
- The caller supplies a custom `Env` implementation that returns attacker
  credentials.
- The caller supplies a custom `SignRequest` implementation that signs the
  wrong bytes.

### 5.3 Cloud-provider authorization and credential validity

Cloud-provider policy and identity behavior belong to the provider and the
operator of that account.

Examples:

- An IAM policy, bucket policy, role trust policy, OAuth scope, storage account
  policy, or service-account permission grants broader access than intended.
- A provider accepts a signature that should have been rejected.
- A provider returns expired, overprivileged, or incorrect temporary
  credentials.

Reqsign can fail safely when provider responses are malformed, but it does not
prove provider-side authorization correctness.

### 5.4 End-to-end request or response integrity beyond signing

Reqsign signs requests according to provider rules. It does not provide
end-to-end authentication of response bytes, object contents, metadata,
timestamps, ETags, or backend state.

Applications that need end-to-end integrity must add it above Reqsign and above
their storage/API client.

### 5.5 Resource exhaustion by default

Reqsign is not a default DoS shield.

Examples:

- A credential file is very large.
- A token endpoint responds slowly or returns a large body.
- A process credential helper hangs.
- A caller asks Reqsign to sign many requests concurrently.

Resource-exhaustion reports are Reqsign vulnerabilities only when they show
Reqsign violates a documented bound, ignores configured timeout or cancellation
behavior that Reqsign owns, or consumes resources independently of the operation
requested by the trusted caller.

### 5.6 Transport policy selected outside Reqsign

TLS certificate validation, CA bundles, proxies, redirect policy, DNS, socket
options, and network egress controls are properties of the configured HTTP
client and host environment. A report is in scope only if Reqsign silently
weakens transport contrary to its documented meaning or sends Reqsign-owned
secret material to an endpoint outside the provider contract.

### 5.7 Supply chain, release, and project infrastructure

Dependency freshness, GitHub Actions hardening, release signing, branch
protection, and ASF infrastructure policy are important, but they are outside
this library threat boundary unless a separate project policy says otherwise.

## 6. Triage Dispositions

| Disposition | Use when |
| --- | --- |
| `VALID` | The report shows a violation of an in-scope boundary in section 4, reachable through documented Reqsign APIs or shipped Reqsign library behavior. |
| `VALID-HARDENING` | There is no clear security-boundary violation, but Reqsign's API, defaults, logging, or documentation make dangerous misuse common enough that maintainers choose to harden behavior or docs. |
| `OUT-OF-SCOPE: caller-authz` | The report depends on the host application forwarding unauthorized end-user input into Reqsign. |
| `OUT-OF-SCOPE: caller-config` | The report depends on a trusted caller choosing a malicious endpoint, provider, context adapter, credential file, command, HTTP client, service name, region, or custom signer. |
| `OUT-OF-SCOPE: provider-authz` | The report is about cloud-provider policy, role trust, OAuth scope, bucket policy, or provider-side signature verification rather than Reqsign behavior. |
| `OUT-OF-SCOPE: transport` | The report is about TLS, proxy, DNS, redirect, timeout, or socket behavior owned by the configured HTTP client or host environment. |
| `OUT-OF-SCOPE: infrastructure` | The report is about release, CI, dependency, or ASF infrastructure policy rather than the Reqsign library boundary. |
| `BY-DESIGN: property-not-provided` | The report asks Reqsign to provide a property explicitly not provided here, such as host-application authorization, endpoint trust, response integrity, or default DoS protection. |
| `MODEL-GAP` | The report cannot be classified by this document. Treat this as evidence that the model needs revision. |

## 7. Triage Examples

### 7.1 Reqsign vulnerability (`VALID`)

- `Signer` B signs a request with credentials cached by unrelated `Signer` A.
- A credential `Debug` implementation prints a secret access key, account key,
  private key, session token, or OAuth token.
- `no_imds()` is configured, but the built provider still contacts IMDS.
- `Context::new()` reads environment variables, local files, HTTP endpoints, or
  external commands without the caller installing adapters.
- A process credential provider executes through a shell when the API only
  accepts a program and argument vector.
- A token-provider error includes the full JSON response body containing an
  access token.
- Query presigning leaves a stale signature parameter from a previous signing
  pass and grants access to a request different from the current request.
- A signer canonicalizes an attacker-controlled header in a way that signs a
  different authority, path, or query than the caller's request.
- A malformed credential file or token response triggers memory unsafety or an
  uncontrolled panic through a normal public API call.

### 7.2 Out of scope by default

- `OUT-OF-SCOPE: caller-config`: a caller signs an attacker-supplied URL with
  production credentials.
- `OUT-OF-SCOPE: caller-config`: a caller configures an attacker-controlled
  S3-compatible endpoint and that endpoint receives signed requests.
- `OUT-OF-SCOPE: caller-authz`: a host application, including OpenDAL,
  authorizes the wrong tenant before calling Reqsign.
- `OUT-OF-SCOPE: provider-authz`: a bucket policy, IAM role, service account,
  storage account, or OAuth scope is overprivileged.
- `OUT-OF-SCOPE: caller-config`: a caller-provided custom signer intentionally
  logs the canonical request and secret key.
- `OUT-OF-SCOPE: provider-authz`: a cloud provider accepts a bad signature due
  to a provider-side verifier bug.
- `OUT-OF-SCOPE: caller-config`: a credential-helper command configured by the
  caller is malicious.
- `BY-DESIGN: property-not-provided`: a credential file is huge and the caller
  did not provide resource limits.

### 7.3 Hardening or documentation (`VALID-HARDENING`)

- A default provider chain is surprising but still follows documented behavior.
- A common integration misuse, especially in OpenDAL usage, is easy enough that
  many users repeat it.
- A provider error includes non-secret operational context that can be sensitive
  in some deployments.
- A service's signing behavior is correct for one compatible backend but should
  document differences for another compatible backend.

## 8. Maintainer Decisions

The following decisions are part of this model.

| Topic | Decision |
| --- | --- |
| Host application trust | Reqsign treats OpenDAL and other embedding applications as trusted callers that authorize users, choose endpoints, construct requests, and decide which inputs may be signed. |
| Custom key signing | Caller-provided custom signers and providers are trusted code, but Reqsign must preserve type relationships, request integrity, credential isolation, and explicit customization. |
| No-op context default | `Context::new()` and `Context::default()` must remain no-op for file reads, HTTP sends, environment reads, and command execution. Ambient access belongs to explicit adapters such as `default_context()`. |
| Default credential providers | Future API changes around `DefaultCredentialProvider` must follow `docs/default-credential-provider-api.md`; reintroducing `configure_*`, `disable_*(bool)`, or build-time fallback re-enabling of removed slots is a design regression unless explicitly approved. |
| Credential redaction | Credentials and reusable signing material are secrets and must be redacted. Paths, endpoints, regions, account names, and provider names are operational context by default. |
| Presigned URLs | Presigned URLs and signed query strings can grant access and should be treated as secret-bearing material when emitted by Reqsign-owned logs, errors, or debug output. |
| Transport | Reqsign delegates TLS, proxy, DNS, redirect, and socket policy to the configured HTTP client and host environment. |
| OpenDAL integration boundary | OpenDAL-level storage semantics, operator authorization, path policy, and backend trust decisions are covered by OpenDAL's own security model, not this Reqsign model. Other host applications own equivalent application-level policy in their own security models. |
| Version binding | A report should be triaged against the threat model version present in the affected release tag or maintenance branch. |
| Capability drift | When credential loading, request signing, context capabilities, WASM support, or custom signing APIs change, this file should be updated in the same pull request or a linked follow-up. |

## 9. Revision Triggers

We will revisit this threat model when any of the following changes:

- A credential provider starts storing credentials outside process memory.
- A context adapter gains a new filesystem, network, process, or environment
  capability.
- A default credential-provider chain changes order, defaults, or disabling
  semantics.
- A signing implementation changes canonicalization, expiry, payload hash, or
  presigning behavior.
- A new service crate, provider family, or token exchange flow is added.
- A new OpenDAL integration or non-OpenDAL embedding relies on Reqsign for
  custom key signing in a way that changes the trusted-caller boundary.
- WASM support gains a new runtime capability.
- A vulnerability report is classified as `MODEL-GAP`.
- The project decides to treat a previously caller-owned property as a
  Reqsign-provided property.

## 10. Relationship To OpenDAL And Other Hosts

Reqsign is a sub-project related to Apache OpenDAL, and OpenDAL is the primary
integration this model expects maintainers to consider. Reqsign is still a
reusable library: direct `reqsign` users and other embedding applications get
the same Reqsign security properties and retain the same host-application
responsibilities.

Reqsign owns:

- documented credential loading behavior;
- request canonicalization and signing behavior;
- credential caching and isolation;
- redaction of Reqsign-owned credentials and signing material;
- documented behavior of Reqsign-provided runtime capabilities and defaults.

OpenDAL and other host applications own:

- end-user authentication and authorization;
- storage path policy and namespace mapping;
- choice of endpoint, service, region, account, signer, credential provider,
  and context adapter;
- whether signed requests or presigned URLs may be exposed to end users;
- deployment controls such as network egress policy, TLS configuration, process
  sandboxing, and resource limits.

For OpenDAL, this threat model is additive. It does not replace OpenDAL's threat
model or the Apache Software Foundation disclosure process. For other embedding
applications, this model defines only Reqsign's library boundary; the embedding
application must define its own authorization, input-validation, endpoint-trust,
and deployment boundaries.
