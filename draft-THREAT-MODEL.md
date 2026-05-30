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

# Apache OpenDAL `reqsign` Security Threat Model — Delta (draft)

## §1 Header

- **Project:** `apache/opendal-reqsign`
- **Crates:** `reqsign` (facade) plus `reqsign-core`, `reqsign-aliyun-oss`,
  `reqsign-aws-v4`, `reqsign-azure-storage`, `reqsign-google`,
  `reqsign-huaweicloud-obs`, `reqsign-oracle`, `reqsign-tencent-cos`,
  `reqsign-volcengine-tos`, `reqsign-command-execute-tokio`,
  `reqsign-file-read-tokio`, `reqsign-http-send-reqwest`.
- **Commit:** HEAD of `main` at draft time (2026-05-30).
- **Status:** Draft delta — awaiting maintainer review.
- **Baseline:** This is a delta document. The canonical OpenDAL threat
  model lives at `apache/opendal:draft-THREAT-MODEL.md` and is inherited
  as the baseline; §1, §2, §4, §7, §10, §12, §13 of the umbrella model
  apply here unchanged unless explicitly overridden in this document.
- **Provenance legend:** *(documented)* / *(maintainer)* / *(inferred)*
  per the umbrella model. Every *(inferred)* tag has a matching §14
  question.
- **Draft confidence (delta only):** 8 documented / 0 maintainer / 9 inferred.

**About this satellite.** `reqsign` is the request-signing engine OpenDAL's
HTTP-based object-store backends rely on (S3 SigV4, Azure Storage
shared-key, GCS, Aliyun OSS, Huawei OBS, Tencent COS, Oracle Cloud, Volcengine
TOS). The OpenDAL `Operator` builds a `Builder`, the `Builder` configures a
`reqsign::Signer`, and per-request signing is delegated to this crate. The
crate is a workspace of pluggable pieces — a `reqsign-core` with the traits
(`ProvideCredential`, `SignRequest`, `SigningCredential`, `Context`), three
`context/*` runtime adapters (Tokio file read, reqwest HTTP send, Tokio
command execute), and one `services/*` crate per cloud. *(documented —
`AGENTS.md`)*

The satellite is also depended on by callers outside OpenDAL (it is
published on crates.io as `reqsign`); the threat model must therefore
hold both when embedded inside OpenDAL *and* when used standalone.

---

## §1a What changes from the main OpenDAL model

The umbrella model treats reqsign as an out-of-scope dependency and
delegates "signer freshness" to it (umbrella §5, "signer freshness is
delegated to `reqsign` (out-of-pilot satellite repo `opendal-reqsign`)").
This delta picks up that delegation.

### Trust-boundary additions

The umbrella model defines four boundaries (umbrella §4):
the `Operator` public API, per-`Operator` credential isolation, layer
composition isolation, debug/log redaction of credentials. For
`reqsign`, two additional boundaries apply *internally*:

- **B5 — `SignRequest` correctness boundary.** *(inferred — Q14.R1)*
  Every per-service `RequestSigner` (e.g. `reqsign_aws_v4::RequestSigner`)
  must produce a signature that the corresponding cloud accepts *and*
  must not produce a signature whose computation leaks information about
  the secret key. Canonicalization bugs that cause the SDK to compute a
  signature over a string the operator did not actually sign are the
  canonical reqsign-specific failure mode — they are in-model.
- **B6 — Credential-provider boundary.** *(inferred — Q14.R1)* Each
  `ProvideCredential` impl loads credentials from a specific source
  (env vars, IMDS, ECS credential helper, SSO, AWS Process credentials,
  Cognito, GCE metadata, Azure CLI, …). The boundary is between the
  external source and the in-process `Credential` struct: a provider
  that silently falls back to a different source than the caller
  selected is in-model.

### Properties inherited from the umbrella model

- Credential redaction in `Debug` output (umbrella §8.1) is inherited:
  reqsign's `Credential` `Debug` impls use `reqsign_core::utils::Redact`
  to redact `access_key_id`, `secret_access_key`, `session_token` and
  similar fields. *(documented — `services/aws-v4/src/credential.rs`,
  similar pattern in other services.)*
- Per-`Operator` credential isolation (umbrella §8.2) is enforced at
  the OpenDAL layer; reqsign contributes by storing its credential
  cache inside the `Signer` struct (`Arc<Mutex<Option<K>>>`) rather
  than in any process-global. *(documented — `core/src/signer.rs`.)*
- Memory safety of the safe-Rust core (umbrella §8.4) is inherited.
  The reqsign workspace contains no `unsafe` block in the core or any
  bundled service. *(inferred — Q14.R6)*

### Properties that DO NOT carry over

- The umbrella's §8.3 "path normalization" property is not relevant —
  reqsign does not touch OpenDAL paths.
- The umbrella's §8.7 `skip_signature` property is *upstream* of
  reqsign: when an OpenDAL service sets `skip_signature = true`, it
  bypasses reqsign entirely. So reqsign cannot violate §8.7 by
  construction.

### Properties that DO carry over but with a new failure mode

- The umbrella's §9.3 "no constant-time comparison" applies, but in
  reqsign it has a sharper edge: `hmac_sha256` / `hex_hmac_sha256`
  (`reqsign_core::hash`) are used to compute the signature itself; if a
  *consumer* of reqsign (not reqsign itself) decides to MAC-compare a
  reqsign-produced signature byte-by-byte against another value with
  `==`, the timing leak is at the consumer's layer. reqsign itself
  does not compare credentials. *(inferred — Q14.R5)*

---

## §11a Known non-findings (recurring false positives)

The following are the recurring reqsign-specific noise patterns the
maintainers (and the umbrella triage queue) expect to see and should
be closed without further analysis unless they include evidence that
something in this section is *itself* wrong.

- **"AWS SigV4 canonicalization differs from <reference impl> on
  edge-case inputs."** Disposition: needs a *concrete* canonical
  request / string-to-sign pair where reqsign's output disagrees with
  AWS's, not a "I looked at `canonical_request_string` and it looks
  off". A bare "this might fail on header X" without a failing test
  case is `KNOWN-NON-FINDING`. The signer is exercised against the
  official SDK in CI (`services/aws-v4/tests/`). *(documented —
  README "Test again official SDK and services".)*
- **"`hex_hmac_sha256` does not use a constant-time comparison."** It
  is not a comparison function. It produces a hex-encoded HMAC for use
  as a signature. `BY-DESIGN: property-disclaimed` per umbrella §9.3
  / §11a (false-friend property: an HMAC function is not a comparison
  function). *(inferred — Q14.R5)*
- **"`Credential::Debug` could be exploited to leak the secret."** The
  `Debug` impl uses `Redact` and does not surface raw secret fields.
  A finding that asserts `{:?}` on a `Credential` *prints* the secret
  is straightforwardly wrong; ship the actual output if claiming
  otherwise. *(documented — `Redact` usage in
  `services/aws-v4/src/credential.rs`.)*
- **"The default credential provider chain reads `AWS_ACCESS_KEY_ID`
  from the environment."** That is the documented behavior of
  `DefaultCredentialProvider`. The disable knob is to *not* construct
  a `DefaultCredentialProvider` — pass a `StaticCredentialProvider` or
  a custom impl instead. `OUT-OF-MODEL: trusted-input` per umbrella
  §6 (the choice of credential provider is operator config).
  *(documented — README "Option 1: Use Default Signer".)*
- **"`reqsign-http-send-reqwest` trusts the TLS configuration of
  `reqwest`."** Yes — see umbrella §3 and §9.7. The transport
  posture is the embedding application's. `OUT-OF-MODEL:
  adversary-not-in-scope`.
- **"Signing a request to a custom endpoint will ship credentials to
  the custom endpoint."** Yes — see umbrella §9.7. The endpoint is
  operator-supplied config. `BY-DESIGN: property-disclaimed`.
- **"The session-token field in `Credential` is `Option<String>` —
  this is suspicious."** It is `Option` because most SigV4 deployments
  do not use STS session tokens (long-lived IAM users do not have one);
  `Option::None` is the normal state. `KNOWN-NON-FINDING`.
- **"A test credential provider stub returns a fixed secret."** Test
  fixtures live under `services/*/tests/mocks/` and `tests/`. They
  are not part of the production trust posture. `OUT-OF-MODEL:
  unsupported-component`.
- **"`reqsign-command-execute-tokio` shells out — that is a code
  smell."** That adapter exists specifically so that AWS Process
  credentials, Azure CLI credentials, and similar provider modes that
  *require* invoking a host binary can plug into `Context`. The
  command and its arguments are operator-supplied config (in the
  `ProvideCredential` impl, not in attacker-controllable data); the
  adapter is `OUT-OF-MODEL: trusted-input` against bare "shells out"
  claims. *(documented — `context/command-execute-tokio/`.)*
- **"`reqsign-core` exposes `Mutex<Option<K>>` for the credential
  cache."** `Signer::sign` takes the lock only to load-or-replace
  the cached credential; the lock is not held across the actual
  signing computation. Lock contention is not a security finding by
  itself. `KNOWN-NON-FINDING`. *(documented — `core/src/signer.rs`.)*

---

## §14 Open questions for the maintainers (delta only)

Each question states a proposed answer for the maintainer to confirm,
correct, or strike. Answers fold back into §1a and §11a and promote
the corresponding *(inferred)* tags.

**Q14.R1** (§1a B5/B6) — Proposed: the in-model failure surface for
reqsign is (a) signature-canonicalization correctness — producing a
signature the cloud accepts but that does not cover what the operator
intended to sign — and (b) credential-provider source confusion — a
provider silently loading credentials from a source the caller did
not select. Anything else (TLS, transport, endpoint choice, bucket
policy) is out of model per the umbrella. Confirm.

**Q14.R2** (§11a) — Proposed: bare "canonicalization looks wrong"
findings without a failing test case against the official SDK are
`KNOWN-NON-FINDING`. A finding becomes `VALID` only when accompanied
by a canonical-request / string-to-sign pair that disagrees with the
reference. Confirm — and is the right reference the AWS SDK's
`aws-sigv4` crate, the Azure SDK's signer, the gcloud auth flow, etc.,
or do you have a smaller in-tree golden corpus?

**Q14.R3** (§1a B6) — Proposed: the in-tree `DefaultCredentialProvider`
chain order is part of the documented contract (per
`docs/default-credential-provider-api.md`, referenced from AGENTS.md).
A reorder that *changes* which source wins for a given environment is
a breaking change requiring a major bump, not a security bug. Confirm.

**Q14.R4** (§1a) — Proposed: the `MaybeSend` future / dyn-trait pair
pattern (AGENTS.md "Key Design Decisions") is a compilation-target
concern only; it does not introduce a new trust boundary. Confirm.

**Q14.R5** (§1a, §11a) — Proposed: reqsign does not provide any
constant-time-compare API and is not used internally to compare
secrets. Consumers that take a reqsign-produced signature and
compare it against an attacker-supplied value with `==` introduce
their own timing leak. Confirm — and is there a documented
recommendation for that consumer-side comparison (e.g. "use
`subtle::ConstantTimeEq`")?

**Q14.R6** (§1a) — Proposed: the reqsign workspace contains no
`unsafe` blocks; safe-Rust memory safety is inherited per the
umbrella §8.4. Confirm — is that an invariant you intend to keep
(no `unsafe` ever), or could a future performance optimisation
introduce some?

**Q14.R7** (§1a) — The `core/src/jwt.rs` and `core/src/hash.rs`
modules contain crypto primitives (RSA / HMAC-SHA256 / SHA256 /
SHA1 via `rsa`, `hmac`, `sha2`, `sha1` crates). Proposed: these
are vetted-upstream crates used at default configurations; the
security envelope of those crates is inherited. A finding against
the *use* (e.g. "uses SHA1 in the Aliyun signer") is `VALID` only
if the cloud the signer targets has deprecated that algorithm —
SHA1-in-Aliyun-v1 is the cloud's protocol, not reqsign's choice.
Confirm.

**Q14.R8** (§14 meta) — Proposed: this delta document lives at
`docs/threat-model.md` in `apache/opendal-reqsign`, with a one-line
pointer from `README.md` and `AGENTS.md`. Confirm — or do you
prefer it as a section of `AGENTS.md` since AGENTS.md is already
the canonical contract document for the workspace?
