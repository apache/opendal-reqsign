# CLAUDE.md

## Project Overview

Apache OpenDAL reqsign — a Rust library for signing HTTP API requests across
cloud providers (AWS, Azure, Google, Aliyun, Huawei, Tencent, Oracle,
Volcengine).

## Architecture

The codebase is a Cargo workspace with three layers:

- **`core`** (`reqsign-core`): traits (`ProvideCredential`, `SignRequest`,
  `SigningCredential`) and the runtime-agnostic `Context` / `Signer` types.
- **`context/*`**: pluggable runtime adapters (`file-read-tokio`,
  `http-send-reqwest`, `command-execute-tokio`).
- **`services/*`**: per-cloud signing implementations, each its own crate.
- **`reqsign`**: facade crate re-exporting everything behind feature flags;
  provides `default_context()` and per-service `default_signer()`.

### Key Design Decisions

- **No default implementations in `Context`**: `Context::new()` wires up
  no-op stubs. Users (or `default_context()`) must explicitly plug in
  `FileRead`, `HttpSend`, `Env`, `CommandExecute`.
- **`MaybeSend` futures**: core traits use `MaybeSend` instead of `async_trait`
  so that the crate compiles for `wasm32-unknown-unknown`.
- **Dyn-trait pairs**: every async trait `Foo` has a `FooDyn` counterpart and a
  blanket `impl FooDyn for T: Foo`, enabling `Arc<dyn FooDyn>` inside `Signer`.

## API Design References

When working on an API area with an explicit design document, follow that
document as the source of truth instead of inferring policy from the current
implementation.

### Default Credential Provider

All future refactors and API reviews around `DefaultCredentialProvider` must
follow the authoritative design in
[docs/default-credential-provider-api.md](docs/default-credential-provider-api.md).

Treat any future API change that reintroduces the following as a design
regression unless explicitly approved: `configure_*`, `disable_*(bool)`,
fallback-based re-enabling of removed slots during `build()`.

## Build & Test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --no-fail-fast            # unit tests
cargo test --doc --all-features --workspace  # doc tests
```

### Integration Tests

Integration tests live per-service under `services/<name>/tests/` and are gated
by `REQSIGN_<SERVICE>_TEST*` env vars. Secrets are loaded via 1Password Connect
in CI. Some providers (IMDS, ECS, SSO, Process, Cognito) use Python mock
servers checked into `services/aws-v4/tests/mocks/`.

## WASM Compatibility

`reqsign-core` and a subset of services (`aws`, `azure`, `aliyun`, `tencent`)
must compile for `wasm32-unknown-unknown`. Google is excluded because
`jsonwebtoken` does not support WASM. CI verifies this.

## Versioning

- Service crates and core share a lockstep major version (`3.0.0`).
- `reqsign-http-send-reqwest` has its own major (`4.0.0`).
- The facade `reqsign` crate follows an independent scheme (`0.20.0`).
- Release is triggered by pushing a `v*.*.*` tag; `cargo publish --workspace`
  publishes everything.

## License

Apache-2.0 (ASF). All source files must carry the Apache header, enforced by
hawkeye via `licenserc.toml`.
