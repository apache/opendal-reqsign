# Default Credential Provider API Design

This document defines the repository's authoritative public API design for all
`DefaultCredentialProvider` types.

Implementations that do not match this document should be treated as legacy
debt. New code, reviews, and refactors must follow this document.

## Goals

- Make provider participation explicit.
- Remove boolean toggles from the public API.
- Remove `configure_*` patch-style APIs from the public API.
- Keep the top-level `DefaultCredentialProvider` API uniform across services.
- Keep builder APIs predictable across services while allowing service-specific
  provider slots.

## Product API

Every service-level default provider exposes the same product-level API:

```rust
DefaultCredentialProvider::new()
DefaultCredentialProvider::builder()
DefaultCredentialProvider::with_chain(chain)
DefaultCredentialProvider::push_front(provider)
impl Default for DefaultCredentialProvider
```

### Semantics

- `new()` creates the documented default chain for that service.
- `default()` is identical to `new()`.
- `builder()` returns a builder pre-populated with the documented default slots.
- `with_chain(chain)` bypasses all default-chain assembly logic.
- `push_front(provider)` prepends a high-priority provider in front of the
  documented default chain.

## Builder API

Every `DefaultCredentialProviderBuilder` exposes:

```rust
DefaultCredentialProviderBuilder::new()
DefaultCredentialProviderBuilder::default()
.build()
```

For each supported provider slot, the builder exposes exactly two primary
methods:

```rust
.env(provider)
.no_env()
```

The same pattern applies to all other slots:

```rust
.profile(provider)
.no_profile()

.sso(provider)
.no_sso()

.imds(provider)
.no_imds()
```

### Rules

- Public builder APIs must not expose `configure_*`.
- Public builder APIs must not expose `disable_*(bool)`.
- Each slot is controlled by one positive method and one removal method.
- Slot names must match the actual provider concept, not an overloaded alias.
- Builders expose only the slots that a service actually supports.

## Internal State Model

Each builder slot should be represented as:

```rust
Option<T>
```

with this meaning:

- `Some(T::default())`: slot enabled with the default provider configuration
- `Some(custom)`: slot enabled with a custom provider configuration
- `None`: slot removed from the chain

This implies:

- `DefaultCredentialProviderBuilder::default()` initializes all documented
  default slots to `Some(T::default())`.
- `.no_env()` sets `env` to `None`.
- `.env(provider)` sets `env` to `Some(provider)`.
- `build()` pushes only `Some(...)` slots and skips `None`.

No separate `enabled` flag is needed.

## Slot Naming

Use provider-concept names without the `CredentialProvider` suffix.

Examples:

- `env`
- `profile`
- `sso`
- `process`
- `ecs`
- `imds`
- `web_identity`
- `oidc`
- `config_file`
- `vm_metadata`

Do not collapse distinct concepts under a vague shared name.

Examples:

- Prefer `web_identity(...)` over `assume_role(...)` when the slot is actually
  `AssumeRoleWithWebIdentityCredentialProvider`.
- Prefer `oidc(...)` over `assume_role(...)` when the slot is specifically
  OIDC-based.

## Service Examples

### AWS V4

```rust
let provider = DefaultCredentialProvider::builder()
    .no_env()
    .profile(ProfileCredentialProvider::new().with_profile("prod"))
    .no_imds()
    .build();
```

Expected slots:

- `env`
- `profile`
- `sso`
- `web_identity`
- `process`
- `ecs`
- `imds`

### Aliyun OSS

```rust
let provider = DefaultCredentialProvider::builder()
    .env(EnvCredentialProvider::new())
    .no_oidc()
    .build();
```

Expected slots:

- `env`
- `oidc`

### Tencent COS

```rust
let provider = DefaultCredentialProvider::builder()
    .no_env()
    .web_identity(AssumeRoleWithWebIdentityCredentialProvider::new())
    .build();
```

Expected slots:

- `env`
- `web_identity`

## Migration Rules

When changing an existing service:

1. Remove all public `configure_*` methods.
2. Remove all public `disable_*(bool)` methods.
3. Initialize builder defaults with `Some(T::default())` for documented default
   slots.
4. Add `slot(provider)` and `no_slot()` methods for every supported slot.
5. Update tests to verify that `no_slot()` truly removes the provider from the
   chain.
6. Update examples and docs to use slot/no-slot APIs only.

## Non-Goals

- This document does not require a repository-wide refactor in one patch.
- This document does not require every service to expose the same set of
  provider slots.
- This document does not remove `with_chain` or `push_front`; those remain the
  escape hatch for advanced composition.
