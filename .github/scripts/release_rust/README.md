# Rust release helpers

These scripts define and publish the crates.io package set for Apache OpenDAL
reqsign.

## Publish plan

`plan.py` reads `cargo metadata --no-deps`, selects workspace packages that can
publish to crates.io, and orders them by non-dev local dependencies.

```bash
python3 .github/scripts/release_rust/plan.py
```

The release workflow first runs the complete workspace dry run:

```bash
cargo publish --workspace --dry-run
```

It then runs `publish.py`. The publisher uploads one package at a time, requests
and revokes a fresh GitHub OIDC-derived crates.io token for every attempt,
retries crates.io rate limits, and treats an already-published matching
name/version as a completed step. Individual uploads use `--no-verify` because
the workflow has already verified the complete package set from the same
commit.

Live publishing requires the `release` GitHub environment and a job with
`id-token: write`. It never reads a long-lived crates.io token.

## Bootstrap crate names

Trusted Publishing cannot create the first version of a crate.
`bootstrap.py` reserves new names and audits the complete publish plan:

- `discover` reports missing names and existing `0.0.0` placeholders without
  credentials.
- `apply` authenticates every existing crate before any write, publishes a
  dependency-free `0.0.0` namespace reservation for each missing name,
  configures the exact `apache/opendal-reqsign`, `release.yml`, `release`
  Trusted Publisher, enables `trustpub_only`, and performs a final authenticated
  audit.
- `verify` checks public crate metadata and `trustpub_only`. It cannot verify
  ownership or the exact Trusted Publisher because those APIs require
  authentication.

The protected `rust-bootstrap` workflow always runs the authenticated audit,
including when discovery finds no missing names. It never changes an
established crate. Existing crates must be migrated independently before the
workflow can succeed.

Version `0.0.0` is an irreversible namespace reservation. It is not an ASF
software release and contains no implementation.

## Tests

```bash
python3 -m unittest discover \
  -s .github/scripts/release_rust \
  -p "test_*.py"
```
