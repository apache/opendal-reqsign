---
name: reqsign-release
description: Use when asked to prepare, execute, or repair an Apache OpenDAL Reqsign release in the opendal-reqsign repo. Covers DISCUSS/VOTE/RESULT threads, RC tags, source tarballs, GPG signatures, checksum generation, ASF dist SVN updates, GitHub prereleases, final tags, and publish verification.
---

# Reqsign Release

Use this skill only for `apache/opendal-reqsign`. Do not apply it to the main `apache/opendal` release process.

## Core Rules

- Preferred flow:
  1. `DISCUSS`
  2. signed RC tag `vX.Y.Z-rc.N`
  3. GitHub prerelease for the RC tag
  4. source release candidate in `dist/dev`
  5. `VOTE` for at least 72 hours
  6. `[RESULT][VOTE]`
  7. signed final tag `vX.Y.Z`
  8. verify `cargo publish --workspace`
  9. move source release from `dist/dev` to `dist/release`

- Final tags match `vX.Y.Z` and trigger `.github/workflows/release.yml`, which runs `cargo publish --workspace`.
- Never push the final tag before the vote passes.
- RC tags use `vX.Y.Z-rc.N`.
- The source release candidate directory is:

```text
https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/
```

- The source artifacts are:

```text
apache-opendal-reqsign-X.Y.Z-src.tar.gz
apache-opendal-reqsign-X.Y.Z-src.tar.gz.asc
apache-opendal-reqsign-X.Y.Z-src.tar.gz.sha512
```

- `KEYS` must already contain the signing key used for the `.asc` file.
- Use `gh api graphql` for Discussions. Do not use web search for repo discussions.

## Preflight

Run before cutting an RC:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --no-fail-fast
cargo publish --workspace --dry-run
```

Optional but recommended:

```bash
cargo check --workspace --target wasm32-unknown-unknown
```

## RC Workflow

### 1. Cut and push the RC tag

```bash
git tag -s vX.Y.Z-rc.N -m 'Release Apache OpenDAL Reqsign vX.Y.Z-rc.N'
git push origin vX.Y.Z-rc.N
```

### 2. Create a GitHub prerelease

```bash
gh release create vX.Y.Z-rc.N \
  --prerelease \
  --title vX.Y.Z-rc.N \
  --notes 'Release candidate for Apache OpenDAL Reqsign X.Y.Z'
```

### 3. Build the source release candidate

```bash
mkdir -p dist

git archive \
  --format=tar.gz \
  --prefix=apache-opendal-reqsign-X.Y.Z/ \
  -o dist/apache-opendal-reqsign-X.Y.Z-src.tar.gz \
  vX.Y.Z-rc.N

gpg --armor \
  --output dist/apache-opendal-reqsign-X.Y.Z-src.tar.gz.asc \
  --detach-sign dist/apache-opendal-reqsign-X.Y.Z-src.tar.gz

(cd dist && shasum -a 512 apache-opendal-reqsign-X.Y.Z-src.tar.gz \
  > apache-opendal-reqsign-X.Y.Z-src.tar.gz.sha512)
```

Important:

- Generate `.sha512` from inside `dist`.
- The checksum file must contain a relative filename, not an absolute path.

### 4. Upload to ASF dist/dev

Check out the SVN working copy, copy the three files into `reqsign-X.Y.Z/`, and commit.

Historical practice in this repo reuses the same `reqsign-X.Y.Z/` directory across rounds. If reusing the directory for a new round, remove the old candidate files first.

Verify after upload:

```bash
svn ls https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/
```

And verify checksum from a clean temp directory:

```bash
tmp=$(mktemp -d)
cd "$tmp"
curl -fsSLO https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/apache-opendal-reqsign-X.Y.Z-src.tar.gz
curl -fsSLO https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/apache-opendal-reqsign-X.Y.Z-src.tar.gz.sha512
shasum -a 512 -c apache-opendal-reqsign-X.Y.Z-src.tar.gz.sha512
```

## Discussion Templates

### DISCUSS

Title:

```text
[DISCUSS] Release Apache OpenDAL Reqsign X.Y.Z
```

Body:

```text
Hello, Apache OpenDAL Community,

This is a call for a discussion to release Apache OpenDAL Reqsign version X.Y.Z.

The change lists about this release:

https://github.com/apache/opendal-reqsign/compare/vPREV...main

Please leave your comments here about this release plan. We will start the release process after the discussion.

Thanks

Xuanwo
```

### VOTE

Title:

```text
[VOTE] Release Apache OpenDAL Reqsign vX.Y.Z - Vote Round N
```

Body:

```text
Hello, Apache OpenDAL Community,

This is a call for a vote to release Apache OpenDAL Reqsign version vX.Y.Z.

The tag to be voted on is vX.Y.Z-rc.N.

The release candidate:

https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/

Keys to verify the release candidate:

https://downloads.apache.org/opendal/KEYS

Git tag for the release:

https://github.com/apache/opendal-reqsign/releases/tag/vX.Y.Z-rc.N

Please download, verify, and test.

The VOTE will be open for at least 72 hours and until the necessary number of votes is reached.

- [ ] +1 approve
- [ ] +0 no opinion
- [ ] -1 disapprove with the reason

Checklist for reference:

- [ ] Download links are valid.
- [ ] Checksums and signatures.
- [ ] LICENSE/NOTICE files exist
- [ ] No unexpected binary files
- [ ] All source files have ASF headers
- [ ] Can compile from source

Thanks,
Xuanwo
```

### RESULT

Title:

```text
[RESULT][VOTE] Release Apache OpenDAL Reqsign vX.Y.Z - Vote Round N
```

Body:

```text
Hello, Apache OpenDAL Community,

The vote to release Apache OpenDAL Reqsign vX.Y.Z has passed.

The vote PASSED with 3 +1 binding votes, no +0 or -1 votes:

Binding votes:

- @name1
- @name2
- @name3

Vote thread: https://github.com/apache/opendal-reqsign/discussions/NUMBER

Thanks

Xuanwo
```

## Round 2 and Repairs

- If the tarball, signature, tag, or any release content changes after voting starts, prefer a new RC tag and a new vote round.
- If only the `.sha512` sidecar file is malformed and the user explicitly wants an in-place fix, update only that checksum file in `dist/dev`, verify `shasum -c`, and comment in the VOTE thread that the tarball and signature are unchanged.
- In-place checksum repair is weaker than issuing `rc.N+1`. Call out that tradeoff explicitly.

## Final Release

After the vote passes:

```bash
git tag -s vX.Y.Z -m 'Release Apache OpenDAL Reqsign vX.Y.Z'
git push origin vX.Y.Z
```

Then verify the GitHub workflow publishes the entire workspace to crates.io.

Move the source release out of `dist/dev`:

```bash
svn mv \
  https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z \
  https://dist.apache.org/repos/dist/release/opendal/reqsign-X.Y.Z \
  -m 'Release Apache OpenDAL Reqsign X.Y.Z'
```

## Repo-Specific Facts

- This repo uses GitHub Discussions for `DISCUSS`, `VOTE`, and `RESULT`.
- Use the `General` discussion category for release threads unless the repo conventions change.
- Historical `reqsign` source candidates live under `dist/dev/opendal/reqsign-X.Y.Z/`, not `reqsign-X.Y.Z-rc.N/`.
- Historical practice reused the same `reqsign-X.Y.Z/` SVN directory across vote rounds. If doing that, clear old files before uploading the new candidate.
- The release workflow in this repo publishes the whole workspace, not only the `reqsign` facade crate.
- A real failure seen in this repo was generating `.sha512` with an absolute path from `/tmp/...`; always generate the checksum file from inside the output directory so `shasum -c` works elsewhere.
