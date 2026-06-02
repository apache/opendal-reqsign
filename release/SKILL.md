---
name: reqsign-release
description: Release Apache OpenDAL reqsign through the Apache RC, vote, dist, tag, crates.io, and announcement flow.
---

# Apache OpenDAL reqsign Release Skill

Use this skill when preparing or executing an Apache OpenDAL reqsign release.

## Hard Rules

- Do not push the formal `vX.Y.Z` tag before the Apache vote passes.
- The voted release candidate tag is `vX.Y.Z-rc.N`; it must be a signed tag.
- The formal `vX.Y.Z` tag must point to the exact same commit as the voted RC tag, even if `main` has advanced after the vote started.
- The repo release workflow is only for formal `vX.Y.Z` tags. It runs `cargo publish --workspace`.
- Source release artifacts live under Apache dist:
  - RC: `https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/`
  - Final: `https://dist.apache.org/repos/dist/release/opendal/reqsign-X.Y.Z/`
- If a wrong formal tag is pushed early, immediately cancel the Release workflow, delete the remote tag, and verify crates.io did not publish anything.

## Release Preparation

1. Sync live state.

   ```bash
   git fetch origin main --tags
   git status --short --branch
   git tag --list 'vX.Y.Z*' --sort=version:refname
   git ls-remote --tags origin 'refs/tags/vX.Y.Z*'
   svn ls https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/ || true
   svn ls https://dist.apache.org/repos/dist/release/opendal/reqsign-X.Y.Z/ || true
   ```

2. Prepare version bump on a PR.

   Typical version policy:

   - `reqsign`: patch bump, for example `0.20.0 -> 0.20.1`.
   - Crate with new public capability: minor bump, for example `reqsign-aliyun-oss 3.0.0 -> 3.1.0`.
   - Other workspace crates published in the same workspace release: patch bump.
   - Keep root `[workspace.dependencies]` version requirements aligned with each crate manifest.

3. Merge the version bump PR into `main`.

   Do not create the RC tag from an unmerged side branch unless the release manager explicitly accepts that the voted commit will not be on `main`.

## Create RC Tag

Create the RC tag from the merged version-bump commit on `main`.

```bash
git fetch origin main --tags
git switch --detach origin/main
git tag -s vX.Y.Z-rc.N -m "vX.Y.Z-rc.N"
git tag -v vX.Y.Z-rc.N
git push origin vX.Y.Z-rc.N
```

The RC tag should not trigger the formal publish workflow.

## Build Source Artifact

Create the Apache source artifact from the RC tag.

```bash
rm -rf /tmp/opendal-reqsign-release-X.Y.Z
mkdir -p /tmp/opendal-reqsign-release-X.Y.Z/dist

git archive \
  --format=tar.gz \
  --prefix=apache-opendal-reqsign-X.Y.Z/ \
  -o /tmp/opendal-reqsign-release-X.Y.Z/dist/apache-opendal-reqsign-X.Y.Z.tar.gz \
  vX.Y.Z-rc.N

cd /tmp/opendal-reqsign-release-X.Y.Z/dist
gpg --armor --detach-sign apache-opendal-reqsign-X.Y.Z.tar.gz
shasum -a 512 apache-opendal-reqsign-X.Y.Z.tar.gz > apache-opendal-reqsign-X.Y.Z.tar.gz.sha512

gpg --verify apache-opendal-reqsign-X.Y.Z.tar.gz.asc apache-opendal-reqsign-X.Y.Z.tar.gz
shasum -a 512 -c apache-opendal-reqsign-X.Y.Z.tar.gz.sha512
tar -tzf apache-opendal-reqsign-X.Y.Z.tar.gz | rg '(^|/)LICENSE$|(^|/)NOTICE$|(^|/)Cargo.toml$'
```

Confirm the signing key is present in Apache OpenDAL KEYS:

```bash
svn cat https://dist.apache.org/repos/dist/release/opendal/KEYS | rg 'xuanwo@apache.org|Xuanwo|KEY_FINGERPRINT'
```

## Upload RC Artifacts

Upload to Apache dev dist.

```bash
rm -rf /tmp/opendal-dist-dev-reqsign-X.Y.Z
svn co --depth=empty https://dist.apache.org/repos/dist/dev/opendal /tmp/opendal-dist-dev-reqsign-X.Y.Z

cd /tmp/opendal-dist-dev-reqsign-X.Y.Z
mkdir reqsign-X.Y.Z
cp /tmp/opendal-reqsign-release-X.Y.Z/dist/* reqsign-X.Y.Z/
svn add reqsign-X.Y.Z
svn status
svn commit --force-interactive -m "Prepare reqsign X.Y.Z release candidate"
```

Verify the remote copy:

```bash
svn ls https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/
rm -rf /tmp/opendal-reqsign-verify-X.Y.Z
svn co https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z /tmp/opendal-reqsign-verify-X.Y.Z
cd /tmp/opendal-reqsign-verify-X.Y.Z
shasum -a 512 -c apache-opendal-reqsign-X.Y.Z.tar.gz.sha512
gpg --verify apache-opendal-reqsign-X.Y.Z.tar.gz.asc apache-opendal-reqsign-X.Y.Z.tar.gz
```

## Start Vote

Create a GitHub Discussion in `apache/opendal-reqsign` General.

Title:

```text
[VOTE] Release Apache OpenDAL reqsign X.Y.Z - Vote Round 1
```

Body:

```text
Hello, Apache OpenDAL Community,

This is a call for a vote to release Apache OpenDAL reqsign version X.Y.Z.

The release candidate:

https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z/

Keys to verify the release candidate:

https://downloads.apache.org/opendal/KEYS

Git tag for the release candidate:

https://github.com/apache/opendal-reqsign/releases/tag/vX.Y.Z-rc.N

The tag points to commit:

COMMIT_SHA

Please download, verify, and test.

The VOTE will be open for at least 72 hours and until the necessary number of votes are reached.

- [ ] +1 approve
- [ ] +0 no opinion
- [ ] -1 disapprove with the reason

Checklist for reference:

- [ ] Download links are valid.
- [ ] Checksums and signatures are valid.
- [ ] LICENSE/NOTICE files exist.
- [ ] No unexpected binary files.
- [ ] All source files have ASF headers.
- [ ] Can compile from source.

Thanks,
NAME
```

## After Vote Passes

1. Verify vote state.

   Confirm at least three binding `+1` votes and no blocking `-1` votes.

2. Publish vote result.

   Create a GitHub Discussion in General.

   Title:

   ```text
   [RESULT][VOTE] Release Apache OpenDAL reqsign X.Y.Z - Vote Round 1
   ```

   Body:

   ```text
   Hello, Apache OpenDAL Community,

   The vote to release Apache OpenDAL reqsign X.Y.Z has passed.

   The vote PASSED with N +1 binding votes, no +0 or -1 votes.

   Binding votes:

   - VOTER_1
   - VOTER_2
   - VOTER_3

   Vote thread: VOTE_THREAD_URL

   Thanks,
   NAME
   ```

3. Push the formal signed tag.

   Use the exact voted RC commit.

   ```bash
   git checkout vX.Y.Z-rc.N
   test "$(git rev-parse vX.Y.Z-rc.N^{})" = "COMMIT_SHA"
   git tag -s vX.Y.Z -m "vX.Y.Z"
   git tag -v vX.Y.Z
   git push origin vX.Y.Z
   ```

4. Move ASF artifacts from dev to release.

   ```bash
   svn mv --force-interactive \
     https://dist.apache.org/repos/dist/dev/opendal/reqsign-X.Y.Z \
     https://dist.apache.org/repos/dist/release/opendal/reqsign-X.Y.Z \
     -m "Release reqsign X.Y.Z"
   ```

5. Monitor the GitHub Release workflow.

   ```bash
   gh run list --repo apache/opendal-reqsign --workflow Release --limit 5
   gh run view RUN_ID --repo apache/opendal-reqsign --json status,conclusion,url,jobs
   ```

6. Verify crates.io versions.

   ```bash
   for c in \
     reqsign reqsign-core reqsign-aliyun-oss reqsign-aws-v4 reqsign-azure-storage \
     reqsign-command-execute-tokio reqsign-file-read-tokio reqsign-google \
     reqsign-http-send-reqwest reqsign-huaweicloud-obs reqsign-oracle \
     reqsign-tencent-cos reqsign-volcengine-tos
   do
     cargo info "$c" --registry crates-io | sed -n '1,4p'
   done
   ```

7. Create a GitHub Release.

   Use the formal tag and include source artifact links, notable changes, and crate versions.

8. Send announcement.

   Create an announcement in the repo's Announcements category if permissions allow. If GitHub returns `FORBIDDEN`, report this explicitly and do not post into the wrong category.

   Wait for `downloads.apache.org`/`dlcdn.apache.org` mirror sync before sending a broad announcement that uses mirror URLs. The SVN release URL may be available earlier:

   ```text
   https://dist.apache.org/repos/dist/release/opendal/reqsign-X.Y.Z/
   ```

## Recovery Notes

- If `main` advances after the vote starts, formal `vX.Y.Z` still points to the RC commit, not latest `origin/main`.
- If `downloads.apache.org` returns 404 immediately after SVN release move, wait for mirror sync. Do not send announcements with broken mirror links.
- If SVN authentication fails, retry with `--force-interactive`; run `svn cleanup` if a killed commit leaves the working copy locked.
- If the Announcements discussion category is restricted, do not use General as a silent fallback.
