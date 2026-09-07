# Google Cloud Tests

The Google test suite separates deterministic protocol coverage from live
credential-provider acceptance. Deterministic tests replay sanitized responses
captured from Google services. Live tests obtain a real credential and use it
to read a fixed private Cloud Storage object containing
`reqsign-live-google-ok\n`.

## CI Contract

The workflow runs on pull requests and pushes to `main`; it has no scheduled
trigger.

- Pull requests without 1Password Connect secrets, including fork and
  Dependabot pull requests, run unit tests and sanitized response replays.
- Pull requests that receive the Connect secrets run the deterministic suite
  and every live test.
- Every push to `main` runs the deterministic suite and every live test again.

The live workflow follows the same failure-isolation model as the AWS and
Azure workflows: every credential provider or distinct signing path has its
own job. All live jobs depend on one shared probe-preparation job, and the
summary reports and enforces every job result independently.

Live tests cover:

- `StaticCredentialProvider`, `FileCredentialProvider`,
  `EnvCredentialProvider`, `WellKnownCredentialProvider`, and
  `DefaultCredentialProvider` with a service-account credential.
- Authorized-user ADC refresh through Google OAuth, from both an explicit
  credential path and the gcloud well-known location.
- GitHub OIDC workload identity through Security Token Service and IAM
  Credentials, including caller-provided subject tokens.
- `TokenCredentialProvider` with a live workload-identity access token.
- Both the ADC-shaped and typed service-account impersonation providers.
- IAM Credentials `generateAccessToken` and `signBlob`.
- Server-side and client-side Credential Access Boundary flows.
- `VmMetadataCredentialProvider` on an ephemeral private Compute Engine VM.
- OAuth bearer signing and service-account signed URLs against Cloud Storage.

Each provider must read the fixed probe successfully. Merely obtaining or
parsing a token is not live acceptance.

## Personal Google Cloud Resources

All live resources belong to the personal `reqsign` project:

- Bucket: `gs://reqsign`
- Probe: `gs://reqsign/live/credential-ok`
- CAB probe: `gs://reqsign/live/cab/allowed/credential-ok`
- Metadata identity: `reqsign-metadata@reqsign.iam.gserviceaccount.com`
- Impersonation target:
  `reqsign-impersonated@reqsign.iam.gserviceaccount.com`
- Runtime region: `us-east1`

The metadata job builds the integration-test binary on GitHub, uploads it as a
short-lived private object, and starts an `e2-micro` VM without a public IP.
The VM has a 15-minute maximum runtime and automatic deletion. The workflow
also removes the VM and binary in an unconditional cleanup step.

Each trusted run recreates and verifies the two fixed probe objects through
workload identity before any provider test starts. This keeps the test oracle
stable if an object is removed outside CI while still failing against the real
Cloud Storage control and data planes.

## Live Test Variables

| Variable | Purpose |
| --- | --- |
| `REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE` | OAuth scope used by Storage requests |
| `REQSIGN_GOOGLE_CLOUD_STORAGE_PROBE_URL` | JSON API media URL for the fixed probe |
| `REQSIGN_GOOGLE_CLOUD_STORAGE_SIGNED_PROBE_URL` | XML API URL for signed URL validation |
| `REQSIGN_GOOGLE_CREDENTIAL` | Base64 service-account JSON |
| `GOOGLE_APPLICATION_CREDENTIALS` | ADC credential file path |
| `REQSIGN_GOOGLE_AUTHORIZED_USER_CREDENTIALS` | Authorized-user ADC file path |
| `REQSIGN_GOOGLE_ACCESS_TOKEN` | Live token for token and typed impersonation providers |
| `REQSIGN_GOOGLE_SUBJECT_TOKEN` | Caller-provided GitHub OIDC token |
| `REQSIGN_GOOGLE_WORKLOAD_IDENTITY_AUDIENCE` | Google STS audience |
| `GOOGLE_SERVICE_ACCOUNT` | WIF service account |
| `REQSIGN_GOOGLE_IMPERSONATED_SERVICE_ACCOUNT` | Typed impersonation target |
| `REQSIGN_GOOGLE_CAB_BUCKET` | CAB test bucket |
| `REQSIGN_GOOGLE_CAB_OBJECT_PREFIX` | Allowed CAB object prefix |

Provider-specific `REQSIGN_GOOGLE_TEST_*` variables gate live tests. CI sets
them only on the exact live test step so deterministic runs never reach Google.

## 1Password Configuration

GitHub Actions reads the existing `reqsign/google` item through 1Password
Connect. The workflow uses these fields:

- `credential_base64`
- `authorized_user_base64`
- `impersonated_sa_base64`
- `workload_identity_provider`
- `service_account_email`

No Google credential is available to fork or Dependabot pull-request jobs.

## Running Tests

Run deterministic tests and response replays:

```bash
cargo test -p reqsign-google --lib --tests --all-features --no-fail-fast
```

Live tests are disabled unless their exact gate variable is `on`. For example:

```bash
REQSIGN_GOOGLE_TEST_STATIC=on \
REQSIGN_GOOGLE_CREDENTIAL="$SERVICE_ACCOUNT_JSON_BASE64" \
REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE=https://www.googleapis.com/auth/devstorage.read_only \
REQSIGN_GOOGLE_CLOUD_STORAGE_PROBE_URL='https://storage.googleapis.com/storage/v1/b/reqsign/o/live%2Fcredential-ok?alt=media' \
cargo test -p reqsign-google --test main \
  credential_providers::static_provider:: -- --no-capture
```

## Updating Response Replays

Files under `tests/fixtures/` must come from the corresponding real Google
endpoint. Replace access tokens, refresh tokens, JWTs, private keys, session
keys, account emails, and project identifiers before committing. Preserve
field names, JSON types, optional-field presence, and time formats.

A fixture update is accepted only after the same live path succeeds against
Google Cloud Storage. Synthetic malformed, timeout, and transport cases may be
derived from a captured response, but must not become the source for a success
fixture.

The repository currently contains captured success responses for authorized
user OAuth, Compute Engine metadata, IAM Credentials `generateAccessToken`, and
server-side CAB STS. Service-account OAuth, direct GitHub workload-identity
STS, client-side CAB STS, and IAM Credentials `signBlob` still require captured
success fixtures. Keep their live tests authoritative until those responses
have been captured and sanitized; do not replace them with fabricated success
fixtures.
