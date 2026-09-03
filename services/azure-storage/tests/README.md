# Azure Storage Tests

The Azure Storage test suite separates deterministic protocol parsing from live
credential-provider acceptance tests. Unit tests parse sanitized responses that
were captured from Azure. Integration tests obtain credentials from the real
provider and use `RequestSigner` to read a fixed private blob.

## Test Structure

```text
tests/
├── credential_providers/     # Live tests for every credential provider
│   ├── static_provider.rs
│   ├── env.rs
│   ├── default.rs
│   ├── imds.rs
│   ├── workload_identity.rs
│   ├── client_secret.rs
│   ├── client_certificate.rs
│   ├── azure_cli.rs
│   └── azure_pipelines.rs
├── fixtures/                 # Sanitized responses captured from Azure
│   ├── entra_token_response.json
│   ├── azure_cli_token_response.json
│   └── imds_token_response.json
└── signing/                  # Shared Key and SAS signing tests
```

The credential-provider tests do not use HTTP mocks. A live test succeeds only
after Azure Blob Storage returns the expected object body.

## Local Tests

Run the deterministic suite without Azure credentials:

```bash
cargo test -p reqsign-azure-storage --lib --tests --no-fail-fast
```

Live tests are disabled unless their provider-specific environment variable is
set to `on`. For example:

```bash
REQSIGN_AZURE_STORAGE_TEST_CLI=on \
REQSIGN_AZURE_STORAGE_URL=https://example.blob.core.windows.net/container/blob \
cargo test -p reqsign-azure-storage --test main \
  credential_providers::azure_cli::test_azure_cli_provider -- --exact
```

## Live Test Configuration

Every live provider test requires `REQSIGN_AZURE_STORAGE_URL`. The URL must
identify a blob that contains `reqsign-live-azure-ok\n`.

| Variable | Provider |
| --- | --- |
| `REQSIGN_AZURE_STORAGE_TEST` | `StaticCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_ENV` | `EnvCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_DEFAULT` | `DefaultCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_IMDS` | `ImdsCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_WORKLOAD_IDENTITY` | `WorkloadIdentityCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_CLI` | `AzureCliCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_CLIENT_SECRET` | `ClientSecretCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_CLIENT_CERTIFICATE` | `ClientCertificateCredentialProvider` |
| `REQSIGN_AZURE_STORAGE_TEST_PIPELINES` | `AzurePipelinesCredentialProvider` |

The source providers use these values:

| Variable | Credential |
| --- | --- |
| `REQSIGN_AZURE_STORAGE_ACCOUNT_NAME` | Static Shared Key account name |
| `REQSIGN_AZURE_STORAGE_ACCOUNT_KEY` | Static Shared Key account key |
| `REQSIGN_AZURE_STORAGE_SAS_TOKEN` | Static SAS token |
| `REQSIGN_AZURE_STORAGE_BEARER_TOKEN` | Static bearer token |
| `AZURE_STORAGE_ACCOUNT_NAME` | Environment Shared Key account name |
| `AZURE_STORAGE_ACCOUNT_KEY` | Environment Shared Key account key |
| `AZURE_STORAGE_SAS_TOKEN` | Environment SAS token |
| `AZURE_STORAGE_BEARER_TOKEN` | Environment bearer token |

The Entra providers use the standard Azure variables, including
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
`AZURE_CLIENT_CERTIFICATE_PATH`, and `AZURE_FEDERATED_TOKEN_FILE`.
`AzurePipelinesCredentialProvider` receives
`AZURESUBSCRIPTION_CLIENT_ID`, `AZURESUBSCRIPTION_TENANT_ID`,
`AZURESUBSCRIPTION_SERVICE_CONNECTION_ID`, and `SYSTEM_ACCESSTOKEN` from an
`AzureCLI@2` task.

## CI Coverage

GitHub Actions runs deterministic unit tests for all changes. Each credential
provider has an independent live-test job, matching the AWS workflow's failure
isolation and summary structure. Trusted same-repository changes run live tests
for:

- Static Shared Key, SAS, and bearer credentials.
- Environment Shared Key, SAS, and bearer credentials.
- Client secret and client certificate credentials.
- Azure CLI and GitHub workload identity credentials.
- The default credential chain.
- IMDS on an ephemeral private Azure VM with a user-assigned managed identity.
- Shared Key and SAS request signing against Azure Blob Storage.

The IMDS job uploads the test binary to a private blob, creates a VM without a
public IP, runs the exact provider test through Azure Run Command, and removes
the VM and uploaded binary in an unconditional cleanup step.

GitHub Actions queues `AzurePipelinesCredentialProvider` through the Azure
DevOps REST API and waits for the result as part of the GitHub check. The queued
run receives the exact GitHub ref and commit, then uses an Azure Resource Manager
workload-identity service connection for the provider test. Azure DevOps has no
repository or scheduled trigger for this pipeline. It uses a dedicated Azure VM
Scale Set agent pool with one-node maximum capacity, zero standby agents, and
automatic recycling after every job.

The final summary reports and enforces every provider and signing job
independently for trusted changes.

## 1Password Configuration

GitHub Actions reads the existing `reqsign/azure-storage` item through
1Password Connect. The workflow uses these existing fields without renaming or
creating fields:

- `url`
- `account_name`
- `account_key`
- `sas_token`
- `tenant_id`
- `client_id`
- `client_secret`
- `certificate_pem_base64`

## Updating Fixtures

Fixtures must come from the corresponding real Azure endpoint or command. Mask
access tokens, client IDs, tenant IDs, subscription IDs, and user-identifying
fields before committing the response. Preserve field names, JSON value types,
and time formats so the parser test continues to represent the service contract.
