# 1Password Setup for Reqsign Tests

This document describes how to set up 1Password for managing secrets in GitHub Actions.

## Prerequisites

1. 1Password Connect server deployed and accessible
2. GitHub repository secrets configured:
   - `OP_CONNECT_HOST`: Your 1Password Connect server URL
   - `OP_CONNECT_TOKEN`: Authentication token for 1Password Connect

## Secret Organization

Secrets are organized in 1Password vaults with the following structure:

```
services/
├── aws-v4/
│   ├── test_enabled                    # "on"
│   ├── access_key                      # Static AWS access key for signing tests
│   ├── secret_key                      # Static AWS secret key for signing tests
│   ├── region                          # AWS region (e.g., "us-east-1")
│   ├── service                         # AWS service (e.g., "s3")
│   ├── url                             # S3 bucket URL for testing
│   ├── test_env_enabled                # "on" to enable EnvCredentialProvider tests
│   ├── env_access_key_id               # Access key for EnvCredentialProvider
│   ├── env_secret_access_key           # Secret key for EnvCredentialProvider
│   ├── test_assume_role_enabled        # "on" to enable AssumeRole tests
│   ├── assume_role_arn                 # ARN of role to assume
│   ├── base_access_key_id              # Base credentials for AssumeRole
│   ├── base_secret_access_key          # Base credentials for AssumeRole
│   ├── test_web_identity_enabled       # "on" to enable WebIdentity tests
│   ├── web_identity_role_arn           # ARN for WebIdentity role
│   ├── test_cognito_enabled            # "on" to enable Cognito tests
│   └── cognito_identity_pool_id        # Cognito identity pool ID
├── aws-v4-s3-express/
│   └── bucket                          # S3 Express bucket name (format: name--azid--x-s3)
├── azure-storage/
│   ├── test_enabled                    # "on"
│   ├── account_name                    # Azure storage account name
│   ├── account_key                     # Azure storage account key
│   └── ...
├── google/
│   ├── test_enabled                    # "on"
│   ├── service_account                 # Google service account JSON
│   └── ...
└── ...
```

## Creating Secrets in 1Password

1. Create a vault named `reqsign-tests` (or use an existing vault)
2. Create items following the structure above
3. For each service, create an item with fields for each secret

Example for AWS V4:
```
Title: services/aws-v4
Fields:
  - test_enabled: on
  - access_key: AKIAIOSFODNN7EXAMPLE
  - secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  - region: us-east-1
  - service: s3
  - url: https://my-test-bucket.s3.amazonaws.com
  ...
```

Example for S3 Express:
```
Title: aws-v4-s3-express
Fields:
  - bucket: my-bucket--use1-az5--x-s3
```

## GitHub Actions Usage

The workflow uses 1Password GitHub Action to load secrets:

```yaml
- name: Setup 1Password Connect
  uses: 1password/load-secrets-action/configure@v3
  with:
    connect-host: ${{ secrets.OP_CONNECT_HOST }}
    connect-token: ${{ secrets.OP_CONNECT_TOKEN }}

- name: Load secrets
  uses: 1password/load-secrets-action@13f58eec611f8e5db52ec16247f58c508398f3e6
  with:
    export-env: true
  env:
    REQSIGN_AWS_V4_TEST: op://reqsign/aws-v4/test_enabled
    REQSIGN_AWS_V4_ACCESS_KEY: op://reqsign/aws-v4/access_key
    # ... more secrets
```

## Security Best Practices

1. **Least Privilege**: Only grant necessary permissions to test credentials
2. **Rotation**: Regularly rotate test credentials
3. **Monitoring**: Monitor usage of test credentials
4. **Isolation**: Use separate AWS accounts/resources for testing
5. **Conditional Access**: Tests only run on the base repository, not on forks

## Troubleshooting

### Tests are skipped
- Check if the PR is from a fork (integration tests don't run on forked PRs)
- Verify 1Password Connect is accessible
- Check GitHub Actions logs for secret loading errors

### Authentication failures
- Verify credentials in 1Password are correct
- Check if credentials have expired
- Ensure proper permissions are granted

### 1Password Connect errors
- Verify `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` are correctly set
- Check network connectivity to 1Password Connect server
- Review 1Password Connect server logs
