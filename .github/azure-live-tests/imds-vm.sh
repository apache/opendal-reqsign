#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set -euo pipefail

: "${AZURE_RUNTIME_RESOURCE_GROUP:?}"
: "${RUNNER_TEMP:?}"
attempts_file="$RUNNER_TEMP/azure-imds-vm-attempts"

case "${1:-}" in
  create)
    : "${GITHUB_RUN_ID:?}"
    : "${GITHUB_RUN_ATTEMPT:?}"
    : "${GITHUB_OUTPUT:?}"
    : "${AZURE_IMDS_IDENTITY_ID:?}"
    ssh-keygen -q -t ed25519 -N '' -f "$RUNNER_TEMP/azure-imds-vm-key"
    : > "$attempts_file"
    attempt=0
    while read -r location vnet size; do
      attempt=$((attempt + 1))
      vm_name="reqsign-imds-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${location}-${attempt}"
      # Record before provisioning so cleanup also covers partial deployments.
      echo "$vm_name" >> "$attempts_file"
      if az vm create \
        --resource-group "$AZURE_RUNTIME_RESOURCE_GROUP" \
        --name "$vm_name" --location "$location" \
        --image Ubuntu2404 --size "$size" \
        --admin-username azureuser \
        --ssh-key-values "$RUNNER_TEMP/azure-imds-vm-key.pub" \
        --assign-identity "$AZURE_IMDS_IDENTITY_ID" \
        --vnet-name "$vnet" --subnet reqsign-ci-subnet \
        --nsg "" --public-ip-address "" --security-type Standard \
        --os-disk-name "${vm_name}-os" \
        --nic-delete-option Delete --os-disk-delete-option Delete \
        --tags Project=reqsign Purpose=live-test GitHubRunId="$GITHUB_RUN_ID" \
        --only-show-errors --output none; then
        echo "name=$vm_name" >> "$GITHUB_OUTPUT"
        exit 0
      fi
    done <<'CANDIDATES'
eastus reqsign-ci-vnet Standard_B1s
eastus reqsign-ci-vnet Standard_B2s
eastus reqsign-ci-vnet Standard_D2s_v6
eastus2 reqsign-ci-vnet-eastus2 Standard_B1s
eastus2 reqsign-ci-vnet-eastus2 Standard_B2s
eastus2 reqsign-ci-vnet-eastus2 Standard_D2s_v7
eastus2 reqsign-ci-vnet-eastus2 Standard_D2s_v6
CANDIDATES
    echo "All configured Azure VM deployment attempts failed; see the errors above" >&2
    exit 1
    ;;
  cleanup)
    [[ -f "$attempts_file" ]] || exit 0
    result=0
    while read -r vm_name; do
      if ! vm_id=$(az vm list --resource-group "$AZURE_RUNTIME_RESOURCE_GROUP" \
        --query "[?name=='${vm_name}'].id | [0]" --output tsv --only-show-errors); then
        result=1
        continue
      fi
      if [[ -n "$vm_id" ]]; then
        if ! az vm delete --ids "$vm_id" --yes --force-deletion true --only-show-errors; then
          result=1
          continue
        fi
      fi
      # A failed deployment may create a NIC or disk without creating a VM.
      if ! resource_ids=$(az resource list --resource-group "$AZURE_RUNTIME_RESOURCE_GROUP" \
        --query "[?name=='${vm_name}VMNic' || name=='${vm_name}-os'].id" \
        --output tsv --only-show-errors); then
        result=1
        continue
      fi
      while IFS= read -r resource_id; do
        [[ -n "$resource_id" ]] || continue
        az resource delete --ids "$resource_id" --only-show-errors || result=1
      done <<< "$resource_ids"
    done < "$attempts_file"
    exit "$result"
    ;;
  *) echo "Usage: imds-vm.sh create|cleanup" >&2; exit 2 ;;
esac
