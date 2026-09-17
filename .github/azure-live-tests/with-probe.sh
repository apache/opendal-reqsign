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

# Run a live test with its own private blob. Setup credentials stay separate
# from the credential provider exercised by the test command.
set -euo pipefail

: "${AZURE_STORAGE_ACCOUNT:?Set the fixture storage account}"
: "${AZURE_STORAGE_CONTAINER:?Set the fixture container}"
(( $# > 0 )) || { echo "Usage: with-probe.sh command [args...]" >&2; exit 2; }

auth_mode=${AZURE_STORAGE_AUTH_MODE:-login}
if [[ "$auth_mode" == key ]]; then
  export AZURE_STORAGE_KEY="${REQSIGN_AZURE_STORAGE_ACCOUNT_KEY:?Set the fixture account key}"
fi
storage_args=(--auth-mode "$auth_mode" --account-name "$AZURE_STORAGE_ACCOUNT"
  --container-name "$AZURE_STORAGE_CONTAINER" --only-show-errors)
blob_name="ci-probe-$(python3 -c 'import uuid; print(uuid.uuid4())').txt"
probe_dir=$(mktemp -d)
created=false
cleanup() {
  local result=$?
  trap - EXIT
  if [[ "$created" == true ]]; then
    if ! az storage blob delete "${storage_args[@]}" --name "$blob_name" --output none; then
      echo "Failed to delete the live-test probe" >&2
      if (( result == 0 )); then result=1; fi
    fi
  fi
  rm -rf "$probe_dir"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'reqsign-live-azure-ok\n' > "$probe_dir/probe.txt"
az storage blob upload "${storage_args[@]}" --name "$blob_name" \
  --file "$probe_dir/probe.txt" --overwrite false --output none
created=true
export REQSIGN_AZURE_STORAGE_PROBE_URL="https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/${AZURE_STORAGE_CONTAINER}/${blob_name}"

# SAS cases use a short-lived, read-only token for this exact object.
if [[ "$auth_mode" == key ]]; then
  expiry=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%MZ"))')
  sas_token=$(az storage blob generate-sas "${storage_args[@]}" --name "$blob_name" \
    --permissions r --expiry "$expiry" --https-only --output tsv)
  test -n "$sas_token"
  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    echo "::add-mask::$sas_token"
  fi
  export REQSIGN_AZURE_STORAGE_SAS_TOKEN="$sas_token"
fi
"$@"
