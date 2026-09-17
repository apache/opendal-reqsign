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

# Keep the fixture alive while Azure Pipelines uses its read-only identity.
set -euo pipefail
run_id=""
completed=false

# Called by the EXIT handler.
# shellcheck disable=SC2329
cancel_unfinished_run() {
  access_token=$(az account get-access-token \
    --resource https://app.vssps.visualstudio.com/ \
    --query accessToken \
    --output tsv) || return
  state=$(curl --fail-with-body --silent --show-error \
    --header "Authorization: Bearer $access_token" \
    "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}/_apis/pipelines/${AZURE_DEVOPS_PIPELINE_ID}/runs/${run_id}?api-version=7.1" |
    jq --raw-output '.state') || return
  if [[ "$state" != "completed" ]]; then
    curl --fail-with-body --silent --show-error \
      --request PATCH \
      --header "Authorization: Bearer $access_token" \
      --header "Content-Type: application/json" \
      --data '{"status":"cancelling"}' \
      "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}/_apis/build/builds/${run_id}?api-version=7.1" \
      >/dev/null
  fi
}
# shellcheck disable=SC2329
cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n "$run_id" && "$completed" != true ]]; then
    if ! cancel_unfinished_run; then
      echo "Failed to cancel the unfinished Azure Pipelines run" >&2
      if (( result == 0 )); then result=1; fi
    fi
  fi
  exit "$result"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

access_token=$(az account get-access-token \
  --resource https://app.vssps.visualstudio.com/ \
  --query accessToken \
  --output tsv)
test -n "$access_token"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  echo "::add-mask::$access_token"
fi

# Pass the probe as a run variable so the bootstrap YAML needs no new parameter.
request_body=$(jq --null-input \
  --arg github_sha "$GITHUB_SHA" \
  --arg github_ref "$GITHUB_REF" \
  --arg probe_url "$REQSIGN_AZURE_STORAGE_PROBE_URL" \
  '{templateParameters: {githubSha: $github_sha, githubRef: $github_ref},
    variables: {REQSIGN_AZURE_STORAGE_PROBE_URL: {value: $probe_url}}}')
response_file="$RUNNER_TEMP/azure-pipelines-queue-response.json"
if ! http_status=$(curl --silent --show-error \
  --output "$response_file" \
  --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer $access_token" \
  --header "Content-Type: application/json" \
  --data "$request_body" \
  "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}/_apis/pipelines/${AZURE_DEVOPS_PIPELINE_ID}/runs?api-version=7.1"); then
  echo "Failed to send the Azure Pipelines queue request" >&2
  exit 1
fi
if (( http_status < 200 || http_status >= 300 )); then
  message=$(jq --raw-output '.message // .error.message // "No error message returned"' \
    "$response_file" 2>/dev/null || echo "Non-JSON error response")
  message=$(tr '\r\n' '  ' <<< "$message" | cut -c1-1000)
  echo "Azure Pipelines queue request failed with HTTP $http_status: $message" >&2
  exit 1
fi
response=$(<"$response_file")

run_id=$(jq --raw-output '.id // empty' <<< "$response")
run_url=$(jq --raw-output '._links.web.href // empty' <<< "$response")
test -n "$run_id"
test -n "$run_url"
echo "Queued Azure Pipelines run: $run_url"

deadline=$((SECONDS + 3300))
while (( SECONDS < deadline )); do
  access_token=$(az account get-access-token \
    --resource https://app.vssps.visualstudio.com/ \
    --query accessToken \
    --output tsv)
  response=$(curl --fail-with-body --silent --show-error \
    --header "Authorization: Bearer $access_token" \
    "https://dev.azure.com/${AZURE_DEVOPS_ORGANIZATION}/${AZURE_DEVOPS_PROJECT}/_apis/pipelines/${AZURE_DEVOPS_PIPELINE_ID}/runs/${run_id}?api-version=7.1")
  state=$(jq --raw-output '.state' <<< "$response")
  result=$(jq --raw-output '.result // empty' <<< "$response")
  if [[ "$state" == "completed" ]]; then
    completed=true
    echo "Azure Pipelines run completed with result '$result': $run_url"
    test "$result" = "succeeded"
    exit
  fi
  sleep 15
done
echo "Azure Pipelines run did not complete before the timeout: $run_url" >&2
exit 1
