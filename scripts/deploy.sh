#!/usr/bin/env bash
set -euo pipefail
: "${AZURE_SUBSCRIPTION_ID:?}"
: "${AZURE_RESOURCE_GROUP:?Existing sandbox resource group required}"
: "${LOCATION:=eastus}"
operation=${1:-what-if}
effect=${2:-Audit}
[[ "$operation" == what-if || "$operation" == apply ]]
[[ "$effect" == Audit || "$effect" == Deny ]]
actual_subscription=$(az account show --query id -o tsv)
[[ "$actual_subscription" == "$AZURE_SUBSCRIPTION_ID" ]]
az group show -n "$AZURE_RESOURCE_GROUP" -o none
python3 -m guardrails build --subscription "$AZURE_SUBSCRIPTION_ID" \
  --resource-group "$AZURE_RESOURCE_GROUP" --effect "$effect"
prefix=$(python3 -c 'import json; print(json.load(open("config.json"))["prefix"])')
if [[ "$operation" == what-if ]]; then
  az deployment sub what-if --name "$prefix-definitions" --location "$LOCATION" --template-file build/definitions.json
  if az policy set-definition show --name "$prefix-baseline" -o none 2>/dev/null; then
    az deployment group what-if --name "$prefix-assignment" -g "$AZURE_RESOURCE_GROUP" --template-file build/assignment.json
  else
    echo 'Assignment Azure what-if deferred: the initiative must exist first. Review build/assignment.json.'
  fi
else
  az deployment sub create --name "$prefix-definitions" --location "$LOCATION" --template-file build/definitions.json -o none
  az deployment group what-if --name "$prefix-assignment" -g "$AZURE_RESOURCE_GROUP" --template-file build/assignment.json
  az deployment group create --name "$prefix-assignment" -g "$AZURE_RESOURCE_GROUP" --template-file build/assignment.json -o none
fi
