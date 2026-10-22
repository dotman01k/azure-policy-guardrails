#!/usr/bin/env bash
set -euo pipefail
: "${AZURE_SUBSCRIPTION_ID:?}"
: "${AZURE_RESOURCE_GROUP:?}"
[[ "$(az account show --query id -o tsv)" == "$AZURE_SUBSCRIPTION_ID" ]]
prefix=$(python3 -c 'import json; print(json.load(open("config.json"))["prefix"])')
assignment_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$AZURE_RESOURCE_GROUP/providers/Microsoft.Authorization/policyAssignments/$prefix"
mkdir -p build
az policy state list --resource-group "$AZURE_RESOURCE_GROUP" --all -o json > build/policy-states.json
python3 -m guardrails report --input build/policy-states.json --assignment-id "$assignment_id" --fail-on-noncompliance
