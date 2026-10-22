#!/usr/bin/env bash
# Removes only this project's governance objects, never the sandbox resource group.
set -euo pipefail
: "${AZURE_SUBSCRIPTION_ID:?}"
: "${AZURE_RESOURCE_GROUP:?}"
prefix=$(python3 -c 'import json; print(json.load(open("config.json"))["prefix"])')
[[ "${CONFIRM_POLICY_CLEANUP:-}" == "$prefix" ]]
[[ "$(az account show --query id -o tsv)" == "$AZURE_SUBSCRIPTION_ID" ]]
scope="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$AZURE_RESOURCE_GROUP"
export GOVERNANCE_ASSIGNMENT_ID="$scope/providers/Microsoft.Authorization/policyAssignments/$prefix"
mkdir -p build
az policy exemption list --scope "$scope" -o json > build/exemptions-before-cleanup.json
python3 - <<'PY' > build/owned-exemption-names.txt
import json, os
rows = json.load(open('build/exemptions-before-cleanup.json'))
for row in rows:
    props = row.get('properties', row)
    if props.get('policyAssignmentId', '').casefold() != os.environ['GOVERNANCE_ASSIGNMENT_ID'].casefold():
        continue
    if props.get('metadata', {}).get('managedBy') != 'azure-policy-guardrails':
        raise SystemExit('A foreign exemption refers to this assignment. Review it before cleanup.')
    print(row['name'])
PY
while IFS= read -r exemption; do
  az policy exemption delete --name "$exemption" --scope "$scope"
done < build/owned-exemption-names.txt
az policy assignment delete --name "$prefix" --scope "$scope"
az policy set-definition delete --name "$prefix-baseline"
for ref in locations tags storage-tls storage-public-blob; do
  az policy definition delete --name "$prefix-$ref"
done
echo 'Removed project governance objects; the resource group and workload resources remain.'
