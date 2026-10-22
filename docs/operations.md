# Operations runbook

## OIDC bootstrap for a dedicated sandbox

These commands change identity/RBAC only when explicitly run by an authorized operator. They are not executed by local validation. Use Azure CLI, GitHub CLI (`gh`) signed into your own account, Python 3, and Bash. Git Bash on Windows additionally needs `export MSYS_NO_PATHCONV=1`. Never paste tokens into chat or commit them.

```bash
export AZURE_SUBSCRIPTION_ID='<sandbox-subscription-id>'
export AZURE_TENANT_ID='<tenant-id>'
export AZURE_RESOURCE_GROUP='rg-governance-sandbox'
export PROJECT_REPOSITORY='dotman01k/azure-policy-guardrails'
az login --tenant "$AZURE_TENANT_ID"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
az group show --name "$AZURE_RESOURCE_GROUP" -o table

export AZURE_CLIENT_ID=$(az ad app create \
  --display-name 'azure-policy-guardrails-deploy' --query appId -o tsv)
az ad sp create --id "$AZURE_CLIENT_ID" -o none
export DEPLOY_PRINCIPAL_ID=$(az ad sp show --id "$AZURE_CLIENT_ID" --query id -o tsv)
az role assignment create --assignee-object-id "$DEPLOY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role 'Resource Policy Contributor' \
  --scope "/subscriptions/$AZURE_SUBSCRIPTION_ID"
```

Application creation is not idempotent by display name. Record the client and principal IDs immediately and reuse them on retries; don't run `az ad app create` repeatedly. Role propagation may take time. The principal ID identifies the role assignee; the client ID identifies the Azure login application.

Obtain the immutable subject base from the intended repository, only after it exists:

```bash
export OIDC_SUBJECT_BASE=$(gh api "repos/$PROJECT_REPOSITORY" \
  --jq '"repo:\(.owner.login)@\(.owner.id)/\(.name)@\(.id)"')
```

For a repository that actually emits the legacy name-only subject, use `repo:OWNER/REPOSITORY` instead. Match the exact subject from the Azure Login error/token claim, rather than guessing or broadening trust. Do not print an OIDC JWT or access token. Modern immutable subjects include IDs, protecting against name reuse. Generate the two federated credential JSON files without string interpolation into shell commands:

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
for environment in ('governance-audit', 'governance-enforce'):
    credential = {
        'name': environment,
        'issuer': 'https://token.actions.githubusercontent.com',
        'subject': os.environ['OIDC_SUBJECT_BASE'] + ':environment:' + environment,
        'audiences': ['api://AzureADTokenExchange'],
    }
    Path(environment + '.local.json').write_text(json.dumps(credential))
PY
for environment in governance-audit governance-enforce; do
  az ad app federated-credential create --id "$AZURE_CLIENT_ID" \
    --parameters "@$environment.local.json"
done
```

These credential JSON documents hold trust metadata, not secrets; they are ignored by git anyway. Do not create an Entra client secret. Existing federated credential names require update rather than another create. Configure GitHub environment variables/reviewers as described in README. Remove temporary local JSON files when no longer needed.

## Promotion acceptance checklist

1. Use a sandbox subscription or a separately approved governance scope. Record the exact subscription ID, RG and unique definition prefix.
2. Review compiler diff and source validation. Verify the four actual Azure Policy aliases for API versions used by your resources.
3. Deploy Audit. Wait for a policy scan to finish and retain the report privately.
4. Inspect affected existing resources. Noncompliance counts are policy evaluation records, not a count of blocked deployments or unique assets.
5. Resolve configuration problems and approve any scoped, dated exemption through your change process.
6. Preview Deny. Confirm the assignment's effect parameter is Deny and `enforcementMode` is Default.
7. Require approval in `governance-enforce`, then apply from the reviewed commit.
8. In the approved sandbox, confirm compliant and noncompliant resource operations behave as expected. Such live acceptance tests can create billable resource usage and are not automated by this repository.

## Roll back enforcement

Use the same subscription, group and prefix. Run `bash scripts/deploy.sh what-if Audit`, review, then `bash scripts/deploy.sh apply Audit`. This changes enforcement to audit rather than deleting workload resources. Evaluation may remain stale briefly. A higher-scope Deny assignment can still block operations; this project's Audit assignment cannot override it.

## Exemptions and ownership

The exemption compiler deliberately supports only waivers for this assignment at the target RG scope. It accepts a nonempty subset of the four reference IDs and records a ticket, reason, expiry, and managedBy marker. It rejects expired, timezone-free and more-than-90-day timestamps. Azure retains expired exemption objects; review and remove them deliberately after their audit retention period. Do not mark an entire initiative exempt just to suppress one failed control.

Azure requires both permission to write an exemption at its scope and the policy assignment `exempt/action`. Resource Policy Contributor includes governance actions; verify current custom-role equivalents before substituting roles. Do not give an application identity exemption-management permissions.

## Troubleshooting

| Symptom | Diagnosis and action |
| --- | --- |
| Azure Login AADSTS700213 | Compare federated subject, issuer and audience exactly. Include immutable repo/owner IDs when emitted. Verify environment spelling and client ID. |
| AuthorizationFailed for definitions | RG-scoped rights cannot deploy subscription definitions. Check identity and Resource Policy Contributor scope. |
| Assignment preview deferred | Expected before initiative creation. Review generated assignment and deploy definitions in Audit first. |
| Alias rejected by Azure | Check the current alias catalog and API support, then update the custom definition and tests. Offline tests cannot prove Azure alias availability. |
| Compliant-looking resource denied | Examine all applicable inherited assignments, missing tag values, partial PUT/PATCH payloads and provider defaults. Keep the exact denial details. |
| No policy states | Evaluation is asynchronous. Trigger a scan, verify RG/assignment ID and wait for actual matching rows. Empty output is an error. |
| Report exit code 2 | The export has NonCompliant or unknown-state records. Inspect `build/policy-states.json` privately. |
| Exemption rejected | Verify the selected reference IDs belong to this initiative, expiry includes UTC/timezone, and the operator has exemption write plus assignment exempt/action. |
| Deny workflow doesn't pause | Required reviewers were not configured or are unsupported. Do not treat an environment name as a protection rule. |
| Cleanup fails partway | Preserve the error. Inspect remaining exemptions/assignments/definitions and rerun only after resolving dependencies. Do not delete the RG to remove policies. |

## Safe cleanup and retained data

The cleanup script reads applicable exemptions, ignores unrelated assignment IDs, refuses to delete a foreign-owned exemption attached to this assignment, then deletes owned exemption objects, the RG assignment, subscription initiative, and the four definitions. The operator explicitly sets `CONFIRM_POLICY_CLEANUP` to the configured prefix. Other assignments using the initiative can prevent deletion. Removing a policy stops future governance from this assignment; it does not repair, delete or deallocate resources previously governed by it.

The example templates use incremental ARM deployment. Removing a resource from source does not automatically delete it from Azure. Use the cleanup script for retired definitions. Deployment history records can be removed separately if your retention policy permits; they are not active assignments.

Remove the dedicated role assignment and application registration only after all deployments and governance object cleanup are complete. Record the actual principal/client IDs, review their ownership, and remove only this project's objects. The script intentionally does not delete identities or revoke broader account access automatically.
