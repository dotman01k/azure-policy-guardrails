"""Dependency-free compiler. Azure, rather than this program, evaluates live policy."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re
import uuid

REFERENCES = ("locations", "tags", "storage-tls", "storage-public-blob")
SUB_SCHEMA = "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#"
RG_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"


def validate_config(config):
    if set(config) != {"prefix", "allowedLocations", "requiredTags"}:
        raise ValueError("config must contain exactly prefix, allowedLocations, requiredTags")
    if not re.fullmatch(r"[a-z][a-z0-9]{2,15}", str(config["prefix"])):
        raise ValueError("prefix must be 3..16 lowercase alphanumeric characters")
    for key, pattern in (("allowedLocations", r"[a-z][a-z0-9]+"),
                         ("requiredTags", r"[A-Za-z][A-Za-z0-9_.-]{0,63}")):
        values = config[key]
        if not isinstance(values, list) or not 1 <= len(values) <= 20:
            raise ValueError(f"{key} must contain 1..20 strings")
        if any(not isinstance(v, str) or not re.fullmatch(pattern, v) for v in values):
            raise ValueError(f"invalid value in {key}")
        if len({v.casefold() for v in values}) != len(values):
            raise ValueError(f"duplicate value in {key}")
    return config


def validate_target(subscription, resource_group):
    if str(uuid.UUID(subscription)) != subscription.lower():
        raise ValueError("subscription must be a UUID")
    if not re.fullmatch(r"[A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,89}", resource_group) or resource_group.endswith("."):
        raise ValueError("invalid resource group name")


def policy_rules(config):
    """Unescaped Azure Policy expressions; escape only at the ARM boundary."""
    return {
        "locations": {"allOf": [
            {"field": "location", "notIn": "[parameters('allowedLocations')]"},
            {"field": "location", "notEquals": "global"},
        ]},
        "tags": {"anyOf": [
            {"anyOf": [{"field": f"tags['{tag}']", "exists": "false"},
                       {"field": f"tags['{tag}']", "equals": ""}]}
            for tag in config["requiredTags"]
        ]},
        "storage-tls": {"allOf": [
            {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
            {"field": "Microsoft.Storage/storageAccounts/minimumTlsVersion", "notEquals": "TLS1_2"},
        ]},
        "storage-public-blob": {"allOf": [
            {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
            {"field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "notEquals": False},
        ]},
    }


def arm_escape(value):
    if isinstance(value, dict):
        return {k: arm_escape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [arm_escape(v) for v in value]
    return "[" + value if isinstance(value, str) and value.startswith("[") else value


def compile_templates(config, subscription, resource_group, effect="Audit"):
    validate_config(config)
    validate_target(subscription, resource_group)
    if effect not in ("Audit", "Deny"):
        raise ValueError("effect must be Audit or Deny")
    prefix = config["prefix"]
    resources = []
    references = []
    effect_param = {"type": "String", "allowedValues": ["Audit", "Deny"], "defaultValue": "Audit"}
    for ref, condition in policy_rules(config).items():
        name = f"{prefix}-{ref}"
        params = {"effect": effect_param}
        if ref == "locations":
            params = {**params, "allowedLocations": {"type": "Array"}}
        resources.append({
            "type": "Microsoft.Authorization/policyDefinitions", "apiVersion": "2023-04-01",
            "name": name, "properties": {
                "policyType": "Custom", "displayName": f"{prefix}: {ref}",
                "mode": "Indexed" if ref in ("locations", "tags") else "All",
                "metadata": {"category": "Custom governance", "version": "1.0.0", "managedBy": "azure-policy-guardrails"},
                "parameters": params,
                "policyRule": arm_escape({"if": condition, "then": {"effect": "[parameters('effect')]"}}),
            },
        })
        mapping = {"effect": {"value": "[[parameters('effect')]"}}
        if ref == "locations":
            mapping["allowedLocations"] = {"value": "[[parameters('allowedLocations')]"}
        references.append({
            "policyDefinitionReferenceId": ref,
            "policyDefinitionId": f"[subscriptionResourceId('Microsoft.Authorization/policyDefinitions', '{name}')]",
            "parameters": mapping,
        })
    initiative = f"{prefix}-baseline"
    resources.append({
        "type": "Microsoft.Authorization/policySetDefinitions", "apiVersion": "2023-04-01",
        "name": initiative,
        "dependsOn": [f"[subscriptionResourceId('Microsoft.Authorization/policyDefinitions', '{prefix}-{ref}')]" for ref in REFERENCES],
        "properties": {
            "policyType": "Custom", "displayName": f"{prefix}: resource governance baseline",
            "metadata": {"category": "Custom governance", "version": "1.0.0"},
            "parameters": {"effect": effect_param, "allowedLocations": {"type": "Array", "defaultValue": config["allowedLocations"]}},
            "policyDefinitions": references,
        },
    })
    definitions = {"$schema": SUB_SCHEMA, "contentVersion": "1.0.0.0", "resources": resources}
    assignment_id = f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Authorization/policyAssignments/{prefix}"
    assignment = {
        "$schema": RG_SCHEMA, "contentVersion": "1.0.0.0", "resources": [{
            "type": "Microsoft.Authorization/policyAssignments", "apiVersion": "2024-04-01", "name": prefix,
            "properties": {
                "displayName": f"{prefix}: {effect} baseline", "enforcementMode": "Default",
                "policyDefinitionId": f"/subscriptions/{subscription}/providers/Microsoft.Authorization/policySetDefinitions/{initiative}",
                "parameters": {"effect": {"value": effect}, "allowedLocations": {"value": config["allowedLocations"]}},
                "nonComplianceMessages": [{"message": "Review location, required tags and storage security settings; request a time-limited exemption with a ticket when needed."}],
            },
        }],
    }
    return {"definitions.json": definitions, "assignment.json": assignment,
            "manifest.json": {"prefix": prefix, "effect": effect, "assignmentId": assignment_id,
                              "resourceGroup": resource_group, "subscriptionId": subscription,
                              "references": list(REFERENCES)}}


def compile_exemption(config, subscription, resource_group, name, references, expires_on, ticket, reason, now=None):
    validate_config(config)
    validate_target(subscription, resource_group)
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", name):
        raise ValueError("invalid exemption name")
    if not references or len(set(references)) != len(references) or set(references) - set(REFERENCES):
        raise ValueError("provide explicit, unique initiative reference IDs")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*-[0-9]+", ticket) or len(reason.strip()) < 20:
        raise ValueError("a ticket such as CHG-123 and a reason of at least 20 characters are required")
    expiry = datetime.fromisoformat(expires_on.replace("Z", "+00:00"))
    now = now or datetime.now(timezone.utc)
    if expiry.tzinfo is None or not now < expiry <= now + timedelta(days=90):
        raise ValueError("expiry must include a timezone and fall within the next 90 days")
    assignment_id = f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Authorization/policyAssignments/{config['prefix']}"
    return {"$schema": RG_SCHEMA, "contentVersion": "1.0.0.0", "resources": [{
        "type": "Microsoft.Authorization/policyExemptions", "apiVersion": "2022-07-01-preview", "name": name,
        "properties": {"displayName": name, "description": reason, "exemptionCategory": "Waiver",
                       "policyAssignmentId": assignment_id, "policyDefinitionReferenceIds": references,
                       "expiresOn": expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                       "metadata": {"ticket": ticket, "managedBy": "azure-policy-guardrails"}},
    }]}


def compliance_report(rows, assignment_id):
    """Count policy evaluation records, not unique resources; reject empty exports."""
    if isinstance(rows, dict):
        rows = rows.get("value")
    if not isinstance(rows, list):
        raise ValueError("expected a list or an object containing value[]")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("every policy state must be an object")
    selected = [r for r in rows if r.get("policyAssignmentId", "").casefold() == assignment_id.casefold()]
    if not selected:
        raise ValueError("no matching policy states; trigger a scan and retry, do not infer compliance")
    counts = Counter(r.get("complianceState", "Unknown") for r in selected)
    resource_ids = {r["resourceId"].casefold() for r in selected if r.get("resourceId")}
    return {"assignmentId": assignment_id, "evaluationRecords": len(selected),
            "uniqueResources": len(resource_ids), "states": dict(sorted(counts.items())),
            "nonCompliantRecords": counts.get("NonCompliant", 0),
            "unknownRecords": sum(v for k, v in counts.items() if k not in ("Compliant", "NonCompliant", "Exempt"))}
