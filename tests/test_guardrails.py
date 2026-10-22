import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from guardrails.core import compile_templates, compile_exemption, compliance_report, policy_rules, validate_config

CONFIG = {"prefix": "azguarddev", "allowedLocations": ["eastus", "eastus2"], "requiredTags": ["owner", "costCenter"]}
SUB = "00000000-0000-0000-0000-000000000001"
RG = "rg-governance-sandbox"
ASSIGNMENT = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Authorization/policyAssignments/azguarddev"
NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


def evaluate(condition, resource):
    """Test-only evaluator for the small emitted operator subset; not Azure Policy."""
    if "allOf" in condition:
        return all(evaluate(c, resource) for c in condition["allOf"])
    if "anyOf" in condition:
        return any(evaluate(c, resource) for c in condition["anyOf"])
    field = condition["field"]
    if field.startswith("tags['"):
        tag = field[6:-2]
        value = resource.get("tags", {}).get(tag)
    elif field.startswith("Microsoft.Storage/storageAccounts/"):
        value = resource.get("properties", {}).get(field.rsplit("/", 1)[1])
    else:
        value = resource.get(field)
    if "exists" in condition:
        return (value is not None) == (condition["exists"] == "true")
    if "notIn" in condition:
        return value not in CONFIG["allowedLocations"]
    if "notEquals" in condition:
        return value != condition["notEquals"]
    return value == condition["equals"]


class CompileTests(unittest.TestCase):
    def test_repeatable_build(self):
        self.assertEqual(compile_templates(CONFIG, SUB, RG), compile_templates(CONFIG, SUB, RG))

    def test_default_audit(self):
        artifacts = compile_templates(CONFIG, SUB, RG)
        self.assertEqual(artifacts['assignment.json']['resources'][0]['properties']['parameters']['effect']['value'], 'Audit')

    def test_deny_is_explicit(self):
        self.assertEqual(compile_templates(CONFIG, SUB, RG, 'Deny')['manifest.json']['effect'], 'Deny')
        with self.assertRaises(ValueError):
            compile_templates(CONFIG, SUB, RG, 'Modify')

    def test_policy_expressions_escaped_for_arm(self):
        definitions = compile_templates(CONFIG, SUB, RG)['definitions.json']['resources']
        for definition in definitions[:4]:
            self.assertEqual(definition['properties']['policyRule']['then']['effect'], "[[parameters('effect')]")
        self.assertEqual(definitions[-1]['properties']['policyDefinitions'][0]['parameters']['effect']['value'], "[[parameters('effect')]")

    def test_definition_dependencies_and_reference_ids(self):
        resources = compile_templates(CONFIG, SUB, RG)['definitions.json']['resources']
        self.assertEqual(len(resources), 5)
        self.assertEqual(len(resources[-1]['dependsOn']), 4)
        self.assertEqual(len({r['policyDefinitionReferenceId'] for r in resources[-1]['properties']['policyDefinitions']}), 4)

    def test_assignment_has_no_identity(self):
        assignment = compile_templates(CONFIG, SUB, RG)['assignment.json']['resources'][0]
        self.assertNotIn('identity', assignment)
        self.assertEqual(assignment['properties']['enforcementMode'], 'Default')

    def test_config_rejects_duplicates_and_unknown_keys(self):
        for updates in ({'requiredTags': ['owner', 'OWNER']}, {'prefix': 'BAD prefix'}, {'oops': True}, {'allowedLocations': []}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                validate_config({**CONFIG, **updates})

    def test_invalid_target(self):
        for sub, rg in [('not-a-guid', RG), (SUB, '../other'), (SUB, 'ends.')]:
            with self.subTest(sub=sub, rg=rg), self.assertRaises(ValueError):
                compile_templates(CONFIG, sub, rg)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.resource = {'type': 'Microsoft.Storage/storageAccounts', 'location': 'eastus',
                         'tags': {'owner': 'platform', 'costCenter': 'engineering'},
                         'properties': {'minimumTlsVersion': 'TLS1_2', 'allowBlobPublicAccess': False}}
        self.rules = policy_rules(CONFIG)

    def test_compliant_storage_has_no_violations(self):
        self.assertFalse(any(evaluate(c, self.resource) for c in self.rules.values()))

    def test_disallowed_location_is_detected(self):
        self.resource['location'] = 'westus'
        self.assertTrue(evaluate(self.rules['locations'], self.resource))

    def test_global_location_is_excluded(self):
        self.resource['location'] = 'global'
        self.assertFalse(evaluate(self.rules['locations'], self.resource))

    def test_missing_or_empty_tags(self):
        for tags in ({}, {'owner': '', 'costCenter': 'engineering'}, {'owner': 'platform'}):
            self.resource['tags'] = tags
            self.assertTrue(evaluate(self.rules['tags'], self.resource))

    def test_legacy_or_missing_tls(self):
        for value in ('TLS1_0', 'TLS1_1', None):
            self.resource['properties']['minimumTlsVersion'] = value
            self.assertTrue(evaluate(self.rules['storage-tls'], self.resource))

    def test_public_access_and_missing_property(self):
        for value in (True, None):
            self.resource['properties']['allowBlobPublicAccess'] = value
            self.assertTrue(evaluate(self.rules['storage-public-blob'], self.resource))

    def test_storage_rules_ignore_other_types(self):
        self.resource['type'] = 'Microsoft.Compute/virtualMachines'
        self.resource['properties'] = {}
        for ref in ('storage-tls', 'storage-public-blob'):
            self.assertFalse(evaluate(self.rules[ref], self.resource))


class ExemptionTests(unittest.TestCase):
    def exemption(self, **overrides):
        args = dict(config=CONFIG, subscription=SUB, resource_group=RG, name='legacy-tls',
                    references=['storage-tls'], expires_on='2026-11-01T00:00:00Z', ticket='CHG-123',
                    reason='Temporary waiver while legacy integration is migrated.', now=NOW)
        return compile_exemption(**{**args, **overrides})

    def test_scoped_expiring_exemption(self):
        p = self.exemption()['resources'][0]['properties']
        self.assertEqual(p['policyAssignmentId'], ASSIGNMENT)
        self.assertEqual(p['policyDefinitionReferenceIds'], ['storage-tls'])
        self.assertEqual(p['expiresOn'], '2026-11-01T00:00:00Z')

    def test_expired_unbounded_or_timezone_free_rejected(self):
        for expiry in ['2026-10-20T00:00:00Z', '2027-10-21T00:00:00Z', '2026-11-01T00:00:00']:
            with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                self.exemption(expires_on=expiry)

    def test_unknown_empty_or_duplicate_references_rejected(self):
        for refs in [[], ['*'], ['storage-tls', 'storage-tls']]:
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                self.exemption(references=refs)

    def test_justification_required(self):
        for values in [{'ticket': 'none'}, {'reason': 'short'}]:
            with self.assertRaises(ValueError):
                self.exemption(**values)


class ReportTests(unittest.TestCase):
    def test_counts_records_separately_from_resources(self):
        rows = [{'policyAssignmentId': ASSIGNMENT, 'resourceId': '/r/one', 'complianceState': state}
                for state in ['Compliant', 'NonCompliant', 'Exempt', 'NotStarted']]
        rows.append({'policyAssignmentId': '/other', 'resourceId': '/r/two', 'complianceState': 'NonCompliant'})
        result = compliance_report({'value': rows}, ASSIGNMENT.upper())
        self.assertEqual(result['evaluationRecords'], 4)
        self.assertEqual(result['uniqueResources'], 1)
        self.assertEqual(result['unknownRecords'], 1)
        self.assertEqual(result['nonCompliantRecords'], 1)

    def test_empty_export_is_not_success(self):
        for value in [[], {'value': []}, {'bad': []}, ['invalid-row']]:
            with self.assertRaises(ValueError):
                compliance_report(value, ASSIGNMENT)

    def test_cli_noncompliance_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'states.json'
            path.write_text(json.dumps([{'policyAssignmentId': ASSIGNMENT, 'complianceState': 'NonCompliant'}]))
            run = subprocess.run([sys.executable, '-m', 'guardrails', 'report', '--input', str(path),
                                  '--assignment-id', ASSIGNMENT, '--fail-on-noncompliance'], capture_output=True)
            self.assertEqual(run.returncode, 2, run.stderr.decode())

    def test_cli_build_creates_all_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            run = subprocess.run([sys.executable, '-m', 'guardrails', 'build', '--subscription', SUB,
                                  '--resource-group', RG, '--output', temp], capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual({p.name for p in Path(temp).iterdir()}, {'definitions.json', 'assignment.json', 'manifest.json'})


if __name__ == '__main__':
    unittest.main()
