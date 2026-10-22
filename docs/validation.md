# Validation evidence

Validation date: October 21, 2026.

## Passed locally

1. Python standard-library unittest suite: 23 tests. It covers deterministic compilation, default Audit and explicit Deny, ARM escaping, initiative dependencies, bounded target names, duplicate/invalid input rejection, missing/empty tags, global-location exclusion, invalid TLS/public blob settings, non-storage exclusion, scoped/expiring waivers, record/resource report distinctions, empty exports, and CLI exit behavior.
2. Bash syntax checks for deployment, compliance export and cleanup scripts.
3. Audit and Deny artifact generation and JSON parse checks.
4. Exemption generation using a future timestamp relative to the validation date.
5. Synthetic compliance CLI gate returned exit code 2 for a noncompliant evaluation record.
6. Workflow YAML parsed successfully with expected workflow/job/permission structure.

`docs/local-tests.txt` contains the captured unittest output. `examples/expected-report.json` contains actual CLI output for the synthetic example. These are local fixtures, not live compliance evidence.

## Not established by local validation

Authenticated ARM validation/what-if, Azure Policy alias acceptance, policy assignment creation, compliance scan, live Audit/Deny enforcement, and exemption propagation require an authorized Azure sandbox. The checked-in workflows provide a path to perform those operations. Offline rule evaluation supports only the small emitted operator subset; it is not an Azure Policy emulator.

## GitHub publication and CI

Published October 22, 2026, to https://github.com/dotman01k/azure-policy-guardrails.
The **Validate governance source** push workflow completed successfully for implementation
commit `6f7feb2e10d7d68e38dede54e5be0f68fc817ade`:
https://github.com/dotman01k/azure-policy-guardrails/actions/runs/39732099639.
It independently ran the 23 Python tests, shell syntax checks and ARM artifact compilation.
Local tests were also rerun successfully on October 22 before upload. These are source/CI checks,
not authenticated Azure enforcement evidence. The workflows remain manual for live deployment.
