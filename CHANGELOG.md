# Changelog

## Unreleased - 2026-09-26

- Added raw-generation canonicalisation, untrusted-content taint checks, requester-authority checks for privileged shell and secret access, and issued-secret trace state.
- Added no-label-leakage regression coverage plus mutation and property tests for the new controls.
- Updated benchmark artifacts: test block rate improved from 76.6% to 90.0% with 0 leaks and unchanged 0.8% false-positive rate.
- Renamed result labels and paths.
- Renamed project to **Contextual Trust Policy Engine**; Python package and CLI use descriptive names.

## 0.1.0 - 2026-09-25

- Initial implementation with native policy decision point, Open Policy Agent policy, tests, benchmarks, and formal specification.
