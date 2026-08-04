## Summary

Describe the analyst or product outcome delivered by this change.

## Safety and evidence impact

- [ ] Routing remains deterministic.
- [ ] No customer-specific index, sourcetype, field, value, entity, event ID or threshold was embedded.
- [ ] Executable SPL remains read-only, bounded and validator-approved.
- [ ] Evidence claims retain source/query/row references or explicit gaps.
- [ ] Detection, risk and response outputs remain approval-gated.
- [ ] No credential, audit log, runtime data or private environment value is included.

## Validation

- [ ] `python validate_v3_acceptance.py --skip-live`
- [ ] Connected acceptance completed when live behaviour changed.
- [ ] `python scripts/build_github_source.py`
- [ ] `python scripts/audit_github_release.py`

## Documentation

List the user, operator, architecture or security documentation updated by this change.
