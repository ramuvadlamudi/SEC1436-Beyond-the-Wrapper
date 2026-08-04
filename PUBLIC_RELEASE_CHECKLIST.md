# Public Release Checklist

`ARIA_GITHUB_RELEASE_AUDIT=PASS` confirms technical sanitization of the generated source archive. It does not grant permission to publish.

Complete every item before creating or making a public repository:

## Ownership and approvals

- [ ] Confirm the contributor has the right to publish all source, documentation and assets.
- [ ] Obtain employer or organisational intellectual-property approval.
- [ ] Obtain security, open-source programme and export-control review where required.
- [ ] Confirm Apache License 2.0 is the approved outbound licence.
- [ ] Confirm the project name, logo, conference references and product claims are approved for public use.

## Privacy and secrets

- [ ] Run `python scripts/build_github_source.py`.
- [ ] Run `python scripts/audit_github_release.py` and require `ARIA_GITHUB_RELEASE_AUDIT=PASS`.
- [ ] Independently secret-scan the extracted archive using the publishing organisation's approved scanner.
- [ ] Confirm `.env`, credentials, API tokens, certificates and private keys are absent.
- [ ] Confirm audit logs, runtime prompts, test results and customer data are absent.
- [ ] Confirm every published screenshot contains only approved generic demonstration content and no credentials, private addresses, customer identifiers or live sensitive telemetry.
- [ ] Confirm private/customer hostnames, usernames, paths, IP addresses, index names, sourcetypes and entities are absent. Public laboratory values may appear only in explicitly approved demonstration screenshots.
- [ ] Confirm all Pattern A screenshots are approved for publication and their model outputs are clearly labelled as untrusted assistance.

## Accuracy and support

- [ ] Run `python validate_v3_acceptance.py --skip-live` from the exact source state being published.
- [ ] Complete connected acceptance in the conference environment.
- [ ] Confirm README support statements match the controlled-preview status.
- [ ] Confirm the security-reporting channel in `SECURITY.md` is configured before publication.
- [ ] Confirm authoritative framework citations and trademark notices remain present.
- [ ] Confirm Pattern C is labelled experimental and is not represented as an implemented RC11 capability or product commitment.

## Repository controls

- [ ] Enable branch protection and required status checks.
- [ ] Enable private vulnerability reporting and secret scanning.
- [ ] Add approved maintainers and a code-owner policy.
- [ ] Tag the exact accepted commit; do not tag an unvalidated working tree.
- [ ] Retain the source archive checksum and acceptance output with the internal release record.
