# Pattern A security and validation controls

## Minimum safe profile

| Control | Requirement |
|---|---|
| Data access | Least-privilege Splunk role and approved datasets only |
| Command access | `apply_ai_commander_command` for operators; connection editing restricted |
| Input size | Explicit time bound, row cap and field allowlist before `| ai` |
| Input content | Exclude credentials, secrets and unnecessary raw payloads |
| Model location | Approved Ollama endpoint inside the enclave |
| Output handling | Treat `ai_result_*` as untrusted analyst assistance |
| SPL proposals | Parse, safety-check and equivalence-test before use |
| Framework mappings | Validate against a pinned local authoritative catalogue |
| Operational actions | No automatic detection, notable, risk or response writeback |
| Audit | Record search owner, model, prompt version, input selection, time and decision |

## Threats to test

- Prompt injection embedded in log messages.
- Delimiter escape or instructions inside `_raw`.
- Hallucinated fields, indexes, sourcetypes, techniques or thresholds.
- Stale framework knowledge and deprecated identifiers.
- Silent semantic loss during SPL rewriting.
- Sensitive-data reproduction in model output.
- Excessive row-by-row inference causing search-head or Ollama saturation.
- Model timeout, partial output and provider unavailability.
- Unapproved provider/model selection.

## Release gate for a Pattern A use case

A use case is demo-ready only when all statements are true:

- [ ] The source search is read-only and bounded before `| ai`.
- [ ] Every source, field, value and threshold is observed or analyst supplied.
- [ ] The prompt says what the model may and may not conclude.
- [ ] Output format and failure behaviour are explicit.
- [ ] A deterministic or analyst validation step exists.
- [ ] The test contains a positive case, a negative case and an adversarial-input case.
- [ ] Latency and resource use are measured with the selected model.
- [ ] No model answer can trigger an operational action.
- [ ] The demo narration distinguishes assistance, evidence and approval.

Pattern A is intentionally lightweight. Use Pattern B when the outcome needs live evidence qualification, evidence identifiers, confidence logic, abstention and multi-agent handoff.

