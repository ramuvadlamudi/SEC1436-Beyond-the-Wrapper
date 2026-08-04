# ARIA v3 Acceptance

Release requires two layers.

## Package gates

Run:

```bash
python validate_v3_acceptance.py --skip-live
```

This validates architecture, routing, isolated and grounded SOC conversation, SPL construction, triage evidence controls, safety, UI, controlled packaging, sanitized GitHub packaging and transactional deployment.

The package gate also replays the complete conference UI route sequence. It blocks release unless:

- capability-help reaches Identity;
- extended portable/deployment SPL wording reaches SPL Builder;
- analyst window/threshold refinement stays with SPL Builder;
- generated-SPL review reaches SPL Review and runs no search;
- destructive search intent reaches Safety and grants no execution;
- Detection Candidate, RBA/ERS and TDIR reach the Evidence Deliverable Agent;
- chained deliverables preserve evidence IDs, run no new search and execute no action;
- missing risk eligibility produces no invented score;
- unrelated general-purpose content reaches Scope Guard.

The Builder refinement step is also a semantic gate. For the exact analyst
follow-up, portable SPL must contain `span=10m`,
`dc({DISTINCT_VALUE_FIELD})`, entity and related-value grouping placeholders,
and `aria_distinct_value_count > 50`. No workflow term may become a `like(...)`
filter. A deployment variant must bind all aggregation fields or explicitly
remain unavailable.

Required marker:

```text
ARIA_V3_SPL_REFINEMENT_SEMANTICS_TEST=PASS
ARIA_V3_SCHEMA_BINDING_CORROBORATION_TEST=PASS
```

The schema-corroboration regression gives unrelated observed fields artificially
perfect embedding similarity and proves that `bytes`, `protocol` and
destination-IP fields cannot satisfy the requested subdomain, entity and
parent-domain concepts. A separate positive control proves that corroborated
live field names can still produce schema-qualified aggregation SPL.

Connected acceptance additionally requires `ARIA_V3_DELIVERABLE_LIVE_ACCEPTANCE=PASS`, proving that the actual Investigation-to-Triage handoff survives through Detection Candidate, RBA/ERS and TDIR without a new Splunk query or action.

## Connected Splunk gate

Run `scripts/live_v3_acceptance.py` with an environment-relevant BUILD_SPL question and a positive-control investigation question whose selected live source contains events. The gate validates inventory, deployment-qualified SPL, safe live investigation, triage and post-Investigation/Triage SOC conversation isolation.

The connected gate fails unless:

- A standalone SOC concept question routes to the Conversation Agent after Investigation and Triage responses.
- The Conversation Agent returns a contract-valid local-model answer to the current topic without executing Splunk or repeating operational history.
- Named framework anchors are preserved in the exact definition rather than being replaced by an adjacent framework.
- Framework answers use the deep response contract, include all six required sections and contain at least 260 words.
- Curated framework answers preserve required authoritative phrases and cite the bundled primary sources.
- A referential follow-up remains grounded in the named framework from bounded same-agent context and cannot drift to NIST CSF, MITRE ATT&CK or another adjacent framework.
- Investigation returns at least one bounded evidence row.
- Returned rows represent at least one live event.
- Every required bound field is populated in execution.
- At least one execution event contains the complete required field set.
- Qualification and execution are consistent at both event and required-field level.
- Triage retains the current investigation, returns non-zero evidence confidence and preserves returned-row evidence identifiers.

`INSUFFICIENT_EVIDENCE` remains a valid security verdict when returned facts do not prove the requested behaviour. Event volume alone must not be described as unusual or suspicious. It is not valid for the release gate to hide a qualification/execution contradiction behind that verdict.

## GitHub publication gate

The package suite builds `releases/aria-v<version>-github-source.tar.gz` and audits it for required public documentation, licensing metadata, reference attribution, secrets, private deployment data, audit logs, release archives and environment-specific addresses.

`ARIA_GITHUB_RELEASE_AUDIT=PASS` means the generated archive passed the technical publication checks. It does not replace organisational approval for intellectual property, branding, trademarks or the selected open-source licence.

After the live report passes, run:

```bash
python validate_v3_acceptance.py
```

Required marker:

```text
ARIA_V3_FINAL_ACCEPTANCE_STATUS=PASS
```
