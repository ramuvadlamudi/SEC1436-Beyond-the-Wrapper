# ARIA v3 Operator Guide

ARIA v3 is an air-gapped, evidence-first SOC copilot for Splunk Enterprise. It separates four product capabilities behind a deterministic control plane:

1. **SOC Conversation Agent** — product identity, cybersecurity explanation, SPL review and conversation context.
2. **SPL Builder Agent** — portable SPL plus deployment-qualified SPL derived from the connected Splunk catalogue and observed schema.
3. **Investigation Agent** — read-only hypothesis-driven investigation with evidence references, confidence and gaps.
4. **Triage Agent** — bounded finding/incident triage with verdict, confidence, supporting evidence and next action.

An **Evidence Deliverable Agent** consumes the current structured result to draft Detection Candidate, RBA/ERS, TDIR and SOAR material. It runs no new Splunk query and executes no operational action.

All agents use one **Telemetry Intelligence Service** for catalogue discovery, raw-profile access, observed fields, sample values, time coverage and cache freshness. The local LLM may interpret or explain, but it never controls routing, write permissions or the SPL safety decision.

Curated public framework questions can also use an **Offline Reference Knowledge** layer. Source-attributed local cards preserve exact framework facts and citations. A grounded local-model timeout or contract failure returns a deterministic cited answer from the same card instead of drifting to an adjacent concept.

## Start and validate

```bash
cd ~/aria-pattern-b
source .venv/bin/activate
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"

python validate_product.py
python validate_runtime.py
python aria_safe_startup_check.py
python aria_health.py
```

## Core smoke tests

Run each prompt in a new investigation unless testing conversation continuity.

```text
Hi
```

Expected: `IDENTITY`; no Splunk query.

```text
Give me telemetry from the connected Splunk instance.
```

Expected: `INVENTORY`; live read-only catalogue results.

```text
Build SPL for repeated failed authentication activity during the last 24 hours. Do not assume an index, sourcetype or field name.
```

Expected: `BUILD_SPL`; portable SPL and deployment-qualified SPL; final SPL not executed.

```text
Investigate DNS tunnelling using live Splunk evidence across all available time.
```

Expected: `INVESTIGATION`; bounded read-only searches or an explicit evidence gap.

For a release positive-control source containing live events, the response must
also show a returned evidence row, a positive bounded-event count, positive
presence for every required execution field, at least one fully-bound execution
event and `Qualification/execution consistency: PASS`.

```text
Triage finding ID <analyst-supplied-value> using live Splunk evidence.
```

Expected: `TRIAGE`; verdict, confidence, evidence references, gaps and next action.

## Deployment

ARIA v3 uses the transactional deployment script. Source compilation and package checks occur before the active runtime is replaced. A complete rollback checkpoint is created before copy, and failed post-copy checks restore the prior runtime.

```bash
python scripts/deploy_v3_release.py \
  --archive ~/aria-v3.0.0-rc11.tar \
  --target ~/aria-pattern-b \
  --no-restart

sudo systemctl restart aria-llm-gateway aria-web
```

## Connected acceptance

```bash
python scripts/live_v3_acceptance.py \
  --build-question 'Build SPL for analysing PowerShell encoded-command execution across all available time. Use the connected Splunk deployment to qualify the source and observed schema, but do not execute the final SPL.' \
  --investigation-question 'Investigate DNS tunnelling using live Splunk evidence across all available time.' \
  --conversation-question 'What is MITRE ATLAS?' \
  --conversation-followup-question 'How can a SOC use that framework to monitor AI-enabled systems with Splunk?'
```

Required marker:

```text
ARIA_V3_CONVERSATION_LIVE_ACCEPTANCE=PASS
ARIA_V3_DELIVERABLE_LIVE_ACCEPTANCE=PASS
ARIA_V3_LIVE_ACCEPTANCE=PASS
```

The markers are emitted only when live investigation evidence survives into
Triage and both post-Investigation/Triage SOC questions remain isolated from the
operational transcript. The framework answer and its referential follow-up must
preserve the exact named subject, retain authoritative phrases and citations,
use the deep six-section contract and meet the minimum useful depth. Safe search
execution without result evidence, concept substitution, missing citations, or
a contaminated or shallow Conversation response is a release failure.

Then run:

```bash
python validate_v3_acceptance.py
```

Required marker:

```text
ARIA_V3_FINAL_ACCEPTANCE_STATUS=PASS
```

## Operational boundary

- Splunk access is read-only.
- BUILD_SPL does not execute the final query.
- Investigation and triage execute only validator-approved bounded searches.
- Customer indexes, sourcetypes, fields, event IDs, entities, values and thresholds are never embedded in product runtime logic.
- Detection, RBA, ERS, TDIR and SOAR outputs remain analyst-reviewed recommendations unless a separately approved write-capable integration is introduced.
