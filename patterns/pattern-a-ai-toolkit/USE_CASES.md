# Validated Pattern A demonstration catalogue

“Validated” here means that the screenshots demonstrate a functioning local inference path and that the use case has been assessed for safe presentation. It does not mean every captured model answer is correct.

## 1. Event-to-MITRE ATT&CK assistance

**Goal:** propose candidate ATT&CK techniques for a small set of selected security events.

**Recommended input:** bounded event text plus only the entity and time fields needed by the analyst.

**Required output contract:** `technique_id`, `technique_name`, `confidence`, `event_basis`, `uncertainty` and `reference_version`.

**Acceptance controls:**

- validate every ID/name pair against a pinned local ATT&CK STIX catalogue;
- reject deprecated or unknown IDs;
- require a direct event-text rationale;
- do not infer maliciousness from a technique mapping;
- keep the original event and model output separately attributable.

**Screenshot assessment:** the captured output includes `T1086` and `T1143`. Current Enterprise ATT&CK uses `T1059.001` for PowerShell and `T1113` for Screen Capture. This is a clear example of model knowledge drift and why raw LLM mapping is advisory only.

## 2. Telemetry coverage-gap hypotheses

**Goal:** ask which behaviours may remain undetected when only a stated telemetry category is available.

**Required evidence:** actual data-source inventory, field population, time coverage, collection health, detection catalogue and ATT&CK version.

**Acceptance controls:** label the answer `HYPOTHESIS`; validate it against live inventory and detection coverage; distinguish “not observed”, “not collected” and “not detectable”.

The model can suggest questions. It cannot prove a monitoring gap from a generic prompt.

## 3. SPL optimisation assistance

**Goal:** propose a safer or more efficient alternative to analyst-supplied SPL.

**Acceptance controls:**

- parse both searches;
- block risky commands;
- preserve source scope, time range, filters, grouping and result semantics;
- compare counts and key sets on a bounded validation range;
- explain every removed or changed command;
- require analyst approval before replacing a saved search.

**Screenshot assessment:** the proposed rewrite is faster-looking but drops material source and relationship logic. Present the capture as a guardrail lesson, not as an accepted optimisation.

## 4. Raw search to accelerated `tstats`

**Goal:** propose a CIM/Data Model equivalent for an existing search.

**Prerequisites:** relevant data is CIM mapped, fields are populated, data-model constraints match the source, acceleration is enabled where intended and the role can access the model.

**Acceptance controls:** compare raw and `tstats` results across the same time range; check count, entity and status equivalence; document any loss of raw-only fields; retain a rollback path.

The LLM may draft the conversion but cannot prove the prerequisites.

## 5. JSON-to-CIM field-mapping proposal

**Goal:** propose `FIELDALIAS`, `EVAL` or extraction candidates from a bounded sample.

**Acceptance controls:**

- confirm the correct CIM data model and field definitions;
- test on representative events from every expected schema variant;
- validate types, multi-value behaviour and null handling;
- detect naming collisions and precedence issues;
- run `btool` or the approved configuration validator;
- deploy through normal review and change control.

Never paste model-generated configuration directly into a production app.

