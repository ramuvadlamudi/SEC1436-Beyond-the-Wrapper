# Pattern A demonstration validation report

**Review date:** 2026-08-04  
**Scope:** five supplied Splunk screenshots using AI Toolkit `| ai` with a local model  
**Decision:** include as a validated demonstration pattern with explicit accuracy and control caveats

## Overall result

| Question | Result |
|---|---|
| Does the capture show Splunk invoking a model and returning an `ai_result_*` field? | PASS |
| Is the use-case set relevant to SOC and Splunk workflows? | PASS |
| Is every generated answer technically correct and current? | NO |
| Can the generated SPL or `.conf` output be deployed without validation? | NO |
| Is Pattern A suitable for demonstrating fast local inference? | PASS |
| Does Pattern A alone provide ARIA Pattern B evidence controls? | NO |

## Capture-level assessment

### 01 — Event-to-MITRE assistance

- **Connectivity:** pass.
- **Use-case value:** high for candidate mapping and analyst acceleration.
- **Accuracy finding:** the response includes stale or incorrect mappings. `T1086` is a deprecated PowerShell identifier now represented by `T1059.001`; Screen Capture is `T1113`, not the displayed `T1143`.
- **Demo narration:** “The local model proposes. A pinned local ATT&CK catalogue validates.”

### 02 — Coverage-gap hypotheses

- **Connectivity:** pass.
- **Use-case value:** useful for generating review questions.
- **Accuracy finding:** a generic prompt cannot prove what the deployment collects or detects.
- **Demo narration:** “This creates a hypothesis backlog; live inventory and detection coverage establish the gap.”

### 03 — SPL optimisation assistance

- **Connectivity:** pass.
- **Use-case value:** useful as a review assistant.
- **Safety finding:** the proposed rewrite removes source and relationship semantics and is not equivalent to the supplied search.
- **Demo narration:** “Never optimise by appearance—parse, compare and bounded-test both searches.”

### 04 — Raw search to `tstats`

- **Connectivity:** pass.
- **Use-case value:** useful for proposing a CIM/Data Model migration.
- **Accuracy finding:** the answer itself notes missing source details; it cannot prove CIM mapping, acceleration or field equivalence.
- **Demo narration:** “The model drafts the target shape; Splunk data-model validation proves deployment readiness.”

### 05 — JSON-to-CIM assistance

- **Connectivity:** pass.
- **Use-case value:** useful for initial field-mapping proposals.
- **Safety finding:** generated `FIELDALIAS` and `EVAL` statements need syntax, precedence, collision and sample-event validation.
- **Demo narration:** “Generate a proposal, validate it, then deploy through normal change control.”

## Publication conditions

- The captures are labelled as public laboratory/demo evidence, not product defaults or customer evidence.
- Reusable templates contain placeholders rather than the dataset-specific values visible in the captures.
- No screenshot model answer is represented as an accepted security verdict.
- Pattern B remains the repository's implemented evidence-first product.
- Pattern C remains an experimental roadmap.

