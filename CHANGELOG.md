# Changelog

All notable public changes to ARIA Pattern B are documented here.

## SEC1436 publication expansion — 2026-08-04

### Added

- Pattern A guidance for Splunk AI Toolkit `| ai` inference to local Ollama.
- Validation assessment and screenshots for MITRE mapping, coverage-gap hypotheses, SPL optimisation, raw-to-`tstats` conversion and JSON-to-CIM mapping.
- Pattern C DSDL/private cyber RAG architecture, experiment roadmap, security evaluation and governance templates.
- Cross-pattern architecture and selection guidance for the SEC1436 repository.

### Boundary

- ARIA Pattern B runtime code and v3.0.0-rc11 authority are unchanged.
- Pattern A model output remains untrusted analyst assistance.
- Pattern C remains experimental and is not an implemented RC11 capability.

## 3.0.0-rc11 — 2026-07-30

### Added

- Deterministic route precedence for Identity, Inventory, SOC Conversation, SPL Builder, SPL Review, Investigation, Triage, Detection Candidate, RBA/ERS, TDIR, SOAR, Safety and Scope Guard.
- Evidence Deliverable Agent with structured Investigation-to-Triage-to-deliverable continuity.
- Source-attributed offline reference grounding with deterministic cited fallback.
- Analyst-supplied SPL refinement contract for windows, thresholds, metrics and grouping concepts.
- Parent Builder source revalidation and required-field lexical corroboration.
- Row-preserving investigation summaries and qualification/execution consistency checks.
- GitHub source sanitization and release-blocking publication audit.

### Safety

- BUILD_SPL does not execute final generated SPL.
- All executable investigation searches remain bounded and read-only.
- Missing evidence or field corroboration produces abstention rather than invented deployment logic.
- Risk scores are not calculated without eligible evidence and a validated risk object.
- Detection, notable, risk, containment and SOAR actions are not activated by RC11.

### Status

Controlled-preview release candidate for approved demonstrations, laboratories and read-only pilots.
