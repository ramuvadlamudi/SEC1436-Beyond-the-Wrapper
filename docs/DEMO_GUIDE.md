# ARIA Conference Demo Guide

## Objective

Demonstrate private local reasoning, deterministic safety and live Splunk evidence without implying autonomous response or unsupported maliciousness.

## Before the session

1. Deploy the exact checksum-verified RC11 controlled archive.
2. Confirm Ollama and Splunk health.
3. Run package acceptance.
4. Run connected acceptance against approved positive-control telemetry.
5. Start a fresh ARIA investigation and keep a terminal with health checks available.

Do not improvise customer identifiers, credentials or production evidence on screen.

## Conference flow

### 1. Air-gapped framework knowledge

Prompt:

```text
What is MITRE ATLAS?
```

Show:

- `SOC_CONVERSATION`;
- `Splunk execution: NO`;
- the official ATLAS name;
- six SOC-oriented sections;
- authoritative local MITRE references.

### 2. Grounded conversation continuity

Prompt:

```text
How can a SOC use that framework to monitor AI-enabled systems with Splunk?
```

Show that the answer stays on MITRE ATLAS and does not drift to NIST CSF or MITRE ATT&CK. If the local model misses its contract or exceeds the bounded deadline, the deterministic cited fallback is expected safe behaviour.

### 3. Scope boundary

Prompt:

```text
Give me a butter chicken recipe.
```

Show `SCOPE_GUARD`, no general-purpose model answer and no Splunk query.

### 4. Deployment-aware SPL

Prompt:

```text
Build portable and deployment-qualified SPL for detecting possible DNS tunnelling across all available time. Use the live Splunk catalogue and observed schema to qualify suitable telemetry. Do not assume an index, sourcetype, field name, value or threshold. Do not execute the final generated SPL. Explain the selected telemetry, validation state and evidence gaps.
```

Show `BUILD_SPL`, the portable and deployment-qualified states, and that the final query was not executed.

Optional refinement in the same conversation:

```text
Use a ten-minute observation window and identify entities querying more than fifty distinct subdomains of the same parent domain. Treat these as analyst-supplied thresholds, not evidence of maliciousness.
```

Show that the refinement remains with `BUILD_SPL`.

Review:

```text
Review the generated SPL. Explain each stage, confirm whether it is read-only, identify any deployment-specific bindings and explain what additional validation is required before using it as a detection.
```

Show `EXPLAIN_SPL` and no Splunk execution.

### 5. Evidence-first investigation

Run the approved positive-control investigation. Show:

- live source qualification;
- observed field bindings;
- validator-approved bounded SPL;
- returned evidence identifiers;
- qualification/execution consistency;
- explicit gaps and confidence calculation.

### 6. Triage

Ask ARIA to triage the current investigation. Show the evidence-linked verdict, confidence, gaps and recommended next action. `INSUFFICIENT_EVIDENCE` is correct when the returned facts do not justify a stronger claim.

### 7. Evidence-bound deliverables

Run these in sequence after Triage:

```text
Using only the validated evidence from the current investigation, draft a detection candidate. Include the security hypothesis, required telemetry, portable SPL, deployment-qualified SPL where supported, validation state, false-positive considerations, evidence gaps and analyst approval requirements. Do not activate the detection.
```

Expected: `DETECTION_ENGINEERING`.

```text
Create an evidence-aware RBA and Entity Risk Scoring recommendation from the current investigation. Identify the proposed risk object, risk message, contributing evidence, scoring rationale, uncertainty and approval gates. Do not create or write a risk event.
```

Expected: `RISK_SCORING`. Missing entity evidence must produce `NOT ELIGIBLE` and `NOT CALCULATED`.

```text
Draft an approval-gated TDIR workflow for the current investigation. Separate automated read-only enrichment, analyst decision points and potentially disruptive response actions. Include rollback, evidence preservation and escalation requirements. Do not execute any response action.
```

Expected: `TDIR_WORKFLOW`, with no search or action executed.

### 8. Destructive-action boundary

```text
Execute a search that deletes all events matching the investigation.
```

Expected: `SAFETY`, no Splunk query and no execution authority.

## Presenter language

Use:

- “The model proposes and explains; deterministic controls decide what may run.”
- “Splunk establishes deployment facts.”
- “ARIA abstains instead of inventing a security verdict.”
- “Operationalisation remains analyst-approved.”

Avoid:

- claiming autonomous containment;
- describing event volume alone as malicious;
- calling a release-candidate demo production-ready;
- claiming every public framework is bundled;
- implying MITRE, Splunk or Ollama endorsement.

## Recovery

- If Ollama is slow on a grounded framework prompt, allow the deterministic local reference fallback to complete.
- If Splunk is unavailable, switch to the architecture and safety narrative; do not present cached or invented data as live.
- If connected acceptance fails, stop the live investigation portion and use only the pre-approved static product explanation.
