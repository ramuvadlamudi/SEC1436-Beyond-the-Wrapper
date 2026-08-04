# SEC1436 three-pattern demo runbook

## Demonstration objective

Show a progression from private inference to defensible agentic workflows and then to future specialist capability:

1. **Pattern A:** a local Ollama model can assist directly in a Splunk search.
2. **Pattern B:** ARIA separates reasoning from evidence and applies deterministic controls.
3. **Pattern C:** DSDL/private RAG can add specialised local knowledge and models when governance and container prerequisites exist.

## Pre-demo checks

- Pattern A Ollama connection test passes with a non-sensitive generated row.
- Pattern A query is bounded before `| ai` and model is warm.
- ARIA `aria_health.py` passes and the RC11 UI is reachable.
- Splunk credentials used by ARIA are read-only.
- The target investigation has approved positive-control telemetry.
- No Pattern C live service is implied; show the architecture and experiment backlog only.
- Screenshots are available as a fallback for every live step.

## Theatre flow

### Act 1 — Pattern A: prove the private connection

Use one approved bounded search and show an `ai_result_*` field returning from local Ollama.

Recommended narration:

> “This is the fastest path: selected Splunk rows go to a model that stays inside the enclave. But the answer is assistance, not evidence. The model can be stale, lose SPL semantics or invent a mapping.”

Show the event-to-MITRE screenshot and point out that the response contains outdated/incorrect identifiers. Then show the validation report.

### Act 2 — Pattern B: make the workflow defensible

Run the validated RC11 path:

1. `What is MITRE ATLAS?`
2. `How can a SOC use that framework to monitor AI-enabled systems with Splunk?`
3. Build portable and deployment-qualified SPL using the exact prompt in `RC11_DEMO_PROMPTS.txt`.
4. Investigate the approved scenario using live read-only evidence.
5. Triage the current structured investigation.
6. Draft a Detection Candidate, RBA/ERS recommendation and approval-gated TDIR workflow.

Point to:

- deterministic route;
- local Ollama reasoning path;
- separate Splunk evidence path;
- source and query identifiers;
- returned rows, evidence gaps and confidence factors;
- safe abstention when telemetry cannot prove the request;
- human approval before any operationalisation.

Recommended narration:

> “The LLM proposes. Splunk proves. Deterministic services enforce. Analysts approve.”

### Act 3 — Pattern C: show the next horizon

Open the Pattern C capability backlog. Highlight:

- private RAG over runbooks, incidents, detections and policy;
- pinned ATT&CK/ATLAS grounding;
- hybrid vector and graph context;
- DGA/DNS and behavioural specialist models;
- evaluation, model cards, drift and rollback.

State clearly that Pattern C is not in RC11 and requires an approved DSDL container environment.

## Close

> “Start with Pattern A when you need a quick private-inference win. Download Pattern B when you need evidence-first agentic workflows. Use Pattern C as the governed roadmap for your own specialist cyber intelligence.”

## Failure-safe presentation

| Failure | Presenter action |
|---|---|
| Local model timeout | Show the saved screenshot and explain bounded failure behaviour |
| Pattern A inaccurate answer | Use it to explain the validation boundary; do not correct it silently |
| No Splunk result | Show ARIA abstention and evidence gaps as the intended safety outcome |
| No schema-qualified SPL | Show portable SPL placeholders and explain why ARIA refused invented fields |
| Pattern C infrastructure absent | Expected; present architecture and backlog only |

