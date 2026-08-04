# Pattern C capabilities to try next

## Priority 0 — foundations

| Capability | Experiment | Success condition |
|---|---|---|
| Offline supply chain | Import signed apps, images, models and dependencies without outbound access | Reproducible build with checksums, SBOM, licences and vulnerability results |
| Corpus governance | Ingest only approved documents with owner, classification, ACL, version and expiry | Every retrieved chunk is attributable and access-filtered |
| Evaluation harness | Run fixed positive, negative, stale, poisoned and prompt-injection cases | Automated groundedness, citation, leakage and abstention report |
| Evidence contract | Separate retrieved content, model inference and Splunk facts | Every claim identifies its evidence class or is labelled hypothesis |

## Priority 1 — private cyber RAG

### Runbook and policy copilot

Retrieve the approved procedure for an incident type, identify prerequisites and draft analyst steps. The assistant must cite the exact document version and refuse to invent missing approval steps.

### Detection knowledge assistant

Retrieve local detection descriptions, dependencies, tuning decisions, known false positives and deployment history. Use it to explain coverage or propose review candidates—not to enable searches automatically.

### ATT&CK and ATLAS grounding

Pin a local release of ATT&CK/ATLAS content and validate all IDs, names, domains, versions and deprecation status. This directly addresses the stale identifiers observed in the Pattern A screenshot.

### Incident precedent retrieval

Find approved, redacted prior cases with similar entities or behaviours. Enforce case ACLs and distinguish similarity from causal evidence.

## Priority 2 — graph and specialist analytics

### Entity and attack-path Graph RAG

Join identity, endpoint, cloud, network, vulnerability and detection relationships into an approved graph. Use graph traversal to retrieve context, while Splunk retains event-level evidence.

### DGA and DNS tunnelling models

Train or import models for domain lexical features, entropy, length, character distribution, query cadence and entity baselines. Validate on local positive and benign controls and publish drift limits.

### Behavioural anomaly models

Develop peer-group or sequence models for identity, service account, endpoint and agent-tool activity. Require explainable features and never equate anomaly with maliciousness.

### Detection tuning recommendations

Use historical result volume, analyst disposition and risk outcomes to propose threshold or suppression changes. Keep Detection Studio or the organisation's change process as the system of record.

## Priority 3 — advanced laboratory research

### Safe malware-pattern simulation

Generate behavioural descriptions, synthetic traces or benign test artefacts in a dedicated sandbox. Prohibit payload generation, live target interaction and automatic execution.

### Synthetic telemetry generation

Create privacy-safe labelled events to exercise parsers, dashboards and detection tests where real positive controls are scarce. Mark all synthetic records and keep them outside operational evidence.

### Prompt-injection and tool-call defence evaluator

Build a regression corpus for indirect prompt injection, tool argument manipulation, data exfiltration attempts and cross-agent context contamination.

### Response-playbook drafting

Retrieve local approval policy and draft zero-trust SOAR steps with preconditions, evidence requirements, rollback and explicit human gates. Do not execute playbooks from the model path.

## Promotion rule

A Pattern C experiment becomes eligible for integration only when it has an owner, threat model, controlled corpus, evaluation baseline, resource envelope, audit trail, rollback plan and operational approval. Integration does not expand RC11 authority automatically.

