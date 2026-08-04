# Pattern C security and evaluation

## Threat model

| Risk | Required control |
|---|---|
| Corpus poisoning | Approved sources, signed ingestion manifest, owner review and version pinning |
| Indirect prompt injection | Treat document text as data; isolate instructions; adversarial retrieval tests |
| ACL leakage | Authorisation filter before retrieval, not after model generation |
| Stale knowledge | Effective/expiry dates, revocation, re-index process and version citations |
| Hallucinated citations | Resolve citation IDs against the retrieval ledger before rendering |
| Embedding leakage | Classification-aware stores, encryption, access logging and deletion testing |
| Graph overreach | Typed relationships, bounded traversal, provenance and per-edge ACLs |
| Model or image compromise | Checksum, signature, SBOM, scan, isolated runtime and egress denial |
| Tool-call abuse | Typed allowlisted tools, argument validation and no write tools in the research profile |
| Sensitive output | Output policy, redaction, least-context prompting and analyst review |

## Evidence classes

Never collapse these into one confidence score without an explicit policy:

1. **Splunk evidence** — returned rows from approved bounded searches.
2. **Corpus evidence** — versioned chunks retrieved from approved documents.
3. **Model inference** — interpretation or hypothesis generated from evidence.
4. **Analyst assertion** — values or constraints supplied by an authorised user.

A final response must identify the class behind each material claim and abstain when required evidence is missing.

## Evaluation dimensions

| Dimension | Example measure |
|---|---|
| Retrieval | Recall@k and precision@k on a labelled question set |
| Citation | Percentage of claims supported by the cited chunk |
| Groundedness | Unsupported material claims per answer |
| Framework accuracy | Valid ID/name/version/deprecation pairs |
| Abstention | Refusal rate when no authorised evidence is present |
| Access control | Cross-role leakage tests passed |
| Robustness | Prompt-injection and poisoned-document attack success rate |
| Safety | Prohibited tool/action requests blocked |
| Performance | p50/p95 latency, queue depth, timeout and resource saturation |
| Operations | Drift detection, rollback time and audit completeness |

## Minimum evaluation set

- answerable questions with one authoritative document;
- questions requiring multiple documents;
- unanswerable and out-of-scope questions;
- conflicting, superseded and revoked documents;
- documents containing malicious instructions;
- users with different corpus permissions;
- framework identifiers that are valid, deprecated and fabricated;
- Splunk evidence that supports, contradicts or does not address retrieved guidance;
- Ollama or store outage and timeout cases.

Use the example evaluation file as a schema seed, then replace its illustrative cases with organisation-approved content.

