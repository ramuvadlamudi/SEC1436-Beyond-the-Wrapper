# Pattern C phased experiment backlog

## Phase 0 — platform readiness

- Approve Docker, Kubernetes or OpenShift for the DSDL runtime.
- Create an internal registry or controlled offline image-import process.
- Verify DSDL, AI Toolkit and PSC version compatibility.
- Define CPU/GPU, memory, storage, queue, timeout and concurrency limits.
- Define service identities, TLS, network flows, secrets storage and audit collection.
- Build repeatable teardown and rollback procedures.

**Exit gate:** no outbound dependency, all artefacts verified, health/benchmark dashboards working and container compromise contained by design.

## Phase 1 — minimum private RAG

- Curate a small non-sensitive corpus of approved SOC runbooks and policy.
- Populate the [corpus manifest](templates/corpus_manifest.example.yaml).
- Chunk and embed with a pinned local model.
- Enforce document and chunk ACLs before retrieval.
- Produce citations containing document ID, version and chunk ID.
- Run the [evaluation cases](templates/evaluation_cases.example.jsonl).

**Exit gate:** required-answer citation precision and access-control tests pass; the system abstains when no approved evidence is retrieved.

## Phase 2 — cyber framework and detection knowledge

- Add pinned MITRE ATT&CK and ATLAS releases.
- Add approved detection metadata, dependencies and tuning decisions.
- Validate framework identifiers deterministically.
- Add stale-document and revoked-document tests.

**Exit gate:** no deprecated or unknown identifier is presented as current; every framework claim has versioned provenance.

## Phase 3 — hybrid graph retrieval

- Define canonical entity identifiers and relationship types.
- Add graph retrieval for relevant entities and attack paths.
- Preserve source-event and corpus provenance on every edge.
- Test graph poisoning, over-broad traversal and ACL leakage.

**Exit gate:** graph context improves benchmark answers without reducing provenance or access isolation.

## Phase 4 — specialist models

- Select one bounded use case such as DGA scoring or entity baselining.
- Document training data, features, label quality and expected drift.
- Compare against a deterministic or classical baseline.
- Create a model card, threshold rationale and rollback criteria.
- Shadow-test before any production alerting.

**Exit gate:** the model adds measurable value, known limitations are accepted and no model score is treated as a security verdict by itself.

## Phase 5 — ARIA integration candidate

- Expose retrieval through a bounded, typed contract.
- Add deterministic route and capability policy.
- Carry citations into the ARIA evidence state as a distinct corpus-evidence class.
- Keep Splunk rows, corpus passages and model inference separate.
- Require analyst approval before operational deliverables.

**Exit gate:** complete regression, threat-model and acceptance review. Until then, the capability remains outside ARIA RC11.

