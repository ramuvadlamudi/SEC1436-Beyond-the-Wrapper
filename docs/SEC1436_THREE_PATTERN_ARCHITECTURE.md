# SEC1436 three-pattern architecture

## Purpose

The three patterns show a progressive architecture for private AI in a Splunk SOC. All services remain inside an approved trust boundary. Splunk remains the evidence system of record and no cloud model is required.

```mermaid
flowchart TD
  Analyst[Analyst]
  Splunk[Splunk Enterprise / ES]
  Ollama[Local Ollama]
  A[Pattern A\nAI Toolkit and ai command]
  B[Pattern B\nARIA deterministic agent control plane]
  C[Pattern C\nDSDL and private cyber RAG]
  Stores[Approved private corpus\nvector and graph stores]

  Analyst --> A
  Analyst --> B
  A <--> Splunk
  A <--> Ollama
  B <--> Splunk
  B <--> Ollama
  C <--> Splunk
  C <--> Ollama
  C <--> Stores
```

These are parallel patterns within the same enclave. Pattern C is not in the RC11 runtime path, and Pattern A does not call Pattern B automatically.

## Pattern A — inference in the SPL pipeline

```mermaid
sequenceDiagram
  participant A as Analyst
  participant S as Splunk search
  participant T as AI Toolkit
  participant O as Local Ollama

  A->>S: Run bounded read-only search
  S->>T: Selected rows and prompt
  T->>O: Local inference request
  O-->>T: Untrusted model output
  T-->>S: ai_result field
  S-->>A: Review result and validate
```

Pattern A is the fastest route to value. It is suitable for summarisation, explanation and proposal generation over small, explicitly selected inputs. The `ai_result` field is not evidence, a validated ATT&CK mapping or deployment-safe SPL until an analyst or additional control validates it.

## Pattern B — agentic evidence control plane

```mermaid
flowchart TD
  Goal[Analyst goal]
  Router[Deterministic router]
  Agent[Bounded specialist agent]
  Reasoning[Local Ollama reasoning]
  Control[Catalogue, schema binding, SPL compiler and safety gate]
  Evidence[Splunk read-only evidence]
  Ledger[Evidence ledger]
  Decision[Qualified answer, gap or abstention]

  Goal --> Router
  Router --> Agent
  Agent <--> Reasoning
  Agent --> Control
  Control <--> Evidence
  Control --> Ledger
  Reasoning --> Ledger
  Ledger --> Decision
```

Pattern B separates model reasoning from deployment facts. The model has no Splunk credentials or operational write authority. Detection, RBA/ERS, TDIR and SOAR outputs remain approval-gated drafts.

## Pattern C — specialised retrieval and model lifecycle

```mermaid
flowchart TD
  Question[Specialist cyber question]
  Access[Authorisation and corpus filter]
  Retrieve[Hybrid retrieval\nvector plus graph]
  Corpus[Runbooks, incidents, detections, policy and frameworks]
  Model[Local LLM or specialist model]
  Evaluate[Citation, groundedness, leakage and quality gates]
  Output[Grounded draft or abstention]

  Question --> Access
  Access --> Retrieve
  Retrieve <--> Corpus
  Retrieve --> Model
  Model --> Evaluate
  Evaluate --> Output
```

DSDL supplies containerised custom-model and notebook workflows. A future ARIA integration would still need deterministic corpus access, provenance, evaluation and approval controls. Vector similarity alone is not an evidence decision.

## Trust boundaries

| Boundary | Required control |
|---|---|
| Air-gap boundary | Pre-stage approved packages, models and container images; no hidden outbound dependency |
| Splunk boundary | Least-privilege identities, bounded searches and explicit command capabilities |
| Model boundary | Treat all model output as untrusted; no credentials or direct action authority |
| Data boundary | Minimise fields and rows; apply classification, retention and corpus ACLs |
| Evidence boundary | Cite returned Splunk rows or approved corpus chunks; keep gaps explicit |
| Operational boundary | Human approval before detection promotion, risk/notable writes or response actions |
| Supply-chain boundary | Verify checksums, licences, SBOMs and vulnerability scans before importing artefacts |

## Reference deployment

The demonstrated environment uses separate Splunk, agentic and Ollama servers. Pattern A runs from the Splunk search tier to Ollama. Pattern B runs on the agentic server and connects independently to Splunk and Ollama. Pattern C requires an approved DSDL container environment and private retrieval stores; it is not assumed to be present in the current no-container RC11 deployment.

