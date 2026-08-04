# Pattern comparison

| Dimension | Pattern A — `| ai` | Pattern B — ARIA agents | Pattern C — DSDL/RAG |
|---|---|---|---|
| Primary goal | Fast local inference inside SPL | Evidence-first SOC copilot | Specialised private knowledge and analytics |
| Main runtime | Splunk AI Toolkit | ARIA Python services | DSDL notebooks and containers |
| Model endpoint | Local Ollama | Local Ollama chat and embeddings | Local Ollama and/or specialist models |
| Splunk interaction | Input rows are supplied by the SPL pipeline | Deterministic read-only REST search path | Search-to-container and model operationalisation |
| Evidence control | Analyst validates model output | Structured source/query/row ledger and explicit gaps | Must be designed for each experiment |
| Field/source qualification | Supplied by the authoring search | Live catalogue and observed-schema qualification | Dataset and notebook dependent |
| Generated SPL safety | Not inherently provided by the LLM response | Deterministic validator and capability contract | Must be added before execution |
| Action authority | None implied | No automatic write or containment in RC11 | None until separately designed and approved |
| Best first use | Summarisation and bounded assistance | Investigation, triage and deployable drafts | RAG, graph context and specialist models |
| Repository status | Validated demonstration guidance | Implemented RC11 product | Future experiment backlog |

## Selection guidance

- Choose Pattern A when the objective is to prove that Splunk can invoke a local model and return useful assistance quickly.
- Choose Pattern B when the task needs deterministic routing, live source qualification, safe searches, evidence continuity, abstention and approval boundaries.
- Explore Pattern C when the SOC has a curated private corpus, container governance, an evaluation programme and a specialist use case that is not well served by a general model alone.

Pattern A output must not be presented as a substitute for Pattern B evidence controls. Pattern C experiments must not be presented as RC11 product capability.

