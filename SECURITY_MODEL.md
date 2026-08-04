# ARIA v3 Security Model

ARIA v3 assumes that analyst prompts, local-model output, Splunk event content and discovered metadata can all be incomplete or adversarial. Trust is established through deterministic policy and returned evidence, not model confidence.

## Trust boundaries

- **Deterministic control plane:** routing, scope, execution permission and safety decisions do not depend on a generative model.
- **Local inference:** LLMs interpret intent, explain results and propose semantic plans. They cannot grant themselves additional tools or permissions.
- **Telemetry Intelligence:** deployment facts come from live Splunk catalogue and bounded raw-profile queries. Cached profiles expire according to policy.
- **SPL safety:** every executable query passes the policy-backed static validator. Write, collection, alerting and destructive commands are blocked.
- **Evidence:** investigation and triage claims must reference returned search rows or be labelled as hypotheses/gaps.
- **Human governance:** operational detections, risk changes and response actions require analyst approval outside the read-only product path.

## Agent contracts

### SOC Conversation Agent

Does not query Splunk unless the request is explicitly redirected to a live-data capability. Model unavailability produces a bounded fallback or an explicit unavailable response.

### SPL Builder Agent

Produces two artefacts:

1. **Portable SPL** compiled from a model-generated semantic intent and visible placeholders.
2. **Deployment-qualified SPL** compiled from analyst constraints, live catalogue sources and observed fields.

`SCHEMA_QUALIFIED` means the deployment can express the search. It does not claim that matching attack activity exists. BUILD_SPL never executes the final query.

### Investigation Agent

Transforms a hypothesis into evidence requirements, source qualification, safe bounded searches, returned rows, confidence and gaps. It may abstain when telemetry cannot prove the requested relationship.

### Triage Agent

Uses an analyst-supplied finding/incident reference or prior investigation rows. Definitive verdicts require evidence references. Event volume, entity presence or model opinion alone cannot produce a true-positive conclusion.

## Prohibited runtime hardcoding

ARIA must not embed customer-specific:

- indexes, sourcetypes or sources;
- field names or field aliases;
- event IDs, vendors or products;
- users, hosts, IP addresses or other entities;
- thresholds, time windows, confidence scores or risk scores;
- BOTSv3 or demonstration assumptions.

Generic cybersecurity roles, SPL grammar, evidence states, read-only policy and triage verdict schemas are product logic rather than customer hardcoding.

## Failure behaviour

- A failed agent is isolated and reported as `COPILOT_ERROR`; other agents remain available.
- A model timeout does not grant fallback access or weaken evidence requirements.
- A failed deployment automatically restores the prior complete runtime.
- Unsupported evidence results in abstention or explicit gaps, never fabricated findings.
