# ARIA v3 Architecture

ARIA v3 is a multi-agent, air-gapped SOC copilot for Splunk Enterprise.

## Control plane

The control plane is deterministic. It classifies each request into one product capability without requiring an LLM:

1. SOC Conversation Agent
2. SPL Builder Agent
3. Investigation Agent
4. Triage Agent
5. Telemetry Inventory
6. SPL Review
7. Safety or scope boundary

The selected agent may use a local model for semantic interpretation or explanation, but a model cannot authorise Splunk access, execute a write command or override evidence policy.

Route precedence blocks write-capable actions first, preserves explicit deliverable grammar, keeps SPL Builder refinements with their parent request and distinguishes generated-SPL review from live Investigation.

## Offline Reference Knowledge

The Conversation Agent can ground named public security frameworks in curated local JSON cards. Each card carries aliases, exact phrases that must survive generation, six structured SOC sections and authoritative source URLs.

The mechanism is generic and data-driven:

- the current question is matched against card aliases;
- a referential follow-up may resolve against bounded same-agent conversation context;
- the source-attributed card is injected into the isolated local-model prompt;
- deterministic validation requires exact subject fidelity, required facts and citations;
- an invalid or timed-out grounded draft falls back to a deterministic cited rendering of the same card.

Reference cards describe public frameworks only. They do not map customer indexes, sourcetypes, fields, values or detections.

## Shared Telemetry Intelligence

All operational agents use one service for:

- live index and sourcetype catalogue discovery;
- earliest and latest event visibility;
- bounded raw source profiling;
- observed field names, population and sample values;
- semantic field-role binding using local embeddings with lexical fallback;
- source and profile caching with freshness limits;
- explicit raw-access gaps.

No customer source or field mapping is embedded in the product.

## SPL Builder Agent

The builder has two independent outputs:

### Portable generic SPL

A local model returns a semantic behaviour plan only. Deterministic code compiles the plan to portable SPL using visible placeholders for unresolved deployment values.

### Deployment-qualified SPL

ARIA queries the live catalogue for an analyst-selected time range, validates an analyst-supplied source first when present, profiles observed fields and substitutes only live deployment bindings. The final SPL is safety validated but is not executed by BUILD_SPL.

### Deterministic refinement contract

Analyst-supplied aggregation refinements are compiler inputs. ARIA extracts the
observation window, comparison operator, numeric threshold, distinct-count
concept, entity grouping and related-value grouping from the retained Builder
request. These values bypass generative interpretation and are rendered into
portable placeholders and deployment-qualified observed-field bindings.
Workflow wording is excluded from behaviour terms.

On a Builder follow-up, the parent result's live source is dynamically
revalidated first. It is a preference, not a forced constraint; a bounded set of
other live catalogue candidates may be checked if it cannot satisfy the refined
contract.

Every required aggregation measurement and grouping needs two independent
signals: local semantic similarity and deterministic lexical corroboration from
the observed field name or live sample. Required aggregation concepts are bound
before optional concepts. If every aggregation field cannot be proven, the
deployment variant abstains rather than weakening or inventing the requested
logic.

The builder distinguishes:

- `PROPOSED`
- `SOURCE_QUALIFIED`
- `SCHEMA_QUALIFIED`
- `DATA_VALIDATED`
- `RESULT_VALIDATED`

Telemetry can be schema-qualified even when no current attack event exists.

## Investigation Agent

The Investigation Agent converts a threat or entity goal into evidence requirements, discovers live candidate telemetry, validates observed fields and co-occurrence, compiles bounded read-only SPL, executes it and synthesises only evidence-linked claims.

## Triage Agent

The Triage Agent accepts a finding identifier, entity or current investigation rows. It returns:

- verdict;
- confidence from 0 to 100;
- reasoning under 50 words;
- supporting and contradicting evidence references;
- evidence gaps;
- next read-only action.

Definitive verdicts require returned evidence identifiers.

## Evidence Deliverable Agent

Detection Candidate, RBA/ERS, TDIR and SOAR requests consume the current structured result. Investigation evidence is carried through Triage and chained deliverables without parsing prior answer prose.

The agent is deterministic and performs no new Splunk query. It:

- cites carried source, query and row evidence identifiers;
- distinguishes investigation SPL from portable and deployment-qualified Builder SPL;
- preserves missing telemetry, entity and corroboration gaps;
- refuses to calculate a risk score without an eligible verdict and validated risk object;
- creates approval-gated response and rollback steps without executing them.

## Safety

The runtime does not execute destructive SPL, lookup writes, collection commands, risk or notable writeback, containment actions or SOAR playbooks. Operational material remains approval-gated.

The offline reference layer never grants Splunk execution authority. Conversation responses remain non-operational and cannot claim live customer evidence.
