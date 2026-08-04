# ARIA 3.0.0-rc11 — Final Schema-Corroborated Conference Build

## RC11 false field-binding correction

- A Builder refinement now revalidates the source selected by the parent Builder result before considering unrelated live catalogue candidates.
- The retained source is a dynamic conversation preference, not a hardcoded or analyst-implied source constraint; ARIA can still reject it and inspect a bounded alternative set.
- Required aggregation measurements and groupings need deterministic lexical corroboration in an observed field name or observed sample in addition to the local embedding score.
- The exact reported mappings `subdomains → bytes`, `entities → protocol` and `parent domain → dst_ip` are release-blocking negative regressions and cannot schema-qualify even under artificially perfect embedding similarity.
- Required aggregation concepts are bound before optional activity/context concepts so optional fields cannot consume the only defensible measurement or grouping field.
- When no candidate corroborates the complete aggregation contract, ARIA returns `NO_SCHEMA_QUALIFIED_SPL`, preserves the correct portable SPL and offers no deployment-execution action.
- Valid lexically corroborated observed fields still produce safety-validated deployment SPL. No customer-specific field mapping was added.

## RC11 release boundary

RC11 supersedes RC10 and is the final conference candidate. RC10 remains a
historical checkpoint but must not be submitted because it could label
embedding-only aggregation mappings as schema-qualified.

# ARIA 3.0.0-rc10 — Locked Conference Build

## RC10 deterministic SPL refinement correction

- The exact final UI smoke-test exchange is now a release-blocking semantic regression, not only a routing regression.
- Builder follow-ups deterministically extract analyst-supplied observation windows, comparison operators, numeric thresholds, distinct-count concepts, entity grouping and related-value grouping.
- The reported refinement now compiles a ten-minute bucket, distinct-count aggregation, entity and parent grouping, and the analyst-supplied `> 50` condition in both portable and schema-qualified SPL.
- Number words such as `ten` and `fifty` are parsed without asking a local model to preserve them.
- Workflow language such as `portable`, `deployment-qualified`, `detecting`, `use`, `validation` and `execute` is removed from the semantic request or rejected before deterministic SPL compilation.
- Aggregation-specific deployment SPL is emitted only when every required aggregation field is bound to a populated, observed field; otherwise ARIA keeps the portable placeholders and reports the schema gap.
- BUILD_SPL still never executes the generated query, and the refinement is explicitly labelled as analyst-supplied logic rather than evidence of maliciousness.

## RC10 release boundary

RC10 supersedes RC9 and is the locked conference candidate. Do not deploy or
publish RC9 after this patch. Package acceptance and the exact UI regression
must pass before packaging; connected Splunk/Ollama acceptance remains required
on the Agentic server.

# ARIA 3.0.0-rc9 — Final Conference Routing and Deliverable Fix

## RC9 deterministic demo-flow correction

- Every misrouted prompt from the 30 July UI acceptance transcript is now a release-blocking regression.
- Extended wording such as `Build portable and deployment-qualified SPL ...` routes to the SPL Builder before Inventory grammar is considered.
- Analyst-supplied window and threshold refinements remain with the current SPL Builder request and retain the parent intent.
- `Review the generated SPL ...` resolves the current deployment-qualified or evidence SPL and routes to the SPL Review Agent without executing Splunk.
- Destructive requests such as deleting matching events route immediately to Safety and cannot grant search authority.
- Detection Candidate, RBA/ERS, TDIR and SOAR requests now route to a deterministic Evidence Deliverable Agent rather than falling into Conversation, Investigation or the generic Safety explanation.
- Investigation evidence is carried through Triage and chained deliverables as structured context. Deliverables run no new Splunk search and execute no action.
- An unresolved risk object or ineligible verdict produces `NOT ELIGIBLE` and `NOT CALCULATED`; no model may invent a risk score.
- The UI now describes the actual deterministic ARIA v3 control plane rather than an obsolete local intent-model route.
- RC9 contains the RC8 authoritative MITRE ATLAS grounding and all prior evidence-continuity and isolation fixes. Deploy RC9 directly.

## RC9 release boundary

RC9 is the final conference submission candidate. Package acceptance and the exact deterministic demo-flow gate must pass before packaging. The connected Splunk gate and UI smoke test remain required on the Agentic server.

## RC8 authoritative offline framework grounding

- Curated public security-framework facts now live in generic, source-attributed JSON reference cards rather than topic-specific Python branches.
- MITRE ATLAS answers preserve the official name, remain on ATLAS through referential follow-ups and include bundled authoritative MITRE citations.
- A grounded question receives one bounded fast-model attempt. If the model times out, drifts to an adjacent framework or omits a required citation, ARIA immediately returns a deterministic six-section cited answer from the same local reference card.
- The exact failed follow-up, `How can a SOC use that framework to monitor AI-enabled systems with Splunk?`, is now a release-blocking regression and connected-acceptance step.
- Grounding remains fully air-gapped at runtime. Adding another supported public framework is a data-only card addition with validation tests; no customer index, sourcetype, field or use-case mapping is introduced.
- A separate sanitized GitHub source bundle, public documentation set and publication audit are now part of package acceptance.
- RC8 contains all RC7 named-concept fidelity, RC6 conversation isolation and RC5 evidence-continuity corrections. Deploy RC8 directly.

## Release boundary

RC8 is a controlled-preview conference demo and public-source candidate. Connected target acceptance is still required before the conference demo, and organisational IP, licensing and trademark approval is required before publishing the source bundle to a public GitHub repository.

## RC7 named-concept fidelity and depth correction

- Named frameworks and acronyms are extracted from the current analyst message and carried into the local-model prompt as mandatory subject anchors.
- Deep framework requests use the configured local reasoning-model role and a structured response contract covering exact definition, scope, adjacent concepts, SOC use, Splunk application, limitations and validation.
- The first definition must name every required subject anchor. An answer that substitutes a related framework is rejected even if it mentions the requested subject later.
- Deep framework answers must contain every required section and at least 260 words; shallow or generic drafts receive one bounded repair and otherwise fail closed.
- The current analyst question remains the final model instruction on both the initial and repair attempts.
- Connected acceptance now uses the named-framework regression prompt after Investigation and Triage and blocks release unless subject fidelity, useful depth, response isolation and zero Splunk execution all pass.
- RC7 contains the complete RC6 Conversation isolation fix and RC5 field-level evidence consistency fix. Deploy RC7 directly; RC5 and RC6 are not prerequisites.

## RC6 consolidated four-agent release

- Standalone SOC concept questions are now isolated from prior Investigation, Triage and SPL Builder response text.
- Referential follow-ups receive only bounded same-agent conversational context, with the current analyst question always placed last in the local-model prompt.
- A deterministic Conversation response contract blocks operational agent headers, live-execution claims, verdicts, evidence-confidence claims, customer-specific SPL and answers that ignore the current topic.
- One bounded clean-context repair is permitted after a rejected draft; a second invalid draft fails closed and is never shown to the analyst.
- Connected acceptance now recreates the reported failure by asking a standalone SOC question after live Investigation and Triage responses, and blocks release if operational content leaks, Splunk is queried, the current topic is missed or the local model does not return a contract-valid answer.
- RC6 includes the complete RC5 field-level qualification/execution consistency fix and supersedes RC5. Deploy RC6 directly; RC5 is not a prerequisite.

## RC5 field-level evidence consistency fix

- Bounded co-occurrence and investigation execution now use the same `head → extract → spath` enrichment sequence.
- Execution records presence for every required bound field and the count of events where the complete required field set co-occurs.
- Positive source event volume can no longer conceal an unpopulated required field.
- Qualification/execution consistency fails unless event count, every required field and the fully-bound event count are all positive.
- Connected acceptance now blocks empty required fields and missing fully-bound execution evidence.
- Triage excludes inconsistent execution rows and deterministically removes unsupported “unusual volume” reasoning when no behaviour-specific values exist.
- RC5 supersedes RC4. RC4 preserved result rows but checked only event-count continuity, allowing `event_count>0` with a required-field distinct count of zero to report a false consistency pass.

## RC4 live-evidence continuity fix

- Investigation execution now produces a row-preserving evidence summary instead of relying on `stats ... by` grouping that can silently discard all events.
- Every investigation aggregation is input-bounded before `stats`, so “bounded” applies to work performed as well as rows displayed.
- Runtime records the number of bounded events represented and fails closed when source qualification observed events but execution cannot reproduce a positive count.
- Triage now preserves returned-row evidence identifiers and cannot report zero confidence when bounded investigation evidence is present.
- Connected acceptance now fails when investigation searches return no rows, represent no live events, contradict source qualification, or fail to carry evidence into Triage.
- RC4 superseded RC3 for field release. RC3’s connected gate could pass on safe execution alone even when no evidence rows survived.

## RC3 evidence-execution hotfix

- Deterministic investigation searches now group by the required fields that passed live qualification and required-field co-occurrence.
- Optional context fields can no longer silently suppress every `stats ... by` result when those fields are null in the qualified events.
- A scenario-agnostic regression test proves that compiled execution SPL excludes optional fields that were not part of required-field co-occurrence.
- RC3 superseded RC2 for connected acceptance.

## RC2 acceptance hotfix

- A negated instruction such as `do not execute the final SPL` can no longer grant search-execution authority.
- Operational investigation prompts that require `safe read-only SPL` remain routed to the Investigation Agent instead of the Safety explanation capability.
- The exact connected-acceptance prompts that exposed both defects are now deterministic router regression tests.
- The release builder no longer emits a falsely labelled SEC1436 replication kit when the Splunk-side `aria_local_llm` app source is absent.
- RC2 supersedes RC1 for connected acceptance. Do not reuse the RC1 archive or checksum after applying this hotfix.

ARIA v3 replaces the single universal workflow with four isolated agents sharing a common telemetry-intelligence service.

## Major changes

- Deterministic, model-independent product routing.
- Dedicated SOC Conversation Agent.
- Rebuilt SPL Builder based on LLM semantic intent and deterministic compilation.
- Explicit separation of portable SPL and deployment-qualified SPL.
- Analyst-supplied index and sourcetype constraints are validated first.
- Schema qualification no longer requires the attack to be present in current events.
- Dedicated Investigation Agent using the validated evidence-first execution service.
- New Triage Agent with an evidence-reference contract.
- Shared live telemetry cache reduces repeated catalogue and source profiling.
- Agent failures are isolated.
- Transactional compile-first installer with automatic rollback.

## Release boundary

This package is a controlled-preview release candidate. It becomes eligible for field release only after the connected four-agent acceptance script and final acceptance suite pass in the target Splunk deployment.
