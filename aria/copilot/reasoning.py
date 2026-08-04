from __future__ import annotations

import json
from typing import Any

from aria.copilot.contracts import (
    ClaimProposal,
    ConfidenceAssessment,
    ConfidenceFactor,
    FindingSynthesis,
    InvestigationPlan,
    SearchExecutionRecord,
    SourceEvidenceRecord,
)
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import clamp_int, ratio
from aria.ollama_client import OllamaClient
from aria.suppressed_exception_logger import log_suppressed_exception


class EvidenceReasoningAgent:
    def __init__(self, ollama: OllamaClient) -> None:
        self.ollama = ollama
        self.policy = evidence_policy()

    def synthesize(
        self,
        question: str,
        plan: InvestigationPlan,
        sources: list[SourceEvidenceRecord],
        searches: list[SearchExecutionRecord],
    ) -> FindingSynthesis:
        if not bool(self.policy.get("reasoning_llm_enabled", False)):
            return self.synthesize_without_model(plan, sources, searches)

        accepted = [source for source in sources if source.accepted]
        successful = [search for search in searches if search.safe and not search.execution_error]
        evidence_ids = {source.evidence_id for source in sources}
        evidence_ids.update(search.evidence_id for search in searches)

        if not accepted:
            access_gap_sources = [
                source
                for source in sources
                if str(source.profile_error or "").startswith((
                    "CATALOG_VISIBLE",
                    "RAW_EVENTS_VISIBLE",
                ))
            ]
            if access_gap_sources:
                source_labels = ", ".join(
                    f"{source.index}/{source.sourcetype}"
                    for source in access_gap_sources[:5]
                )
                return FindingSynthesis(
                    verdict="INSUFFICIENT_EVIDENCE",
                    summary=(
                        "Live Splunk catalog evidence identified candidate source groups, "
                        "but the current search context could not retrieve the raw events "
                        "and observed fields required for evidence qualification. "
                        f"Access-limited candidates: {source_labels}."
                    ),
                    supporting_claims=[],
                    contradicting_claims=[],
                    missing_evidence=[
                        *[
                            requirement.concept
                            for requirement in plan.requirements
                            if requirement.required
                        ],
                        "Raw event and field access for the selected live source groups",
                    ],
                    next_best_query_goal=(
                        "Verify the Splunk role, search time access and raw-event visibility "
                        "for the access-limited source groups, then rerun the same investigation."
                    ),
                    analyst_guidance=[
                        "Catalog visibility proves source presence, not field-level security evidence.",
                        "Do not weaken field and co-occurrence policy to work around a Splunk access gap.",
                    ],
                )

            return FindingSynthesis(
                verdict="NO_RELEVANT_TELEMETRY",
                summary="ARIA did not find a live Splunk source that satisfied the evidence qualification policy for this analyst goal.",
                supporting_claims=[],
                contradicting_claims=[],
                missing_evidence=[
                    requirement.concept
                    for requirement in plan.requirements
                    if requirement.required
                ],
                next_best_query_goal="Refine the time range, provide an explicit entity or value, or onboard telemetry that can express the missing concepts.",
                analyst_guidance=[
                    "Review the rejected-source reasons before changing the investigation logic.",
                    "Do not operationalise a detection from unqualified telemetry.",
                ],
            )

        if not successful:
            return FindingSynthesis(
                verdict="INSUFFICIENT_EVIDENCE",
                summary="ARIA qualified at least one live source, but no safe Splunk execution completed successfully.",
                supporting_claims=[],
                contradicting_claims=[],
                missing_evidence=["Executed read-only result evidence"],
                next_best_query_goal="Resolve the search validation or execution issue and rerun the bounded investigation.",
                analyst_guidance=["Inspect the validation and execution errors shown with each generated search."],
            )

        payload = {
            "sources": [source.model_dump() for source in sources],
            "searches": [search.model_dump() for search in searches],
        }
        model_role = (
            "reasoning"
            if plan.capability
            in {
                "THREAT_ANALYSIS",
                "INVESTIGATE_ENTITY",
                "DETECTION_ENGINEERING",
                "RISK_SCORING",
                "TDIR_WORKFLOW",
                "SOAR_PLAYBOOK",
            }
            else "fast"
        )

        system = """You are ARIA's evidence reasoning agent.

You receive an analyst request, a structured plan, deterministic source-qualification records and bounded read-only Splunk results.

Rules:
- Every supporting or contradicting claim must cite one or more supplied evidence_id values.
- Do not use outside knowledge to claim that an event, field value, event ID, process, account, host, IP or destination is malicious.
- Distinguish entity presence from suspicious behaviour.
- Event volume alone is not evidence of maliciousness.
- Missing outcome, relationship or corroboration evidence must be stated.
- Use INSUFFICIENT_EVIDENCE when the returned rows do not support the requested security conclusion.
- Use NO_RELEVANT_TELEMETRY when source qualification failed.
- Use SUSPICIOUS_REQUIRES_REVIEW or LIKELY_TRUE_POSITIVE only when evidence rows and relationships support those verdicts.
- Explain contradictions and uncertainty.
- Recommend the next highest-value read-only query goal.
- Keep the response concise and analyst-oriented.
"""
        user = f"""Analyst question:
{question}

Investigation plan:
{plan.model_dump_json(indent=2)}

Evidence ledger:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Valid evidence IDs:
{sorted(evidence_ids)}

Return only the FindingSynthesis schema."""

        try:
            finding = self.ollama.structured_chat(
                system_prompt=system,
                user_prompt=user,
                response_model=FindingSynthesis,
                model_role=model_role,
                num_predict=1100,
                timeout=int(self.policy.get("reasoning_model_timeout_seconds", 90)),
            )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.reasoning.synthesis")
            finding = self.synthesize_without_model(plan, sources, searches)

        finding.supporting_claims = [
            claim
            for claim in finding.supporting_claims
            if claim.evidence_refs and all(ref in evidence_ids for ref in claim.evidence_refs)
        ]
        finding.contradicting_claims = [
            claim
            for claim in finding.contradicting_claims
            if claim.evidence_refs and all(ref in evidence_ids for ref in claim.evidence_refs)
        ]

        row_evidence_ids = {search.evidence_id for search in successful if search.rows}
        suspicious_claims_with_rows = [
            claim
            for claim in finding.supporting_claims
            if any(reference in row_evidence_ids for reference in claim.evidence_refs)
        ]
        if finding.verdict in {"SUSPICIOUS_REQUIRES_REVIEW", "LIKELY_TRUE_POSITIVE"} and not suspicious_claims_with_rows:
            finding.verdict = "INSUFFICIENT_EVIDENCE"
            finding.summary = (
                "The reasoning model did not produce a traceable claim linked to returned Splunk rows, so ARIA abstained from a suspicious verdict."
            )
            finding.missing_evidence.append(
                "A supporting security claim linked to a successful QRY evidence record with returned rows"
            )

        if all(not search.rows for search in successful):
            finding.verdict = "INSUFFICIENT_EVIDENCE"
            finding.summary = "The safe bounded searches returned no result rows for the requested scope."

        return finding

    def synthesize_without_model(
        self,
        plan: InvestigationPlan,
        sources: list[SourceEvidenceRecord],
        searches: list[SearchExecutionRecord],
    ) -> FindingSynthesis:
        """Create a conservative evidence summary without another model call."""
        accepted = [source for source in sources if source.accepted]
        successful = [search for search in searches if search.safe and not search.execution_error]
        row_searches = [search for search in successful if search.rows]
        if row_searches:
            claims = [
                ClaimProposal(
                    claim=(
                        f"Read-only search returned {len(search.rows)} bounded result row(s) "
                        f"for the qualified source {search.index}/{search.sourcetype}."
                    ),
                    evidence_refs=[search.evidence_id],
                )
                for search in row_searches
            ]
            return FindingSynthesis(
                verdict="EVIDENCE_FOUND",
                summary=(
                    "ARIA completed evidence-qualified read-only searches. The local reasoning "
                    "stage was skipped or exceeded its bounded latency budget, so ARIA preserved "
                    "the returned facts without assigning an unsupported security verdict."
                ),
                supporting_claims=claims,
                contradicting_claims=[],
                missing_evidence=["Bounded local-model interpretation of the returned evidence"],
                next_best_query_goal=(
                    "Review the returned rows and refine the security hypothesis with an explicit "
                    "entity, value or comparison objective."
                ),
                analyst_guidance=[
                    "The search results are live Splunk facts; ARIA did not infer maliciousness from volume or source presence.",
                    "Retry only the interpretation step when the local model is healthy.",
                ],
            )
        if accepted:
            return FindingSynthesis(
                verdict="INSUFFICIENT_EVIDENCE",
                summary="ARIA qualified live telemetry, but no safe bounded search returned result rows.",
                supporting_claims=[],
                contradicting_claims=[],
                missing_evidence=["Returned result rows supporting the analyst goal"],
                next_best_query_goal="Refine the time range or evidence requirements and rerun the bounded search.",
                analyst_guidance=["ARIA preserved abstention rather than inventing an interpretation."],
            )
        return FindingSynthesis(
            verdict="NO_RELEVANT_TELEMETRY",
            summary="No live source passed the evidence qualification policy within the bounded workflow.",
            supporting_claims=[],
            contradicting_claims=[],
            missing_evidence=[item.concept for item in plan.requirements if item.required],
            next_best_query_goal="Review source qualification gaps or provide an explicit entity/value.",
            analyst_guidance=["ARIA did not weaken evidence controls to meet the latency budget."],
        )

    def confidence(
        self,
        plan: InvestigationPlan,
        sources: list[SourceEvidenceRecord],
        searches: list[SearchExecutionRecord],
        finding: FindingSynthesis,
    ) -> ConfidenceAssessment:
        weights = self.policy.get("confidence_weights", {})
        penalties = self.policy.get("confidence_penalties", {})
        accepted = [source for source in sources if source.accepted]
        required_count = sum(1 for requirement in plan.requirements if requirement.required)
        supported_required = 0
        observed_bindings = 0
        total_bindings = 0
        cooccurrence_values: list[float] = []

        for source in accepted:
            for binding in source.requirement_bindings:
                total_bindings += 1
                if binding.fields and any(binding.observed_samples.values()):
                    observed_bindings += 1
                if binding.required and binding.status in {"SUPPORTED", "PARTIAL"} and binding.fields:
                    supported_required += 1
            cooccurrence_values.append(source.cooccurrence_ratio)

        required_coverage = ratio(supported_required, max(1, required_count * max(1, len(accepted))))
        field_observation = ratio(observed_bindings, total_bindings or 1)
        cooccurrence = max(cooccurrence_values, default=0.0)
        successful = [search for search in searches if search.safe and not search.execution_error]
        result_support = ratio(sum(1 for search in successful if search.rows), len(successful) or 1)
        corroboration = 1.0 if sum(1 for search in successful if search.rows) > 1 else 0.0
        traceability = 1.0 if finding.supporting_claims or finding.contradicting_claims else 0.0

        factors = [
            ConfidenceFactor(
                factor="Required concept coverage",
                points=clamp_int(required_coverage * int(weights.get("required_concept_coverage", 35))),
                reason=f"{required_coverage:.0%} of required concept bindings were supported across accepted sources.",
            ),
            ConfidenceFactor(
                factor="Observed field/value support",
                points=clamp_int(field_observation * int(weights.get("field_observation", 15))),
                reason=f"{field_observation:.0%} of bindings contained live observed values.",
            ),
            ConfidenceFactor(
                factor="Required-field co-occurrence",
                points=clamp_int(cooccurrence * int(weights.get("cooccurrence", 20))),
                reason=f"Best bounded co-occurrence ratio was {cooccurrence:.0%}.",
            ),
            ConfidenceFactor(
                factor="Executed result support",
                points=clamp_int(result_support * int(weights.get("search_result_support", 15))),
                reason=f"{sum(1 for search in successful if search.rows)} of {len(successful)} successful searches returned rows.",
            ),
            ConfidenceFactor(
                factor="Cross-source corroboration",
                points=clamp_int(corroboration * int(weights.get("cross_source_corroboration", 10))),
                reason="More than one qualified source returned evidence." if corroboration else "No cross-source corroboration was established.",
            ),
            ConfidenceFactor(
                factor="Evidence traceability",
                points=clamp_int(traceability * int(weights.get("reasoning_traceability", 5))),
                reason="Reasoning claims cite evidence ledger IDs." if traceability else "No evidence-linked claim was produced.",
            ),
        ]

        missing_required = len(
            {
                item
                for item in finding.missing_evidence
                if item
            }
        )
        if missing_required:
            factors.append(
                ConfidenceFactor(
                    factor="Missing evidence penalty",
                    points=-min(
                        30,
                        missing_required * int(penalties.get("missing_required_concept", 10)),
                    ),
                    reason=f"{missing_required} material evidence gap(s) remain.",
                )
            )
        if finding.contradicting_claims:
            factors.append(
                ConfidenceFactor(
                    factor="Contradicting evidence penalty",
                    points=-min(
                        24,
                        len(finding.contradicting_claims) * int(penalties.get("contradicting_claim", 8)),
                    ),
                    reason=f"{len(finding.contradicting_claims)} evidence-linked contradiction(s) were identified.",
                )
            )
        execution_errors = sum(1 for search in searches if search.execution_error or not search.safe)
        if execution_errors:
            factors.append(
                ConfidenceFactor(
                    factor="Execution reliability penalty",
                    points=-min(
                        30,
                        execution_errors * int(penalties.get("execution_error", 15)),
                    ),
                    reason=f"{execution_errors} search(es) failed validation or execution.",
                )
            )

        return ConfidenceAssessment(
            score=clamp_int(sum(factor.points for factor in factors)),
            factors=factors,
        )
