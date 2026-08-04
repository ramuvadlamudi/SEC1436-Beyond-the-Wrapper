from __future__ import annotations

from aria.copilot.contracts import (
    ConfidenceAssessment,
    ConfidenceFactor,
    FindingSynthesis,
    InvestigationPlan,
    RiskRecommendation,
    SearchExecutionRecord,
    SourceEvidenceRecord,
)
from aria.copilot.policy import risk_policy
from aria.copilot.utils import clamp_int


class EvidenceAwareRiskAgent:
    def __init__(self) -> None:
        self.policy = risk_policy()

    def recommend(
        self,
        plan: InvestigationPlan,
        sources: list[SourceEvidenceRecord],
        searches: list[SearchExecutionRecord],
        finding: FindingSynthesis,
        confidence: ConfidenceAssessment,
    ) -> RiskRecommendation:
        security_verdicts = {"SUSPICIOUS_REQUIRES_REVIEW", "LIKELY_TRUE_POSITIVE"}
        minimum_confidence = int(self.policy.get("minimum_evidence_confidence", 60))
        minimum_claims = int(self.policy.get("minimum_supporting_claims", 1))

        row_evidence_ids = {
            search.evidence_id
            for search in searches
            if search.safe and not search.execution_error and search.rows
        }
        row_linked_claims = [
            claim
            for claim in finding.supporting_claims
            if any(reference in row_evidence_ids for reference in claim.evidence_refs)
        ]
        eligible = (
            finding.verdict in security_verdicts
            and confidence.score >= minimum_confidence
            and len(row_linked_claims) >= minimum_claims
        )

        if not eligible:
            return RiskRecommendation(
                eligible=False,
                proposed_score=0,
                factors=[],
                rationale=(
                    "ARIA did not produce a risk recommendation because the evidence-linked finding, "
                    "confidence, or corroboration policy threshold was not met. Entity presence and event volume alone do not create risk."
                ),
                writeback_performed=False,
            )

        base = self.policy.get("base_factors", {})
        penalties = self.policy.get("penalties", {})
        accepted = [source for source in sources if source.accepted]
        result_sources = [search for search in searches if search.safe and not search.execution_error and search.rows]
        has_relationship = any(
            binding.role == "relationship" and binding.fields
            for source in accepted
            for binding in source.requirement_bindings
        )
        has_outcome = any(
            binding.role == "outcome" and binding.fields and any(binding.observed_samples.values())
            for source in accepted
            for binding in source.requirement_bindings
        )
        has_explicit_entity = bool(plan.explicit_entities or plan.explicit_values)
        repeated_or_concentrated = any(self._rows_show_repetition(search.rows) for search in result_sources)

        factors = [
            ConfidenceFactor(
                factor="Evidence confidence",
                points=clamp_int(confidence.score / 100 * int(base.get("evidence_confidence", 30))),
                reason=f"Evidence confidence was {confidence.score}/100.",
            ),
            ConfidenceFactor(
                factor="Cross-source corroboration",
                points=int(base.get("cross_source_corroboration", 20)) if len(result_sources) > 1 else 0,
                reason="Multiple qualified sources returned evidence." if len(result_sources) > 1 else "Only one qualified source returned evidence.",
            ),
            ConfidenceFactor(
                factor="Relationship strength",
                points=int(base.get("relationship_strength", 15)) if has_relationship else 0,
                reason="A validated relationship field contributed to the finding." if has_relationship else "No validated relationship field contributed.",
            ),
            ConfidenceFactor(
                factor="Repeated or concentrated activity",
                points=int(base.get("repeated_or_concentrated_activity", 15)) if repeated_or_concentrated else 0,
                reason="Returned aggregates showed repeated or concentrated activity." if repeated_or_concentrated else "No repeated or concentrated activity was proven by returned aggregates.",
            ),
            ConfidenceFactor(
                factor="Outcome support",
                points=int(base.get("outcome_support", 10)) if has_outcome else 0,
                reason="Observed outcome evidence was validated." if has_outcome else "No observed outcome evidence was validated.",
            ),
            ConfidenceFactor(
                factor="Analyst-supplied entity match",
                points=int(base.get("analyst_supplied_entity_match", 10)) if has_explicit_entity else 0,
                reason="The investigation was tied to an analyst-supplied value." if has_explicit_entity else "No explicit analyst-supplied entity was involved.",
            ),
        ]

        if len(result_sources) <= 1:
            factors.append(
                ConfidenceFactor(
                    factor="Single-source penalty",
                    points=-int(penalties.get("single_source_only", 10)),
                    reason="The finding was not corroborated across multiple qualified sources.",
                )
            )
        if finding.missing_evidence:
            factors.append(
                ConfidenceFactor(
                    factor="Missing evidence penalty",
                    points=-int(penalties.get("missing_required_evidence", 15)),
                    reason="Material evidence gaps remain.",
                )
            )
        if finding.contradicting_claims:
            factors.append(
                ConfidenceFactor(
                    factor="Contradicting evidence penalty",
                    points=-int(penalties.get("contradicting_evidence", 15)),
                    reason="Evidence-linked contradictions remain unresolved.",
                )
            )

        score = clamp_int(sum(factor.points for factor in factors), 0, int(self.policy.get("maximum_recommendation", 100)))
        return RiskRecommendation(
            eligible=True,
            proposed_score=score,
            factors=factors,
            rationale=(
                "This is an evidence-derived recommendation for analyst review. ARIA did not write a risk event or update entity risk."
            ),
            writeback_performed=False,
        )

    @staticmethod
    def _rows_show_repetition(rows: list[dict]) -> bool:
        for row in rows:
            for key, raw in row.items():
                name = str(key).lower()
                if "count" not in name and "events" not in name and "frequency" not in name:
                    continue
                try:
                    if float(raw) > 1:
                        return True
                except Exception:
                    continue
        return False
