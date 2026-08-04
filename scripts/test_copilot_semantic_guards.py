from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("OLLAMA_FAST_MODEL", "test-fast")
os.environ.setdefault("OLLAMA_REASONING_MODEL", "test-reasoning")
os.environ.setdefault("OLLAMA_EMBEDDING_MODEL", "test-embedding")
os.environ.setdefault("SPLUNK_URL", "https://127.0.0.1:8089")
os.environ.setdefault("SPLUNK_USERNAME", "test")
os.environ.setdefault("SPLUNK_PASSWORD", "test")
os.environ.setdefault("SPLUNK_VERIFY_SSL", "false")
os.environ.setdefault("TELEMETRY_DB_PATH", str(ROOT / "data" / "test-telemetry.db"))

from aria.copilot.contracts import (  # noqa: E402
    ClaimProposal,
    ConfidenceAssessment,
    EvidenceRequirement,
    FindingSynthesis,
    InvestigationPlan,
    RequirementBindingRecord,
    RequirementFieldProposal,
    RiskRecommendation,
    SourceEvidenceRecord,
    SourceProfileRecord,
    SourceQualificationProposal,
    SourceQualificationSet,
)
from aria.copilot.evidence_qualifier import DeterministicEvidenceQualifier  # noqa: E402
from aria.copilot.reasoning import EvidenceReasoningAgent  # noqa: E402
from aria.copilot.risk_agent import EvidenceAwareRiskAgent  # noqa: E402
from aria.copilot.spl_agent import EvidenceBoundSPLAgent  # noqa: E402
from aria.spl_validator import StaticSPLValidator  # noqa: E402


class ProbeReturnsNoCooccurrence:
    def cooccurrence_probe(self, **kwargs):
        return {"sampled_events": 20, "fully_bound_events": 0, "field_presence": {}}


class EvidenceSummarySplunk:
    def __init__(self, event_count: int, field_presence: int | None = None) -> None:
        self.event_count = event_count
        self.field_presence = event_count if field_presence is None else field_presence

    def search(self, spl):
        present = self.field_presence
        return [
            {
                "event_count": str(self.event_count),
                "aria_required_signal_distinct": "3",
                "aria_required_signal_values": ["x", "y"],
                "aria_required_1_present": str(present),
                "aria_required_all_present": str(present),
            }
        ]




class SourceOnlySuspicionModel:
    def structured_chat(self, *, response_model, **kwargs):
        return FindingSynthesis(
            verdict="SUSPICIOUS_REQUIRES_REVIEW",
            summary="Suspicion linked only to source qualification.",
            supporting_claims=[ClaimProposal(claim="Source exists", evidence_refs=["SRC-1"])],
            contradicting_claims=[],
            missing_evidence=[],
            next_best_query_goal="Collect behavioural rows",
        )

class UnreferencedSuspicionModel:
    def structured_chat(self, *, response_model, **kwargs):
        return FindingSynthesis(
            verdict="SUSPICIOUS_REQUIRES_REVIEW",
            summary="Suspicion without traceable evidence.",
            supporting_claims=[ClaimProposal(claim="Unsupported suspicion", evidence_refs=[])],
            contradicting_claims=[],
            missing_evidence=[],
            next_best_query_goal="Collect more evidence",
        )


def main() -> int:
    failures: list[str] = []

    plan = InvestigationPlan(
        capability="QUERY_SPLUNK",
        goal="Test generic evidence relationship",
        requirements=[
            EvidenceRequirement(requirement_id="R1", concept="actor", role="entity", required=True, reason="actor"),
            EvidenceRequirement(requirement_id="R2", concept="activity", role="activity", required=True, reason="activity"),
        ],
    )
    profile = SourceProfileRecord(
        candidate_id="C1",
        index="live_index",
        sourcetype="live_source",
        event_count=20,
        fields=[
            {"name": "actor_key", "count": 20, "distinct_count": 2, "sample_values": ["a", "b"]},
            {"name": "activity_key", "count": 20, "distinct_count": 3, "sample_values": ["x", "y"]},
        ],
    )
    proposals = SourceQualificationSet(
        sources=[
            SourceQualificationProposal(
                candidate_id="C1",
                suitability="HIGH",
                requirement_mappings=[
                    RequirementFieldProposal(requirement_id="R1", status="SUPPORTED", fields=["actor_key"], rationale="observed"),
                    RequirementFieldProposal(requirement_id="R2", status="SUPPORTED", fields=["activity_key"], rationale="observed"),
                ],
                source_reasoning="proposed",
            )
        ]
    )
    qualifier = DeterministicEvidenceQualifier(ProbeReturnsNoCooccurrence())
    source_records = qualifier.qualify(plan, [profile], proposals)
    if source_records[0].accepted:
        failures.append("source without required-field co-occurrence was accepted")

    single_requirement_plan = InvestigationPlan(
        capability="QUERY_SPLUNK",
        goal="Test single required field presence",
        requirements=[
            EvidenceRequirement(
                requirement_id="R1",
                concept="activity",
                role="activity",
                required=True,
                reason="activity",
            )
        ],
    )
    single_requirement_proposals = SourceQualificationSet(
        sources=[
            SourceQualificationProposal(
                candidate_id="C1",
                suitability="HIGH",
                requirement_mappings=[
                    RequirementFieldProposal(
                        requirement_id="R1",
                        status="SUPPORTED",
                        fields=["activity_key"],
                        rationale="observed",
                    )
                ],
                source_reasoning="proposed",
            )
        ]
    )
    single_requirement_records = qualifier.qualify(
        single_requirement_plan,
        [profile],
        single_requirement_proposals,
    )
    if single_requirement_records[0].accepted:
        failures.append(
            "single required field without bounded presence was accepted"
        )

    risk_agent = EvidenceAwareRiskAgent()
    entity_presence_finding = FindingSynthesis(
        verdict="EVIDENCE_FOUND",
        summary="Entity exists in telemetry.",
        supporting_claims=[ClaimProposal(claim="Entity presence", evidence_refs=["SRC-1"])],
        contradicting_claims=[],
        missing_evidence=[],
        next_best_query_goal="Investigate behaviour",
    )
    risk = risk_agent.recommend(
        plan,
        [
            SourceEvidenceRecord(
                evidence_id="SRC-1",
                candidate_id="C1",
                index="live_index",
                sourcetype="live_source",
                suitability="HIGH",
                score=90,
                accepted=True,
                sampled_events=100000,
                fully_bound_events=100000,
                cooccurrence_ratio=1.0,
            )
        ],
        [],
        entity_presence_finding,
        ConfidenceAssessment(score=95, factors=[]),
    )
    if risk.eligible or risk.proposed_score != 0:
        failures.append("entity presence or event volume created a risk recommendation")

    reasoning = EvidenceReasoningAgent(UnreferencedSuspicionModel())
    reasoning.policy["reasoning_llm_enabled"] = True
    accepted_source = SourceEvidenceRecord(
        evidence_id="SRC-1",
        candidate_id="C1",
        index="live_index",
        sourcetype="live_source",
        suitability="HIGH",
        score=80,
        accepted=True,
        sampled_events=20,
        fully_bound_events=10,
        cooccurrence_ratio=0.5,
    )
    from aria.copilot.contracts import SearchExecutionRecord
    search = SearchExecutionRecord(
        evidence_id="QRY-1",
        candidate_id="C1",
        index="live_index",
        sourcetype="live_source",
        purpose="bounded test",
        spl="search index=\"live_index\" | stats count",
        safe=True,
        rows=[{"event_count": "2"}],
    )
    finding = reasoning.synthesize("test", plan, [accepted_source], [search])
    if finding.verdict != "INSUFFICIENT_EVIDENCE":
        failures.append("unreferenced suspicious claim was not downgraded")

    source_only_reasoning = EvidenceReasoningAgent(SourceOnlySuspicionModel())
    source_only_reasoning.policy["reasoning_llm_enabled"] = True
    source_only_finding = source_only_reasoning.synthesize("test", plan, [accepted_source], [search])
    if source_only_finding.verdict != "INSUFFICIENT_EVIDENCE":
        failures.append("source-only suspicious claim was not downgraded")

    source_only_risk = risk_agent.recommend(
        plan,
        [accepted_source],
        [search],
        FindingSynthesis(
            verdict="SUSPICIOUS_REQUIRES_REVIEW",
            summary="Source-only claim",
            supporting_claims=[ClaimProposal(claim="Source exists", evidence_refs=["SRC-1"])],
            contradicting_claims=[],
            missing_evidence=[],
            next_best_query_goal="Collect behavioural evidence",
        ),
        ConfidenceAssessment(score=95, factors=[]),
    )
    if source_only_risk.eligible or source_only_risk.proposed_score != 0:
        failures.append("source-only claim created a risk recommendation")

    execution_profile = SourceProfileRecord(
        candidate_id="C2",
        index="live_execution_index",
        sourcetype="live_execution_source",
        event_count=25,
        fields=[
            {"name": "required_signal", "count": 25, "distinct_count": 3, "sample_values": ["x"]},
            {"name": "optional_context", "count": 5, "distinct_count": 2, "sample_values": ["y"]},
        ],
    )
    execution_source = SourceEvidenceRecord(
        evidence_id="SRC-2",
        candidate_id="C2",
        index=execution_profile.index,
        sourcetype=execution_profile.sourcetype,
        suitability="HIGH",
        score=80,
        accepted=True,
        requirement_bindings=[
            RequirementBindingRecord(
                requirement_id="R1",
                concept="required activity",
                role="activity",
                required=True,
                status="SUPPORTED",
                fields=["required_signal"],
                observed_samples={"required_signal": ["x"]},
                rationale="Required field validated by the live profile.",
            ),
            RequirementBindingRecord(
                requirement_id="R2",
                concept="optional context",
                role="entity",
                required=False,
                status="SUPPORTED",
                fields=["optional_context"],
                observed_samples={"optional_context": ["y"]},
                rationale="Optional field was observed but not part of required co-occurrence.",
            ),
        ],
        sampled_events=25,
        fully_bound_events=25,
        cooccurrence_ratio=1.0,
    )
    execution_plan = InvestigationPlan(
        capability="QUERY_SPLUNK",
        goal="Test qualification-aligned execution",
        earliest="0",
        latest="now",
        time_range_explicit=True,
        execute_read_only_search=True,
        requirements=[
            EvidenceRequirement(
                requirement_id="R1",
                concept="required activity",
                role="activity",
                required=True,
                reason="required",
            ),
            EvidenceRequirement(
                requirement_id="R2",
                concept="optional context",
                role="entity",
                required=False,
                reason="optional",
            ),
        ],
    )
    spl_agent = EvidenceBoundSPLAgent(
        ollama=UnreferencedSuspicionModel(),
        splunk=ProbeReturnsNoCooccurrence(),
        validator=StaticSPLValidator(),
    )
    execution_strategy = spl_agent._deterministic_strategy(execution_source, execution_profile)
    execution_spl = spl_agent.compile(
        execution_plan,
        execution_source,
        execution_profile,
        execution_strategy,
    )
    if execution_strategy.group_by:
        failures.append(
            "row-preserving deterministic execution used a row-dropping group-by"
        )
    if not execution_strategy.preserve_result_row:
        failures.append("deterministic execution did not request a row-preserving summary")
    if "optional_context" in execution_spl or "required_signal" not in execution_spl:
        failures.append("compiled SPL was not aligned to the qualification field set")
    if execution_spl.find("| head ") > execution_spl.find("| stats "):
        failures.append("investigation input was not bounded before aggregation")
    if "| extract" not in execution_spl or "| spath" not in execution_spl:
        failures.append("execution did not reproduce bounded profile enrichment")
    if "aria_required_1_present" not in execution_spl:
        failures.append("execution did not measure required-field presence")

    positive_agent = EvidenceBoundSPLAgent(
        ollama=UnreferencedSuspicionModel(),
        splunk=EvidenceSummarySplunk(25),
        validator=StaticSPLValidator(),
    )
    positive_record = positive_agent.compile_and_execute(
        execution_plan,
        execution_source,
        execution_profile,
        execution_strategy,
        1,
    )
    if (
        not positive_record.rows
        or positive_record.observed_event_count != 25
        or positive_record.required_field_presence != {"required_signal": 25}
        or positive_record.fully_bound_event_count != 25
        or positive_record.qualification_consistent is not True
        or positive_record.execution_error
    ):
        failures.append("positive bounded execution did not preserve qualified live evidence")

    inconsistent_agent = EvidenceBoundSPLAgent(
        ollama=UnreferencedSuspicionModel(),
        splunk=EvidenceSummarySplunk(0),
        validator=StaticSPLValidator(),
    )
    inconsistent_record = inconsistent_agent.compile_and_execute(
        execution_plan,
        execution_source,
        execution_profile,
        execution_strategy,
        1,
    )
    if (
        inconsistent_record.qualification_consistent is not False
        or "QUALIFICATION_EXECUTION_INCONSISTENCY"
        not in str(inconsistent_record.execution_error or "")
    ):
        failures.append("qualification/execution contradiction did not fail closed")

    field_mismatch_agent = EvidenceBoundSPLAgent(
        ollama=UnreferencedSuspicionModel(),
        splunk=EvidenceSummarySplunk(25, field_presence=0),
        validator=StaticSPLValidator(),
    )
    field_mismatch_record = field_mismatch_agent.compile_and_execute(
        execution_plan,
        execution_source,
        execution_profile,
        execution_strategy,
        1,
    )
    if (
        field_mismatch_record.observed_event_count != 25
        or field_mismatch_record.missing_required_fields != ["required_signal"]
        or field_mismatch_record.qualification_consistent is not False
        or "QUALIFICATION_EXECUTION_INCONSISTENCY"
        not in str(field_mismatch_record.execution_error or "")
    ):
        failures.append(
            "positive event volume concealed an unpopulated required execution field"
        )

    print("ARIA Evidence-First Semantic Guard Tests")
    print("========================================")
    if failures:
        for failure in failures:
            print(f"FAIL   {failure}")
        print("ARIA_COPILOT_SEMANTIC_GUARDS=FAIL")
        return 1

    print("PASS   required-field co-occurrence is mandatory")
    print("PASS   single required fields need bounded live presence")
    print("PASS   entity presence does not create risk")
    print("PASS   event volume alone does not create risk")
    print("PASS   unreferenced suspicious claims are downgraded")
    print("PASS   source-only suspicious claims are downgraded")
    print("PASS   risk requires a claim linked to returned Splunk rows")
    print("PASS   row-preserving execution matches required-field qualification")
    print("PASS   investigation input is bounded before aggregation")
    print("PASS   qualification and execution use aligned bounded extraction")
    print("PASS   required-field presence is measured during execution")
    print("PASS   qualification/execution contradictions fail closed")
    print("PASS   event volume cannot conceal a missing required field")
    print("ARIA_COPILOT_SEMANTIC_GUARDS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
