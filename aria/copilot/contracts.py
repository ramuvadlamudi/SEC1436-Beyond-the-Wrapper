from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Capability = Literal[
    "IDENTITY",
    "SAFETY",
    "INVENTORY",
    "EXPLAIN_SPL",
    "BUILD_SPL",
    "QUERY_SPLUNK",
    "INVESTIGATE_ENTITY",
    "THREAT_ANALYSIS",
    "MALWARE_SIMULATION",
    "DETECTION_ENGINEERING",
    "RISK_SCORING",
    "TDIR_WORKFLOW",
    "SOAR_PLAYBOOK",
    "CASE_SUMMARY",
    "SOC_CONVERSATION",
    "SCOPE_GUARD",
]



InteractionMode = Literal[
    "CONVERSATION",
    "LIVE_EVIDENCE",
    "SPL_EXPLANATION",
    "SPL_BUILD",
    "GENERIC_TEMPLATE",
    "SAFETY_REDIRECT",
    "DOMAIN_REDIRECT",
]


DomainScope = Literal[
    "SECOPS",
    "OUT_OF_SCOPE",
]


class IntentRoute(BaseModel):
    capability: Capability
    domain_scope: DomainScope = "SECOPS"
    mode: InteractionMode
    goal: str
    requires_live_splunk: bool = False
    requires_evidence_plan: bool = False
    generic_template_only: bool = False
    unsafe_action_requested: bool = False
    safe_redirect_goal: str | None = None
    clarification_needed: bool = False
    clarifying_question: str | None = None
    response_depth: Literal["brief", "standard", "deep"] = "standard"
    routing_confidence: int = Field(default=80, ge=0, le=100)
    routing_summary: str
    suggested_followups: list[str] = Field(default_factory=list)


class ScopeDecision(BaseModel):
    domain_scope: DomainScope
    confidence: int = Field(default=80, ge=0, le=100)
    summary: str


class FollowUpSuggestionSet(BaseModel):
    prompts: list[str] = Field(default_factory=list)


RequirementRole = Literal[
    "entity",
    "activity",
    "outcome",
    "relationship",
    "time",
    "quantity",
    "context",
]


class EvidenceRequirement(BaseModel):
    requirement_id: str
    concept: str
    role: RequirementRole
    required: bool = True
    reason: str


class InvestigationHypothesis(BaseModel):
    hypothesis_id: str
    statement: str
    supporting_requirement_ids: list[str] = Field(default_factory=list)
    disconfirming_evidence: list[str] = Field(default_factory=list)


class InvestigationPlan(BaseModel):
    capability: Capability
    goal: str
    earliest: str = "-24h"
    latest: str = "now"
    time_range_explicit: bool = False
    explicit_entities: list[str] = Field(default_factory=list)
    explicit_values: list[str] = Field(default_factory=list)
    generic_template_only: bool = False
    unsafe_action_requested: bool = False
    safe_redirect_goal: str | None = None
    execute_read_only_search: bool = True
    hypotheses: list[InvestigationHypothesis] = Field(default_factory=list)
    requirements: list[EvidenceRequirement] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    abstain_conditions: list[str] = Field(default_factory=list)


class CatalogCandidateChoice(BaseModel):
    candidate_id: str
    rationale: str


class CatalogCandidateSelection(BaseModel):
    candidates: list[CatalogCandidateChoice] = Field(default_factory=list)


class RequirementFieldProposal(BaseModel):
    requirement_id: str
    status: Literal["SUPPORTED", "PARTIAL", "UNSUPPORTED"]
    fields: list[str] = Field(default_factory=list)
    rationale: str


class SourceQualificationProposal(BaseModel):
    candidate_id: str
    suitability: Literal["HIGH", "MEDIUM", "LOW", "NONE"]
    requirement_mappings: list[RequirementFieldProposal] = Field(default_factory=list)
    source_reasoning: str


class SourceQualificationSet(BaseModel):
    sources: list[SourceQualificationProposal] = Field(default_factory=list)


class FilterProposal(BaseModel):
    field: str
    operator: Literal[
        "exists",
        "equals",
        "contains",
        "contains_any",
        "in",
        "gt",
        "gte",
        "lt",
        "lte",
    ]
    values: list[str] = Field(default_factory=list)
    rationale: str


class MetricProposal(BaseModel):
    function: Literal["count", "dc", "values", "sum", "avg", "min", "max"]
    field: str | None = None
    alias: str


class SearchStrategyProposal(BaseModel):
    candidate_id: str
    purpose: str
    filters: list[FilterProposal] = Field(default_factory=list)
    group_by: list[str] = Field(default_factory=list)
    display_fields: list[str] = Field(default_factory=list)
    metrics: list[MetricProposal] = Field(default_factory=list)
    preserve_result_row: bool = False
    time_bucket: str | None = None
    sort_by: str | None = None
    descending: bool = True
    limit: int = Field(default=30, ge=1, le=100)


class ClaimProposal(BaseModel):
    claim: str
    evidence_refs: list[str] = Field(default_factory=list)


class FindingSynthesis(BaseModel):
    verdict: Literal[
        "BENIGN_OR_EXPECTED",
        "SUSPICIOUS_REQUIRES_REVIEW",
        "LIKELY_TRUE_POSITIVE",
        "INSUFFICIENT_EVIDENCE",
        "CONTRADICTORY_EVIDENCE",
        "NO_RELEVANT_TELEMETRY",
        "EVIDENCE_FOUND",
    ]
    summary: str
    supporting_claims: list[ClaimProposal] = Field(default_factory=list)
    contradicting_claims: list[ClaimProposal] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    next_best_query_goal: str
    analyst_guidance: list[str] = Field(default_factory=list)


class SourceProfileRecord(BaseModel):
    candidate_id: str
    index: str
    sourcetype: str
    event_count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    fields: list[dict[str, Any]] = Field(default_factory=list)
    profile_error: str | None = None


class RequirementBindingRecord(BaseModel):
    requirement_id: str
    concept: str
    role: RequirementRole
    required: bool
    status: Literal["SUPPORTED", "PARTIAL", "UNSUPPORTED"]
    fields: list[str] = Field(default_factory=list)
    observed_samples: dict[str, list[str]] = Field(default_factory=dict)
    rationale: str


class SourceEvidenceRecord(BaseModel):
    evidence_id: str
    candidate_id: str
    index: str
    sourcetype: str
    suitability: str
    score: float
    accepted: bool
    rejection_reasons: list[str] = Field(default_factory=list)
    requirement_bindings: list[RequirementBindingRecord] = Field(default_factory=list)
    sampled_events: int = 0
    fully_bound_events: int = 0
    cooccurrence_ratio: float = 0.0
    profile_error: str | None = None


class SearchExecutionRecord(BaseModel):
    evidence_id: str
    candidate_id: str
    index: str
    sourcetype: str
    purpose: str
    spl: str
    safe: bool
    validation_errors: list[str] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    execution_error: str | None = None
    observed_event_count: int | None = None
    required_field_presence: dict[str, int] = Field(default_factory=dict)
    missing_required_fields: list[str] = Field(default_factory=list)
    fully_bound_event_count: int | None = None
    qualification_consistent: bool | None = None


class ConfidenceFactor(BaseModel):
    factor: str
    points: int
    reason: str


class ConfidenceAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    factors: list[ConfidenceFactor] = Field(default_factory=list)


class RiskRecommendation(BaseModel):
    eligible: bool
    proposed_score: int = Field(ge=0, le=100)
    factors: list[ConfidenceFactor] = Field(default_factory=list)
    rationale: str
    writeback_performed: bool = False


class CopilotResult(BaseModel):
    capability: str
    goal: str
    answer: str
    plan: InvestigationPlan | None = None
    source_evidence: list[SourceEvidenceRecord] = Field(default_factory=list)
    searches: list[SearchExecutionRecord] = Field(default_factory=list)
    finding: FindingSynthesis | None = None
    confidence: ConfidenceAssessment | None = None
    risk: RiskRecommendation | None = None
    context_actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
