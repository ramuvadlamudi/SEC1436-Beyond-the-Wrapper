from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# =====================================================
# ACTION CONTRACT
# =====================================================


class ActionRecommendation(BaseModel):
    capability: str

    goal: str

    reason: str

    requires_approval: bool = False


# =====================================================
# GOAL PLAN
# =====================================================


class TaskPlan(BaseModel):
    task_type: Literal[
        "DISCOVER",
        "SEARCH",
        "INVESTIGATE",
        "ANALYZE",
    ]

    goal: str

    earliest: str = "0"
    latest: str = "now"

    entity_terms: list[str] = Field(
        default_factory=list
    )

    evidence_concepts: list[str] = Field(
        default_factory=list
    )

    required_evidence: list[str] = Field(
        default_factory=list
    )

    success_criteria: list[str] = Field(
        default_factory=list
    )


# =====================================================
# SPLUNK DISCOVERY
# =====================================================


class CatalogItem(BaseModel):
    index: str
    sourcetype: str

    event_count: int = 0

    first_seen: str | None = None
    last_seen: str | None = None


class CandidateSource(BaseModel):
    index: str
    sourcetype: str

    rationale: str


class CandidateSelection(BaseModel):
    candidates: list[
        CandidateSource
    ] = Field(
        default_factory=list
    )


# =====================================================
# FIELD PROFILING
# =====================================================


class FieldEvidence(BaseModel):
    name: str

    count: int | None = None

    distinct_count: int | None = None

    sample_values: str | None = None


class SourceProfile(BaseModel):
    index: str
    sourcetype: str

    rationale: str = ""

    fields: list[
        FieldEvidence
    ] = Field(
        default_factory=list
    )


# =====================================================
# TELEMETRY SOURCE CARDS
# =====================================================


class TelemetrySourceCard(BaseModel):
    card_id: str

    index: str
    sourcetype: str

    event_count: int = 0

    first_seen: str | None = None
    last_seen: str | None = None

    profile_status: Literal[
        "CATALOG_ONLY",
        "PROFILED",
        "EVENT_SEARCH_UNAVAILABLE",
        "PROFILE_FAILED",
    ] = "CATALOG_ONLY"

    fields: list[
        FieldEvidence
    ] = Field(
        default_factory=list
    )

    availability_reason: str | None = None

    semantic_text: str

    updated_at: str


class TelemetryMatch(BaseModel):
    score: float

    card: TelemetrySourceCard


# =====================================================
# FIELD-LEVEL TELEMETRY INTELLIGENCE
# =====================================================


class FieldSemanticMatch(BaseModel):
    score: float

    index: str
    sourcetype: str

    field: FieldEvidence

    semantic_text: str


class RequirementEvidence(BaseModel):
    requirement_id: str

    requirement: str

    matches: list[
        FieldSemanticMatch
    ] = Field(
        default_factory=list
    )


class SourceEvidenceBundle(BaseModel):
    index: str
    sourcetype: str

    score: float

    coverage_count: int
    total_requirements: int

    requirement_evidence: list[
        RequirementEvidence
    ] = Field(
        default_factory=list
    )


# =====================================================
# EVIDENCE BINDING
# =====================================================


class EvidenceLocation(BaseModel):
    index: str
    sourcetype: str

    fields: list[str] = Field(
        default_factory=list
    )

    observed_signals: list[str] = Field(
        default_factory=list
    )


class EvidenceRequirementBinding(BaseModel):
    requirement_id: str

    requirement: str

    status: Literal[
        "SUPPORTED",
        "PARTIAL",
        "UNSUPPORTED",
    ]

    confidence: int = Field(
        ge=0,
        le=100,
    )

    locations: list[
        EvidenceLocation
    ] = Field(
        default_factory=list
    )

    reason: str


class EvidenceBindingProposal(BaseModel):
    """
    Small LLM output contract.

    The LLM proposes requirement bindings only.

    Python derives:
    - final verdict,
    - compile readiness,
    - overall confidence,
    - missing evidence,
    - next action.
    """

    bindings: list[
        EvidenceRequirementBinding
    ] = Field(
        default_factory=list
    )


class EvidenceBindingDecision(BaseModel):
    verdict: Literal[
        "SUPPORTED",
        "PARTIAL",
        "NO_EVIDENCE",
    ]

    compile_ready: bool

    overall_confidence: int = Field(
        ge=0,
        le=100,
    )

    bindings: list[
        EvidenceRequirementBinding
    ] = Field(
        default_factory=list
    )

    missing_evidence: list[str] = Field(
        default_factory=list
    )

    reasoning: str

    next_best_action: (
        ActionRecommendation | None
    ) = None

    alternative_actions: list[
        ActionRecommendation
    ] = Field(
        default_factory=list
    )


# =====================================================
# SOC ASSESSMENT ENVELOPE
# =====================================================


class AssessmentDecision(BaseModel):
    verdict: str

    model_confidence: int = Field(
        ge=0,
        le=100,
    )

    evidence_confidence: int = Field(
        ge=0,
        le=100,
    )

    final_confidence: int = Field(
        ge=0,
        le=100,
    )

    reasoning: str

    evidence_for: list[str] = Field(
        default_factory=list
    )

    evidence_against: list[str] = Field(
        default_factory=list
    )

    missing_evidence: list[str] = Field(
        default_factory=list
    )

    next_best_action: (
        ActionRecommendation | None
    ) = None

    alternative_actions: list[
        ActionRecommendation
    ] = Field(
        default_factory=list
    )
