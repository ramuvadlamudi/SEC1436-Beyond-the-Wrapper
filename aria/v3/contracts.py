from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


V3Capability = Literal[
    "IDENTITY",
    "SAFETY",
    "SCOPE_GUARD",
    "SOC_CONVERSATION",
    "INVENTORY",
    "EXPLAIN_SPL",
    "BUILD_SPL",
    "DETECTION_ENGINEERING",
    "RISK_SCORING",
    "TDIR_WORKFLOW",
    "SOAR_PLAYBOOK",
    "INVESTIGATION",
    "TRIAGE",
]


class V3Route(BaseModel):
    capability: V3Capability
    requires_splunk: bool = False
    execute_search: bool = False
    clarification_needed: bool = False
    clarifying_question: str | None = None
    rationale: str


class IntentConcept(BaseModel):
    concept_id: str
    role: Literal["activity", "entity", "target", "outcome", "context", "quantity"]
    description: str
    required: bool = True


class BehaviourIntent(BaseModel):
    summary: str
    behaviour_terms: list[str] = Field(default_factory=list)
    concepts: list[IntentConcept] = Field(default_factory=list)
    desired_shape: Literal["events", "distribution", "timeline", "relationship", "ratio", "sequence"] = "events"
    limit: int = Field(default=100, ge=1, le=500)


class AnalystAggregation(BaseModel):
    """Deterministically extracted analyst aggregation instructions.

    These values originate only from the analyst's current request or retained
    Builder request. They are never inferred from deployment data or invented by
    a model.
    """

    metric: Literal["distinct_count"] = "distinct_count"
    measured_concept: str
    measured_concept_id: str = "ARIA_MEASURED_VALUE"
    entity_concept: str | None = None
    entity_concept_id: str | None = None
    grouping_concept: str | None = None
    grouping_concept_id: str | None = None
    window_span: str | None = None
    operator: Literal[">", ">=", "<", "<=", "="]
    threshold: int = Field(ge=0)
    source_text: str


class SourceConstraint(BaseModel):
    index: str | None = None
    sourcetype: str | None = None
    earliest: str | None = None
    latest: str | None = None
    literal_condition: str | None = None
    explicit: bool = False


class FieldBinding(BaseModel):
    concept_id: str
    role: str
    description: str
    field: str | None = None
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    method: str = "NONE"
    observed_samples: list[str] = Field(default_factory=list)
    populated_events: int = 0


class SourceAssessment(BaseModel):
    candidate_id: str
    index: str
    sourcetype: str
    event_count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    profile_error: str | None = None
    fields_observed: int = 0
    bindings: list[FieldBinding] = Field(default_factory=list)
    required_bindings_supported: int = 0
    required_bindings_total: int = 0
    schema_qualified: bool = False
    rationale: list[str] = Field(default_factory=list)


class SPLVariant(BaseModel):
    name: str
    spl: str
    status: Literal[
        "PROPOSED",
        "WAITING_FOR_TIME_RANGE",
        "SOURCE_QUALIFIED",
        "SCHEMA_QUALIFIED",
        "DATA_VALIDATED",
        "RESULT_VALIDATED",
        "BLOCKED",
        "UNAVAILABLE",
    ]
    safe: bool = False
    validation_errors: list[str] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)
    executed: bool = False
    rows: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class TriageDecision(BaseModel):
    verdict: Literal[
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "SUSPICIOUS",
        "BENIGN_OR_EXPECTED",
        "INSUFFICIENT_EVIDENCE",
    ] = "INSUFFICIENT_EVIDENCE"
    confidence: int = Field(default=0, ge=0, le=100)
    reasoning: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    next_action: str
