from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_POLICY_PATH = ROOT / "product" / "evidence_policy.json"
RISK_POLICY_PATH = ROOT / "product" / "risk_policy.json"


DEFAULT_EVIDENCE_POLICY: dict[str, Any] = {
    "policy_name": "ARIA Evidence Qualification Policy",
    "policy_version": "2.1.11",
    "candidate_limit": 2,
    "accepted_source_limit": 1,
    "profile_field_limit": 36,
    "profile_sample_value_limit": 3,
    "cooccurrence_event_limit": 200,
    "result_limit": 30,
    "minimum_required_coverage": 0.6,
    "minimum_source_score": 55.0,
    "require_cooccurrence_for_multiple_required_concepts": True,
    "confidence_weights": {
        "required_concept_coverage": 35,
        "field_observation": 15,
        "cooccurrence": 20,
        "search_result_support": 15,
        "cross_source_corroboration": 10,
        "reasoning_traceability": 5
    },
    "confidence_penalties": {
        "missing_required_concept": 10,
        "contradicting_claim": 8,
        "stale_or_unbounded_time": 5,
        "execution_error": 15
    },
    "minimum_llm_suitability": "MEDIUM",
    "historical_candidate_limit": 3,
    "qualification_batch_size": 2,
    "recovery_candidate_limit": 1,
    "qualification_prompt_field_limit": 24,
    "semantic_positive_candidate_limit": 1,
    "candidate_model_timeout_seconds": 30,
    "qualification_model_timeout_seconds": 60,
    "qualification_retry_timeout_seconds": 30,
    "strategy_model_timeout_seconds": 45,
    "reasoning_model_timeout_seconds": 60,
    "followup_llm_enabled": False,
    "profile_search_timeout_seconds": 60,
    "execution_search_timeout_seconds": 90,
    "runtime_budget_seconds": 300,
    "max_total_candidates_profiled": 4,
    "intent_model_timeout_seconds": 45,
    "scope_model_timeout_seconds": 20,
    "route_repair_timeout_seconds": 30,
    "plan_model_timeout_seconds": 60,
    "plan_repair_timeout_seconds": 45,
    "conversation_model_timeout_seconds": 90,
    "conversation_retry_timeout_seconds": 75,
    "spl_explanation_timeout_seconds": 120,
    "template_model_timeout_seconds": 60,
    "deliverable_model_timeout_seconds": 120,
    "followup_model_timeout_seconds": 20,
    "recovery_minimum_budget_seconds": 55,
    "historical_recovery_minimum_budget_seconds": 75,
    "reasoning_minimum_budget_seconds": 30
}


DEFAULT_RISK_POLICY: dict[str, Any] = {
    "minimum_evidence_confidence": 60,
    "minimum_supporting_claims": 1,
    "require_security_relevant_finding": True,
    "base_factors": {
        "evidence_confidence": 30,
        "cross_source_corroboration": 20,
        "relationship_strength": 15,
        "repeated_or_concentrated_activity": 15,
        "outcome_support": 10,
        "analyst_supplied_entity_match": 10
    },
    "penalties": {
        "missing_required_evidence": 15,
        "contradicting_evidence": 15,
        "single_source_only": 10,
        "weak_field_binding": 10
    },
    "maximum_recommendation": 100,
    "writeback_enabled": False
}


def _load(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            merged = dict(default)
            for key, item in value.items():
                if isinstance(item, dict) and isinstance(merged.get(key), dict):
                    merged[key] = {**merged[key], **item}
                else:
                    merged[key] = item
            return merged
    except Exception:
        return dict(default)
    return dict(default)


def evidence_policy() -> dict[str, Any]:
    return _load(EVIDENCE_POLICY_PATH, DEFAULT_EVIDENCE_POLICY)


def risk_policy() -> dict[str, Any]:
    return _load(RISK_POLICY_PATH, DEFAULT_RISK_POLICY)
