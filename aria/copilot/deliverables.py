from __future__ import annotations

import json

from aria.copilot.contracts import (
    ConfidenceAssessment,
    FindingSynthesis,
    InvestigationPlan,
    RiskRecommendation,
    SearchExecutionRecord,
    SourceEvidenceRecord,
)
from aria.copilot.policy import evidence_policy
from aria.ollama_client import OllamaClient
from aria.suppressed_exception_logger import log_suppressed_exception


class EvidenceBoundDeliverableAgent:
    def __init__(self, ollama: OllamaClient) -> None:
        self.ollama = ollama

    def generate(
        self,
        question: str,
        plan: InvestigationPlan,
        sources: list[SourceEvidenceRecord],
        searches: list[SearchExecutionRecord],
        finding: FindingSynthesis,
        confidence: ConfidenceAssessment,
        risk: RiskRecommendation | None,
    ) -> str:
        if plan.capability not in {
            "MALWARE_SIMULATION",
            "DETECTION_ENGINEERING",
            "RISK_SCORING",
            "TDIR_WORKFLOW",
            "SOAR_PLAYBOOK",
        }:
            return ""

        evidence = {
            "sources": [item.model_dump() for item in sources],
            "searches": [item.model_dump() for item in searches],
            "finding": finding.model_dump(),
            "confidence": confidence.model_dump(),
            "risk": risk.model_dump() if risk else None,
        }

        capability_instructions = {
            "MALWARE_SIMULATION": """Create a defender-only behavioural simulation plan. Decompose the analyst-described behaviour into observable stages, show which stages are covered by qualified live telemetry, identify gaps, provide safe validation steps, and reference generated read-only SPL. Do not provide payloads, executable code, exploit instructions or evasion guidance.""",
            "DETECTION_ENGINEERING": """Create an evidence-bound detection candidate. Include objective, validated telemetry, field bindings, candidate SPL already executed, returned evidence, false-positive hypotheses, tuning plan, promotion readiness and analyst approval gates. Do not claim production readiness when evidence is incomplete.""",
            "RISK_SCORING": """Explain the evidence-derived RBA/ERS recommendation. Show every factor and penalty, distinguish risk recommendation from writeback, and state why no score is produced when policy eligibility is false.""",
            "TDIR_WORKFLOW": """Draft an evidence-specific TDIR workflow. Detect and investigate steps may use the supplied read-only SPL. Response and recovery actions must be approval-gated, include decision criteria, owners, rollback and validation. Do not claim that any action was executed.""",
            "SOAR_PLAYBOOK": """Draft a zero-trust SOAR playbook from the supplied evidence. Include trigger evidence, enrichments, branch conditions, approval owners, actions, failure handling, rollback, audit records and closure criteria. Keep every disruptive action approval-gated and unexecuted.""",
        }

        system = f"""You are ARIA's evidence-bound deliverable agent.

{capability_instructions[plan.capability]}

Universal rules:
- Use only facts in the supplied evidence ledger.
- Cite evidence IDs next to factual claims.
- Do not invent indexes, sourcetypes, fields, values, event IDs, entities, thresholds, risk facts or action outcomes.
- Missing evidence must remain explicit.
- Keep the output useful to an intermediate SOC analyst.
- Output Markdown only.
"""
        user = f"""Analyst request:
{question}

Plan:
{plan.model_dump_json(indent=2)}

Evidence ledger:
{json.dumps(evidence, ensure_ascii=False, indent=2)}

Create the requested evidence-bound deliverable."""
        try:
            return self.ollama.chat(
                system_prompt=system,
                user_prompt=user,
                model_role="reasoning",
                temperature=0.1,
                num_predict=1400,
                timeout=int(evidence_policy().get("deliverable_model_timeout_seconds", 120)),
            )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.deliverables")
            return (
                "## Deliverable generation deferred\n\n"
                "The evidence workflow completed, but the local reasoning model exceeded its "
                "bounded latency budget while drafting the requested deliverable. The evidence "
                "ledger, executed SPL and confidence calculation remain available for analyst review."
            )
