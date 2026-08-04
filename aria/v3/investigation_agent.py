from __future__ import annotations

import os
import re
import time
from typing import Any

from aria.copilot.contracts import EvidenceRequirement, IntentRoute, InvestigationHypothesis, InvestigationPlan
from aria.copilot.legacy_engine import EvidenceFirstCopilotEngine as LegacyWorkflowEngine
from aria.copilot.planner import CopilotPlanner
from aria.ollama_client import OllamaClient
from aria.splunk_client import SplunkClient
from aria.suppressed_exception_logger import log_suppressed_exception
from aria.v3.utils import compact_text, parse_time_range, salient_terms


class InvestigationAgent:
    """Evidence-first live investigation agent.

    ARIA v3 owns routing and the investigation contract. The previously validated
    evidence workflow remains an internal execution service for catalogue discovery,
    observed-schema binding, co-occurrence, SPL safety, execution and evidence
    synthesis.
    """

    def __init__(self, ollama: OllamaClient, splunk: SplunkClient) -> None:
        self.ollama = ollama
        self.splunk = splunk
        self.planner = CopilotPlanner(ollama)
        self.workflow = LegacyWorkflowEngine(ollama=ollama, splunk=splunk)

    def investigate(self, question: str, *, progress: Any | None = None) -> Any:
        started = time.monotonic()
        cleaned = self._clean_control_language(question)
        route = IntentRoute(
            capability="QUERY_SPLUNK",
            mode="LIVE_EVIDENCE",
            goal=cleaned,
            requires_live_splunk=True,
            requires_evidence_plan=True,
            routing_confidence=100,
            routing_summary="ARIA v3 deterministic control plane selected the Investigation Agent.",
        )
        try:
            plan = self.planner.plan(cleaned, history=[], last_result=None, route=route)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.investigation.plan")
            plan = self._fallback_plan(cleaned)
        plan.capability = "QUERY_SPLUNK"
        plan.execute_read_only_search = True
        plan = self._repair_plan(cleaned, plan)
        deadline = started + max(60, int(os.getenv("ARIA_V3_INVESTIGATION_BUDGET_SECONDS", "300")))
        result = self.workflow._run_evidence_workflow(
            cleaned,
            plan,
            progress=progress,
            deadline=deadline,
        )
        result.capability = "INVESTIGATION"
        result.metadata.update({
            "agent": "INVESTIGATION_AGENT_V3",
            "control_plane": "DETERMINISTIC",
            "legacy_execution_service": "EVIDENCE_WORKFLOW_V2_VALIDATED",
            "duration_seconds": round(time.monotonic() - started, 2),
        })
        result.answer = result.answer.replace("ARIA Evidence-First SOC Copilot", "ARIA v3 Investigation Agent", 1)
        return result

    def _repair_plan(self, question: str, plan: InvestigationPlan) -> InvestigationPlan:
        earliest, latest, explicit = parse_time_range(question)
        if explicit:
            plan.earliest = earliest or plan.earliest
            plan.latest = latest or plan.latest
            plan.time_range_explicit = True
        bad_required = [
            item for item in plan.requirements
            if item.required and self._workflow_directive(item.concept)
        ]
        if bad_required or not any(item.required for item in plan.requirements):
            terms = salient_terms(question, limit=8)
            concept = " ".join(terms) or "analyst-requested security activity"
            plan.requirements = [
                EvidenceRequirement(
                    requirement_id="R1",
                    concept=concept,
                    role="activity",
                    required=True,
                    reason="Observable event content representing the analyst-requested behaviour.",
                ),
                EvidenceRequirement(
                    requirement_id="R2",
                    concept="originating entity or actor context",
                    role="entity",
                    required=False,
                    reason="Provides entity context when observed in the live source.",
                ),
                EvidenceRequirement(
                    requirement_id="R3",
                    concept="target, destination, or related entity context",
                    role="relationship",
                    required=False,
                    reason="Provides a relationship dimension when observed.",
                ),
                EvidenceRequirement(
                    requirement_id="R4",
                    concept="outcome, response, or state",
                    role="outcome",
                    required=False,
                    reason="Provides outcome context when observed.",
                ),
            ]
            plan.hypotheses = [
                InvestigationHypothesis(
                    hypothesis_id="H1",
                    statement="The analyst-requested behaviour is observable in the connected telemetry for the selected time range.",
                    supporting_requirement_ids=["R1"],
                    disconfirming_evidence=[
                        "No live source can express the required activity concept.",
                        "The generated read-only search returns no supporting rows.",
                    ],
                )
            ]
        plan.goal = question
        plan.success_criteria = list(dict.fromkeys([
            *plan.success_criteria,
            "At least one live source is profiled from the connected catalogue.",
            "Executable SPL contains only observed or analyst-supplied deployment bindings.",
            "Any security conclusion references returned Splunk rows.",
        ]))
        return plan

    @staticmethod
    def _fallback_plan(question: str) -> InvestigationPlan:
        earliest, latest, explicit = parse_time_range(question)
        terms = salient_terms(question, limit=8)
        concept = " ".join(terms) or "analyst-requested security activity"
        return InvestigationPlan(
            capability="QUERY_SPLUNK",
            goal=question,
            earliest=earliest or "-24h",
            latest=latest or "now",
            time_range_explicit=explicit,
            execute_read_only_search=True,
            hypotheses=[
                InvestigationHypothesis(
                    hypothesis_id="H1",
                    statement="The analyst-requested behaviour is observable in the connected telemetry.",
                    supporting_requirement_ids=["R1"],
                )
            ],
            requirements=[
                EvidenceRequirement(
                    requirement_id="R1",
                    concept=concept,
                    role="activity",
                    required=True,
                    reason="Primary analyst-requested observable activity.",
                )
            ],
            success_criteria=["A live source is qualified and a safe read-only search is executed."],
            abstain_conditions=["No source can express the required activity or no returned rows support it."],
        )

    @staticmethod
    def _workflow_directive(concept: str) -> bool:
        value = " ".join(str(concept or "").lower().split())
        return any(phrase in value for phrase in (
            "build and", "build spl", "execute spl", "discover source", "validate fields",
            "report gaps", "live splunk evidence", "across all available time",
        ))

    @staticmethod
    def _clean_control_language(question: str) -> str:
        text = str(question or "")
        text = re.sub(r"^\s*(?:build|create|generate)\s+and\s+execute\s+(?:a\s+)?(?:safe\s+bounded\s+)?spl(?:\s+search)?\s+(?:using\s+live\s+splunk\s+evidence\s+)?(?:to\s+)?", "Investigate ", text, flags=re.IGNORECASE)
        text = re.sub(r"\bdiscover\s+the\s+source\s+and\s+fields\s+rather\s+than\s+assuming\s+them\b", "", text, flags=re.IGNORECASE)
        text = re.sub(r"^\s*Investigate\s+investigate\b", "Investigate", text, flags=re.IGNORECASE)
        text = re.sub(r"\s+([.?!])", r"\1", text)
        text = re.sub(r"(?:\.\s*){2,}", ". ", text)
        return " ".join(text.split()).strip()
