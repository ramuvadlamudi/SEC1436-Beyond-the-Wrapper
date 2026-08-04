from __future__ import annotations

import json
import re
from typing import Any

from aria.copilot.catalog_ranker import deterministic_catalog_selection
from aria.copilot.contracts import (
    CatalogCandidateSelection,
    EvidenceRequirement,
    InvestigationHypothesis,
    InvestigationPlan,
    IntentRoute,
    SourceQualificationSet,
)
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import compact_text, safe_time
from aria.ollama_client import OllamaClient


class CopilotPlanner:
    """Reliable, scenario-agnostic investigation planner.

    The interactive control path does not require a generative model. Plans are
    built from the routed product capability, analyst-supplied language and
    generic observable roles. Local models can still reason over the resulting
    evidence, but a slow or unavailable model cannot prevent telemetry access.
    """

    LIVE_CAPABILITIES = {
        "QUERY_SPLUNK",
        "INVESTIGATE_ENTITY",
        "THREAT_ANALYSIS",
        "MALWARE_SIMULATION",
        "DETECTION_ENGINEERING",
        "RISK_SCORING",
        "TDIR_WORKFLOW",
        "SOAR_PLAYBOOK",
        "CASE_SUMMARY",
    }

    def __init__(self, ollama: OllamaClient) -> None:
        self.ollama = ollama
        self.policy = evidence_policy()

    def plan(
        self,
        question: str,
        history: list[Any] | None = None,
        last_result: Any | None = None,
        route: IntentRoute | None = None,
    ) -> InvestigationPlan:
        route = route or IntentRoute(
            capability="SOC_CONVERSATION",
            domain_scope="SECOPS",
            mode="CONVERSATION",
            goal=question,
            routing_summary="Fallback conversational route.",
        )
        earliest, latest, explicit_time = self._extract_time_range(question)
        prior_text = self._prior_text(last_result)
        explicit_entities = self._extract_explicit_values(question)
        if self._has_context_reference(question):
            explicit_entities.extend(self._extract_explicit_values(prior_text))
        explicit_entities = list(dict.fromkeys(explicit_entities))[:12]

        requirements: list[EvidenceRequirement] = []
        hypotheses: list[InvestigationHypothesis] = []
        execute = bool(route.requires_live_splunk)

        if route.capability in self.LIVE_CAPABILITIES:
            core = self._extract_core_concept(question)
            requirements = self._generic_requirements(
                capability=route.capability,
                core_concept=core,
                has_explicit_entity=bool(explicit_entities),
            )
            hypotheses = [
                InvestigationHypothesis(
                    hypothesis_id="H1",
                    statement=(
                        "The analyst-requested activity or condition is observable in the "
                        "connected telemetry for the selected time range."
                    ),
                    supporting_requirement_ids=[
                        item.requirement_id for item in requirements if item.required
                    ],
                    disconfirming_evidence=[
                        "No live source exposes a populated field semantically aligned to the required activity.",
                        "Required observed fields do not occur in the same bounded events.",
                        "The safe read-only search returns no rows.",
                    ],
                )
            ]

        plan = InvestigationPlan(
            capability=route.capability,
            goal=compact_text(question, 1000),
            earliest=earliest,
            latest=latest,
            time_range_explicit=explicit_time,
            explicit_entities=explicit_entities,
            explicit_values=list(explicit_entities),
            generic_template_only=route.generic_template_only,
            unsafe_action_requested=route.unsafe_action_requested,
            safe_redirect_goal=route.safe_redirect_goal,
            execute_read_only_search=execute,
            hypotheses=hypotheses,
            requirements=requirements,
            success_criteria=(
                [
                    "At least one live source is profiled with observed fields and values.",
                    "Required evidence fields are validated against the live profile.",
                    "Required fields occur in at least one bounded event.",
                    "Any generated SPL passes the deterministic read-only safety gate.",
                    "The final response cites returned Splunk evidence or clearly abstains.",
                ]
                if execute and route.capability != "INVENTORY"
                else []
            ),
            abstain_conditions=(
                [
                    "No live source can express the required observable concept.",
                    "Only catalog metadata is visible and raw field validation is unavailable.",
                    "Required fields are not observed together.",
                    "The read-only search fails validation or execution.",
                ]
                if execute and route.capability != "INVENTORY"
                else []
            ),
        )
        return plan

    def select_candidates(
        self,
        question: str,
        plan: InvestigationPlan,
        catalog_rows: list[dict[str, Any]],
        limit: int,
    ) -> CatalogCandidateSelection:
        """Select candidates using deterministic live-catalog semantics only.

        Source labels are recall hints, never proof. No generative model is used in
        the interactive candidate-retrieval path, eliminating a common timeout and
        ensuring parity with the connected diagnostic.
        """
        safe_limit = max(0, min(int(limit), len(catalog_rows)))
        if safe_limit <= 0:
            return CatalogCandidateSelection(candidates=[])

        positive = deterministic_catalog_selection(
            question=question,
            plan=plan,
            catalog_rows=catalog_rows,
            limit=safe_limit,
            positive_only=True,
        )
        if positive.candidates:
            return positive
        return deterministic_catalog_selection(
            question=question,
            plan=plan,
            catalog_rows=catalog_rows,
            limit=safe_limit,
            positive_only=False,
        )

    def qualify_sources(
        self,
        question: str,
        plan: InvestigationPlan,
        profiles: list[dict[str, Any]],
    ) -> SourceQualificationSet:
        """Return an empty advisory set for observed-schema semantic binding.

        The SemanticFieldBinder consumes the live profile and produces proposals
        using local embeddings with lexical fallback. This removes generative
        field-mapping calls from the critical path while preserving deterministic
        field existence, observed-value and co-occurrence validation.
        """
        return SourceQualificationSet(sources=[])

    @classmethod
    def _generic_requirements(
        cls,
        *,
        capability: str,
        core_concept: str,
        has_explicit_entity: bool,
    ) -> list[EvidenceRequirement]:
        output = [
            EvidenceRequirement(
                requirement_id="R1",
                concept=core_concept,
                role="activity",
                required=True,
                reason=(
                    "A populated observable aligned to the analyst-requested activity is "
                    "required before ARIA can qualify telemetry or generate SPL."
                ),
            )
        ]
        if capability == "INVESTIGATE_ENTITY" and has_explicit_entity:
            output.insert(
                0,
                EvidenceRequirement(
                    requirement_id="R0",
                    concept="analyst-supplied entity or value",
                    role="entity",
                    required=True,
                    reason="The supplied entity must be observable in the selected telemetry.",
                ),
            )
        # Context roles are optional for exploratory evidence discovery. They
        # improve the resulting search when available but cannot reject otherwise
        # usable telemetry solely because a particular schema omits one role.
        output.extend(
            [
                EvidenceRequirement(
                    requirement_id="R2",
                    concept="originating entity or actor",
                    role="entity",
                    required=False,
                    reason="Useful for attributing the observed activity.",
                ),
                EvidenceRequirement(
                    requirement_id="R3",
                    concept="target, destination, or related entity",
                    role="relationship",
                    required=False,
                    reason="Useful for describing relationships and pivots.",
                ),
                EvidenceRequirement(
                    requirement_id="R4",
                    concept="outcome, response, or state",
                    role="outcome",
                    required=False,
                    reason="Useful for distinguishing result states when the source exposes them.",
                ),
            ]
        )
        return output

    @classmethod
    def _extract_core_concept(cls, question: str) -> str:
        text = str(question or "").strip()
        first = re.split(r"[\n\r.]", text, maxsplit=1)[0]
        normalised = " ".join(first.split())

        # Remove product-control wording while preserving the analyst's security
        # subject. This is grammar normalisation, not a scenario dictionary.
        patterns = [
            r"\b(?:use|using)\s+live\s+splunk\s+evidence\b",
            r"\b(?:use|using)\s+splunk\s+evidence\b",
            r"\b(?:from|against|in)\s+(?:the\s+)?connected\s+splunk(?:\s+instance)?\b",
            r"\b(?:in|across)\s+(?:my|our|the)\s+environment\b",
            r"\bacross\s+all\s+available\s+time\b",
            r"\bacross\s+all\s+time\b",
            r"\b(?:discover|validate|verify|execute|report|show)\b.*$",
        ]
        candidate = normalised
        for pattern in patterns:
            candidate = re.sub(pattern, " ", candidate, flags=re.IGNORECASE)
        candidate = re.sub(
            r"^(?:please\s+)?(?:build\s+and\s+execute|build|create|generate|write|construct|draft|produce|give\s+me)\s+(?:me\s+)?(?:an?\s+)?spl\s*(?:for|to|that|which)?\s*",
            "",
            candidate,
            flags=re.IGNORECASE,
        )
        candidate = re.sub(
            r"^(?:please\s+)?(?:investigate|find|identify|detect|hunt\s+for|hunt|query|search\s+for|search|analyse|analyze|examine|test)\s+",
            "",
            candidate,
            flags=re.IGNORECASE,
        )
        candidate = " ".join(candidate.strip(" ,:-").split())
        if len(candidate) < 3:
            return "analyst-requested security activity or condition"
        return compact_text(candidate, 180)

    @staticmethod
    def _extract_time_range(question: str) -> tuple[str, str, bool]:
        text = " ".join(str(question or "").lower().replace("-", " ").split())
        if any(phrase in text for phrase in (
            "all available time", "across all time", "all historical time",
            "all history", "earliest available", "from the beginning",
        )):
            return "0", "now", True

        match = re.search(r"(?:last|past)\s+(\d+)\s*(minute|minutes|hour|hours|day|days|week|weeks)", text)
        if match:
            value = max(1, int(match.group(1)))
            unit = match.group(2)
            suffix = "m" if unit.startswith("minute") else "h" if unit.startswith("hour") else "d" if unit.startswith("day") else "w"
            return f"-{value}{suffix}", "now", True
        return "-24h", "now", False

    @staticmethod
    def _extract_explicit_values(text: str) -> list[str]:
        raw = str(text or "")
        values: list[str] = []
        patterns = [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            r"\b[A-Fa-f0-9]{32,64}\b",
            r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
            r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            r"[\"']([^\"']{2,160})[\"']",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, raw):
                value = match.group(1) if match.lastindex else match.group(0)
                value = value.strip()
                if value and value not in values:
                    values.append(value)
        return values

    @staticmethod
    def _has_context_reference(question: str) -> bool:
        text = " ".join(str(question or "").lower().split())
        return any(term in text for term in (
            "based on that", "use the previous", "previous evidence", "same entity",
            "that result", "those results", "turn this", "continue",
        ))

    @staticmethod
    def _prior_text(last_result: Any | None) -> str:
        if not last_result:
            return ""
        try:
            if isinstance(last_result, dict):
                return compact_text(json.dumps(last_result, ensure_ascii=False), 1800)
            return compact_text(last_result, 1800)
        except Exception:
            return compact_text(last_result, 1800)
