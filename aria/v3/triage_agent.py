from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from aria.copilot.contracts import (
    ConfidenceAssessment,
    ConfidenceFactor,
    CopilotResult,
    FindingSynthesis,
    InvestigationPlan,
    SearchExecutionRecord,
)
from aria.ollama_client import OllamaClient
from aria.spl_validator import StaticSPLValidator
from aria.splunk_client import SplunkClient
from aria.suppressed_exception_logger import log_suppressed_exception
from aria.v3.contracts import TriageDecision
from aria.v3.utils import compact_text, markdown_table, parse_time_range, spl_quote


class TriageAgent:
    def __init__(self, ollama: OllamaClient, splunk: SplunkClient, validator: StaticSPLValidator) -> None:
        self.ollama = ollama
        self.splunk = splunk
        self.validator = validator

    def triage(
        self,
        question: str,
        *,
        last_result: Any | None = None,
        progress: Any | None = None,
    ) -> CopilotResult:
        started = time.monotonic()
        evidence_context = self._evidence_context(last_result)
        earliest, latest, explicit_time = parse_time_range(question)
        earliest = earliest or "-24h"
        latest = latest or "now"
        prior_rows = self._prior_rows(last_result)
        has_prior_investigation = self._has_prior_investigation(last_result)
        value = self._explicit_value(question)
        searches: list[SearchExecutionRecord] = []
        evidence_rows: list[dict[str, Any]] = list(prior_rows)

        if not evidence_rows and not value and not has_prior_investigation:
            answer = """## Triage Agent needs a finding reference

Provide one of the following:

- A notable, finding or incident identifier.
- An analyst-supplied entity plus a time range.
- Search-result rows from the current investigation.

ARIA has not queried Splunk because no triage subject was supplied."""
            return CopilotResult(
                capability="TRIAGE",
                goal=question,
                answer=answer,
                plan=InvestigationPlan(capability="CASE_SUMMARY", goal=question, execute_read_only_search=False, requirements=[]),
                context_actions=[
                    "Triage finding ID <value> over the last 24 hours.",
                    "Triage the current investigation results.",
                    "Triage entity <value> across all available time.",
                ],
                metadata={"agent": "TRIAGE_AGENT_V3", "live_splunk_queries": False, "clarification_needed": True},
            )

        if value and not evidence_rows:
            if progress:
                progress("v3_triage_locator", "Locating the triage subject", "ARIA is running a bounded read-only locator search for the analyst-supplied value.")
            spl = (
                f"search index=* earliest={earliest} latest={latest} {spl_quote(value)}\n"
                "| table _time index sourcetype source _raw\n"
                "| head 100"
            )
            validation = self.validator.validate(spl)
            record = SearchExecutionRecord(
                evidence_id="QRY-1",
                candidate_id="TRIAGE-LOCATOR",
                index="*",
                sourcetype="*",
                purpose="Bounded read-only locator search for the analyst-supplied triage subject.",
                spl=spl,
                safe=bool(getattr(validation, "safe", False)),
                validation_errors=list(getattr(validation, "errors", []) or []),
                validation_warnings=list(getattr(validation, "warnings", []) or []),
            )
            if record.safe:
                try:
                    record.rows = self.splunk.search(spl)[:100]
                except Exception as exc:
                    record.execution_error = f"{exc.__class__.__name__}: {exc}"
            searches.append(record)
            evidence_rows.extend(record.rows)

        decision = self._decision(question, value, evidence_rows, searches)
        confidence = ConfidenceAssessment(
            score=decision.confidence,
            factors=[
                ConfidenceFactor(
                    factor="Returned evidence",
                    points=min(45, len(evidence_rows)),
                    reason=f"{len(evidence_rows)} bounded row(s) were available to the triage agent.",
                ),
                ConfidenceFactor(
                    factor="Evidence gaps",
                    points=-min(30, 10 * len(decision.evidence_gaps)),
                    reason=f"{len(decision.evidence_gaps)} material evidence gap(s) remain.",
                ),
            ],
        )
        verdict_map = {
            "TRUE_POSITIVE": "LIKELY_TRUE_POSITIVE",
            "FALSE_POSITIVE": "BENIGN_OR_EXPECTED",
            "SUSPICIOUS": "SUSPICIOUS_REQUIRES_REVIEW",
            "BENIGN_OR_EXPECTED": "BENIGN_OR_EXPECTED",
            "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE",
        }
        finding = FindingSynthesis(
            verdict=verdict_map[decision.verdict],
            summary=decision.reasoning,
            missing_evidence=decision.evidence_gaps,
            next_best_query_goal=decision.next_action,
            analyst_guidance=["Analyst approval is required before any containment or operational action."],
        )
        answer = self._render(question, decision, searches, evidence_rows)
        return CopilotResult(
            capability="TRIAGE",
            goal=question,
            answer=answer,
            plan=InvestigationPlan(
                capability="CASE_SUMMARY",
                goal=question,
                earliest=earliest,
                latest=latest,
                time_range_explicit=explicit_time,
                execute_read_only_search=bool(searches),
                requirements=[],
            ),
            searches=searches,
            finding=finding,
            confidence=confidence,
            context_actions=[
                decision.next_action,
                "Summarise the supporting and contradicting evidence.",
                "Draft an approval-gated response workflow.",
                "Turn the validated evidence into a detection candidate.",
            ],
            metadata={
                "agent": "TRIAGE_AGENT_V3",
                "live_splunk_queries": bool(searches),
                "triage_verdict": decision.verdict,
                "triage_confidence": decision.confidence,
                "supporting_evidence": list(decision.supporting_evidence),
                "contradicting_evidence": list(decision.contradicting_evidence),
                "duration_seconds": round(time.monotonic() - started, 2),
                "prior_investigation_available": has_prior_investigation,
                "evidence_context": evidence_context,
            },
        )

    @staticmethod
    def _evidence_context(last_result: Any | None) -> dict[str, Any]:
        if isinstance(last_result, dict):
            payload = last_result
        elif hasattr(last_result, "model_dump"):
            dumped = last_result.model_dump()
            payload = dumped if isinstance(dumped, dict) else {}
        else:
            payload = {}
        if not payload:
            return {}
        metadata = payload.get("metadata") or {}
        inherited = metadata.get("evidence_context")
        if isinstance(inherited, dict) and inherited:
            return inherited
        return {
            "origin_capability": payload.get("capability"),
            "goal": payload.get("goal"),
            "plan": payload.get("plan"),
            "source_evidence": payload.get("source_evidence") or [],
            "searches": payload.get("searches") or [],
            "finding": payload.get("finding"),
            "confidence": payload.get("confidence"),
            "risk": payload.get("risk"),
            "spl_variants": {
                "generic": metadata.get("generic_spl"),
                "deployment": metadata.get("deployment_spl"),
            },
        }

    def _decision(
        self,
        question: str,
        value: str | None,
        rows: list[dict[str, Any]],
        searches: list[SearchExecutionRecord],
    ) -> TriageDecision:
        if not rows:
            return TriageDecision(
                verdict="INSUFFICIENT_EVIDENCE",
                confidence=0,
                reasoning="No bounded Splunk rows were returned for the supplied triage subject.",
                evidence_gaps=["No returned event evidence", "No corroborating source context"],
                next_action="Widen the time range or provide the source finding and relevant entity context.",
            )
        evidence_payload = []
        for position, row in enumerate(rows[:40], start=1):
            evidence_payload.append({"evidence_id": f"ROW-{position}", "row": row})
        system = """You are ARIA v3's evidence-bound SOC Triage Agent.
Return a conservative triage decision using only the supplied bounded evidence.
Rules:
- A model opinion is not evidence.
- Event volume or entity presence alone cannot create TRUE_POSITIVE or FALSE_POSITIVE.
- TRUE_POSITIVE requires returned rows that directly support harmful or policy-violating behaviour and should normally include corroboration.
- FALSE_POSITIVE or BENIGN_OR_EXPECTED requires returned evidence supporting an expected explanation.
- Use SUSPICIOUS when evidence is concerning but incomplete.
- Otherwise use INSUFFICIENT_EVIDENCE.
- Confidence must reflect evidence quality and gaps.
- reasoning must be fewer than 50 words.
- supporting_evidence and contradicting_evidence must reference supplied ROW-* identifiers.
Return only the TriageDecision schema."""
        try:
            decision = self.ollama.structured_chat(
                system_prompt=system,
                user_prompt=(
                    f"Analyst triage request:\n{question}\n\nSubject value: {value or 'current investigation'}\n\n"
                    f"Bounded evidence:\n{json.dumps(evidence_payload, ensure_ascii=False, default=str)[:18000]}"
                ),
                response_model=TriageDecision,
                model_role="reasoning",
                num_predict=650,
                timeout=int(os.getenv("ARIA_V3_TRIAGE_REASONING_TIMEOUT_SECONDS", "75")),
            )
            valid_refs = {item["evidence_id"] for item in evidence_payload}
            decision.supporting_evidence = [ref for ref in decision.supporting_evidence if ref in valid_refs]
            decision.contradicting_evidence = [ref for ref in decision.contradicting_evidence if ref in valid_refs]
            if decision.verdict in {"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_OR_EXPECTED"} and not decision.supporting_evidence:
                decision.verdict = "INSUFFICIENT_EVIDENCE"
                decision.confidence = min(decision.confidence, 30)
                decision.evidence_gaps.append("No evidence identifiers supported the proposed definitive verdict")
            if not decision.supporting_evidence:
                decision.supporting_evidence = [
                    f"ROW-{position}"
                    for position in range(1, min(3, len(rows)) + 1)
                ]
            if not self._has_discriminative_evidence(rows):
                decision.verdict = "INSUFFICIENT_EVIDENCE"
                decision.confidence = min(decision.confidence, 25)
                decision.reasoning = (
                    "Returned rows confirm bounded source activity, but no populated "
                    "behaviour-specific values survived execution. Event volume alone "
                    "cannot establish the requested security conclusion."
                )
                for gap in (
                    "Populated behaviour-specific field values",
                    "Corroborating entity or relationship context",
                ):
                    if gap not in decision.evidence_gaps:
                        decision.evidence_gaps.append(gap)
                decision.next_action = (
                    "Run a read-only query that returns populated behaviour-specific "
                    "fields and relevant entity context."
                )
            elif re.fullmatch(r"[A-Z0-9_]+", str(decision.next_action or "")):
                decision.next_action = (
                    "Run the next evidence-bound read-only query for the identified "
                    "entity, behaviour and time window."
                )
            decision.confidence = max(
                decision.confidence,
                min(35, 10 + len(rows)),
            )
            return decision
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.triage.reasoning")
            return TriageDecision(
                verdict="INSUFFICIENT_EVIDENCE",
                confidence=min(35, 10 + len(rows)),
                reasoning="Bounded evidence was retrieved, but the local triage model was unavailable; ARIA preserved the evidence without inventing a verdict.",
                supporting_evidence=[f"ROW-{position}" for position in range(1, min(3, len(rows)) + 1)],
                evidence_gaps=["Evidence interpretation unavailable", "Analyst validation required"],
                next_action="Review the returned rows and run the highest-value contextual query for the affected entity and time window.",
            )

    @staticmethod
    def _render(question: str, decision: TriageDecision, searches: list[SearchExecutionRecord], rows: list[dict[str, Any]]) -> str:
        lines = [
            "## ARIA v3 Triage Agent", "",
            f"**VERDICT:** `{decision.verdict}`  ",
            f"**CONFIDENCE:** `{decision.confidence}/100`", "",
            f"**REASONING:** {decision.reasoning}", "",
            "## Supporting evidence", "",
            *([f"- `{item}`" for item in decision.supporting_evidence] or ["- No evidence identifier supports a definitive verdict."]), "",
        ]
        if decision.contradicting_evidence:
            lines.extend(["## Contradicting evidence", "", *[f"- `{item}`" for item in decision.contradicting_evidence], ""])
        lines.extend(["## Evidence gaps", "", *([f"- {item}" for item in decision.evidence_gaps] or ["- None recorded"]), ""])
        if searches:
            for search in searches:
                lines.extend([
                    "## Read-only SPL executed", "", "```spl", search.spl, "```", "",
                    f"- Safety gate: `{'PASS' if search.safe else 'BLOCKED'}`",
                    f"- Rows returned: `{len(search.rows)}`", "",
                ])
        if rows:
            headers = list(rows[0].keys())[:8]
            table_rows = [[compact_text(row.get(header, ""), 180) for header in headers] for row in rows[:10]]
            lines.extend(["## Bounded evidence preview", "", markdown_table(headers, table_rows), ""])
        lines.extend([
            "## Recommended next action", "", decision.next_action, "",
            "## Safety boundary", "",
            "- Splunk access remained read-only.",
            "- No risk event, notable, detection or response action was created.",
            "- Definitive verdicts require returned evidence identifiers.",
        ])
        return "\n".join(lines)

    @staticmethod
    def _has_prior_investigation(last_result: Any | None) -> bool:
        if not isinstance(last_result, dict):
            return False
        return str(last_result.get("capability") or "") in {"INVESTIGATION", "QUERY_SPLUNK"}

    @staticmethod
    def _prior_rows(last_result: Any | None) -> list[dict[str, Any]]:
        if not isinstance(last_result, dict):
            return []
        rows: list[dict[str, Any]] = []
        for search in last_result.get("searches") or []:
            if (
                not search.get("safe", True)
                or search.get("execution_error")
                or search.get("qualification_consistent") is False
            ):
                continue
            for row in search.get("rows") or []:
                if isinstance(row, dict):
                    rows.append(row)
        return rows[:100]

    @staticmethod
    def _has_discriminative_evidence(rows: list[dict[str, Any]]) -> bool:
        for row in rows:
            for key, value in row.items():
                name = str(key or "").lower()
                if (
                    name in {"event_count", "sampled_events", "source_event_count"}
                    or name.endswith("_distinct")
                    or name.endswith("_present")
                    or name == "aria_required_all_present"
                ):
                    continue
                if isinstance(value, list):
                    if any(str(item or "").strip() for item in value):
                        return True
                elif str(value or "").strip():
                    return True
        return False

    @staticmethod
    def _explicit_value(question: str) -> str | None:
        patterns = (
            r"\b(?:finding|notable|incident|alert|case)\s+(?:id\s*)?(?:=|:)?\s*[\"']?([A-Za-z0-9_.:@/-]{3,})",
            r"\btriage\s+(?:entity\s+)?[\"']([^\"']{3,})[\"']",
        )
        for pattern in patterns:
            match = re.search(pattern, question, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
