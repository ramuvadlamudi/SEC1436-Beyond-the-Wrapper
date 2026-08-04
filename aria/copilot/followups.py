from __future__ import annotations

import json
from typing import Any

from aria.copilot.contracts import CopilotResult, FollowUpSuggestionSet, IntentRoute
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import compact_text
from aria.ollama_client import OllamaClient
from aria.suppressed_exception_logger import log_suppressed_exception


class ResponseFollowUpAgent:
    """Produces concise follow-up prompts grounded in the completed response."""

    def __init__(self, ollama: OllamaClient) -> None:
        self.ollama = ollama

    def suggest(
        self,
        *,
        question: str,
        route: IntentRoute,
        result: CopilotResult,
    ) -> list[str]:
        if route.capability == "SCOPE_GUARD":
            return [
                "Explain a cybersecurity concept.",
                "Explain or optimise an SPL search.",
                "Query Splunk using natural language.",
                "Start an evidence-first security investigation.",
            ]

        seeds: list[str] = []
        if result.finding and result.finding.next_best_query_goal:
            seeds.append(result.finding.next_best_query_goal)
        seeds.extend(result.context_actions)
        seeds.extend(route.suggested_followups)

        # Conversational answers already received LLM-generated suggestions from
        # the intent router. Evidence responses benefit from a second bounded pass
        # because the outcome was unknown when initial routing occurred.
        policy = evidence_policy()
        needs_outcome_alignment = bool(result.finding or result.searches or result.source_evidence)
        if needs_outcome_alignment and bool(policy.get("followup_llm_enabled", False)):
            try:
                summary = {
                    "analyst_question": question,
                    "capability": result.capability,
                    "goal": result.goal,
                    "verdict": result.finding.verdict if result.finding else None,
                    "summary": result.finding.summary if result.finding else None,
                    "missing_evidence": result.finding.missing_evidence if result.finding else [],
                    "next_best_query_goal": result.finding.next_best_query_goal if result.finding else None,
                    "confidence": result.confidence.score if result.confidence else None,
                    "searches_executed": len(result.searches),
                    "accepted_sources": sum(1 for item in result.source_evidence if item.accepted),
                }
                suggestions = self.ollama.structured_chat(
                    system_prompt="""You create follow-up prompt chips for an air-gapped SOC copilot.
Return 3 or 4 concise prompts the analyst can send next.
They must be directly aligned to the completed result, its evidence gaps and its next-best action.
Do not claim evidence that was not returned. Do not request autonomous write actions.
When evidence is insufficient, prefer clarification, time-range refinement, entity/value input, telemetry validation or the next defensible read-only query.
When evidence exists, prefer a useful pivot, explanation, baseline comparison or evidence-bound deliverable.
Return only the FollowUpSuggestionSet schema.""",
                    user_prompt=json.dumps(summary, ensure_ascii=False, indent=2),
                    response_model=FollowUpSuggestionSet,
                    model_role="fast",
                    num_predict=320,
                    timeout=int(policy.get("followup_model_timeout_seconds", 20)),
                )
                seeds = list(suggestions.prompts) + seeds
            except Exception as exc:
                log_suppressed_exception(exc, component="aria.copilot.followups")

        if not seeds:
            fallback_by_capability = {
                "IDENTITY": [
                    "Show me ARIA's SOC copilot capabilities.",
                    "Explain an SPL search.",
                    "Query Splunk using natural language.",
                    "Describe the evidence-first investigation workflow.",
                ],
                "SAFETY": [
                    "Explain ARIA's read-only Splunk boundary.",
                    "Show how analyst approval gates TDIR actions.",
                    "Describe the SPL safety policy.",
                    "Explain how evidence prevents unsupported conclusions.",
                ],
                "EXPLAIN_SPL": [
                    "Validate this SPL against live telemetry.",
                    "Optimise this SPL.",
                    "Run a safe bounded version.",
                    "Turn the validated logic into a detection candidate.",
                ],
                "SOC_CONVERSATION": [
                    "Show how this security concept could be investigated with live Splunk evidence.",
                    "Turn this into a defender-focused threat hypothesis.",
                    "Explain the telemetry a SOC would need to observe this behaviour.",
                    "Summarise this for a SOC analyst.",
                ],
            }
            seeds.extend(fallback_by_capability.get(route.capability, []))

        output: list[str] = []
        seen: set[str] = set()
        for raw in seeds:
            prompt = " ".join(str(raw or "").split()).strip()
            key = prompt.lower()
            if not prompt or key in seen:
                continue
            seen.add(key)
            output.append(compact_text(prompt, 240))
            if len(output) >= 4:
                break
        return output
