from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from aria.copilot.engine import copilot_engine


@dataclass
class RouteDecision:
    capability: str
    topic: str
    route: str
    answer: str | None = None
    run_workflow: bool = False
    context_note: str = ""
    context_actions: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None


class ConversationOrchestrator:
    """Single front door for ARIA's evidence-first SOC copilot engine."""

    def route(
        self,
        question: str,
        last_result: Any | None = None,
        history: list[Any] | None = None,
        progress: Callable[[str, str, str], None] | None = None,
    ) -> RouteDecision:
        result = copilot_engine.invoke(
            question=question,
            history=history or [],
            last_result=last_result,
            progress=progress,
        )
        finding = result.finding.verdict if result.finding else None
        confidence = result.confidence.score if result.confidence else None
        note_parts = ["ARIA used the ARIA v3 multi-agent SOC copilot."]
        if finding:
            note_parts.append(f"Verdict: {finding}.")
        if confidence is not None:
            note_parts.append(f"Evidence confidence: {confidence}/100.")

        return RouteDecision(
            capability=result.capability,
            topic=result.goal,
            route="ARIA_V3_ORCHESTRATOR",
            answer=result.answer,
            run_workflow=False,
            context_note=" ".join(note_parts),
            context_actions=result.context_actions,
            result=result.model_dump(),
        )

    def context_for_workflow_answer(
        self,
        question: str | None = None,
        workflow_result: Any | None = None,
    ) -> tuple[str, list[str]]:
        return (
            "ARIA completed an evidence-first read-only investigation.",
            [
                "Explain the evidence logic",
                "Run the next-best query",
                "Turn validated evidence into a detection candidate",
            ],
        )


conversation_orchestrator = ConversationOrchestrator()
