from __future__ import annotations

from typing import Any, Callable

from aria.copilot.contracts import CopilotResult
from aria.ollama_client import OllamaClient
from aria.splunk_client import SplunkClient
from aria.v3.orchestrator import ARIAV3Orchestrator


ProgressCallback = Callable[[str, str, str], None]


class EvidenceFirstCopilotEngine:
    """Compatibility adapter exposing the ARIA v3 multi-agent product path."""

    def __init__(
        self,
        *,
        ollama: OllamaClient | None = None,
        splunk: SplunkClient | None = None,
    ) -> None:
        self.v3 = ARIAV3Orchestrator(ollama=ollama, splunk=splunk)

    def invoke(
        self,
        question: str,
        *,
        history: list[Any] | None = None,
        last_result: Any | None = None,
        progress: ProgressCallback | None = None,
    ) -> CopilotResult:
        return self.v3.invoke(
            question,
            history=history or [],
            last_result=last_result,
            progress=progress,
        )


copilot_engine = EvidenceFirstCopilotEngine()
