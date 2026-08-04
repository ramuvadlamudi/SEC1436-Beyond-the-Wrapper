from __future__ import annotations

import re
import time
from typing import Any, Callable

from aria.audit_logger import audit_logger
from aria.copilot.contracts import CopilotResult, InvestigationPlan
from aria.ollama_client import OllamaClient, ollama_client
from aria.spl_validator import StaticSPLValidator, spl_validator
from aria.splunk_client import SplunkClient, splunk_client
from aria.suppressed_exception_logger import log_suppressed_exception
from aria.v3.conversation_agent import ConversationAgent
from aria.v3.deliverable_agent import EvidenceDeliverableAgent
from aria.v3.investigation_agent import InvestigationAgent
from aria.v3.router import V3Router
from aria.v3.spl_builder_agent import SPLBuilderAgent
from aria.v3.telemetry_intelligence import TelemetryIntelligenceService
from aria.v3.triage_agent import TriageAgent
from aria.v3.utils import compact_text, markdown_table


ProgressCallback = Callable[[str, str, str], None]


class ARIAV3Orchestrator:
    """Final ARIA v3 control plane.

    Routing and safety are deterministic. Each product capability is isolated in a
    dedicated agent and shares one deployment telemetry-intelligence service.
    """

    def __init__(
        self,
        *,
        ollama: OllamaClient | None = None,
        splunk: SplunkClient | None = None,
        validator: StaticSPLValidator | None = None,
    ) -> None:
        self.ollama = ollama or ollama_client
        self.splunk = splunk or splunk_client
        self.validator = validator or spl_validator
        self.router = V3Router()
        self.telemetry = TelemetryIntelligenceService(self.splunk, self.ollama)
        self.conversation = ConversationAgent(self.ollama, self.validator)
        self.deliverable = EvidenceDeliverableAgent()
        self.spl_builder = SPLBuilderAgent(self.ollama, self.telemetry, self.validator)
        self.investigation = InvestigationAgent(self.ollama, self.splunk)
        self.triage = TriageAgent(self.ollama, self.splunk, self.validator)

    def invoke(
        self,
        question: str,
        *,
        history: list[Any] | None = None,
        last_result: Any | None = None,
        progress: ProgressCallback | None = None,
    ) -> CopilotResult:
        started = time.monotonic()
        question = str(question or "").strip()
        history = history or []
        if not question:
            raise ValueError("Analyst question is empty.")
        route = self.router.route(question, history=history, last_result=last_result)
        self._emit(progress, "v3_route", "ARIA v3 selected an agent", f"Capability {route.capability}. {route.rationale}")
        try:
            if route.clarification_needed:
                result = self._clarification(question, route.clarifying_question or "What SOC outcome should ARIA deliver?")
            elif route.capability == "IDENTITY":
                result = self.conversation.identity(question)
            elif route.capability == "SAFETY":
                result = self.conversation.safety(question)
            elif route.capability == "SCOPE_GUARD":
                result = self.conversation.scope_guard(question)
            elif route.capability == "SOC_CONVERSATION":
                self._emit(progress, "v3_conversation", "SOC Conversation Agent", "The local model is answering an in-scope security question without querying Splunk.")
                result = self.conversation.conversation(question, history=history)
            elif route.capability == "INVENTORY":
                self._emit(progress, "v3_inventory", "Telemetry Intelligence", "ARIA is querying the connected Splunk catalogue through the read-only service.")
                result = self._inventory(question)
            elif route.capability == "EXPLAIN_SPL":
                self._emit(progress, "v3_spl_review", "SPL Review Agent", "ARIA is reviewing supplied SPL without execution.")
                spl = self._extract_spl(question, last_result=last_result)
                result = (
                    self.conversation.explain_spl(question, spl)
                    if spl
                    else self._clarification(
                        question,
                        "Paste the SPL to review, or first ask the SPL Builder Agent to generate it.",
                    )
                )
            elif route.capability == "BUILD_SPL":
                self._emit(progress, "v3_spl_build", "SPL Builder Agent", "ARIA is producing a semantic portable query and a separately qualified deployment query.")
                result = self.spl_builder.build(
                    question,
                    history=history,
                    last_result=last_result,
                    progress=progress,
                )
            elif route.capability in {
                "DETECTION_ENGINEERING",
                "RISK_SCORING",
                "TDIR_WORKFLOW",
                "SOAR_PLAYBOOK",
            }:
                self._emit(
                    progress,
                    "v3_deliverable",
                    "Evidence Deliverable Agent",
                    "ARIA is reusing the current structured evidence without running a new Splunk search or executing an operational action.",
                )
                result = self.deliverable.create(
                    question,
                    route.capability,
                    last_result=last_result,
                )
            elif route.capability == "TRIAGE":
                self._emit(progress, "v3_triage", "Triage Agent", "ARIA is gathering bounded evidence and producing a traceable triage decision.")
                result = self.triage.triage(question, last_result=last_result, progress=progress)
            else:
                self._emit(progress, "v3_investigation", "Investigation Agent", "ARIA is running the evidence-first read-only investigation workflow.")
                result = self.investigation.investigate(question, progress=progress)

            result.metadata.setdefault("architecture", "ARIA_V3_MULTI_AGENT")
            result.metadata["route"] = route.model_dump()
            result.metadata["duration_seconds"] = round(time.monotonic() - started, 2)
            self._emit(progress, "complete", "Response ready", f"ARIA v3 completed capability {result.capability}.")
            self._audit(question, result, status="success")
            return result
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.orchestrator")
            answer = "\n".join([
                "## ARIA v3 request stopped", "",
                "ARIA did not fabricate evidence or execute a write action.", "",
                f"**Failed agent:** `{route.capability}`  ",
                f"**Error:** `{compact_text(f'{exc.__class__.__name__}: {exc}', 900)}`", "",
                "The failure is isolated to the selected agent. Inventory, safety and other agents remain available through the deterministic control plane.",
            ])
            result = CopilotResult(
                capability="COPILOT_ERROR",
                goal=question,
                answer=answer,
                plan=InvestigationPlan(capability="SOC_CONVERSATION", goal=question, execute_read_only_search=False, requirements=[]),
                context_actions=["Check agent health.", "Review the audit record.", "Retry the isolated capability."],
                metadata={
                    "architecture": "ARIA_V3_MULTI_AGENT",
                    "failed_agent": route.capability,
                    "error_type": exc.__class__.__name__,
                    "duration_seconds": round(time.monotonic() - started, 2),
                },
            )
            self._audit(question, result, status="error")
            return result

    def _inventory(self, question: str) -> CopilotResult:
        catalog = self.telemetry.catalog("0", "now")
        rows = [
            [
                item.get("candidate_id"), item.get("index"), item.get("sourcetype"),
                item.get("event_count"), item.get("first_seen") or "", item.get("last_seen") or "",
            ]
            for item in catalog[:50]
        ]
        answer = "\n".join([
            "## Live Splunk Telemetry Inventory", "",
            "ARIA v3 queried the connected Splunk catalogue in real time. Catalogue presence is source visibility, not proof that a source supports a particular investigation.", "",
            markdown_table(["ID", "Index", "Sourcetype", "Events", "First seen", "Last seen"], rows), "",
            "## Shared telemetry-intelligence layer", "",
            "The same catalogue and profile service is used by the SPL Builder, Investigation and Triage agents. Profiles are cached with freshness controls to avoid repeatedly scanning the deployment.", "",
            "## Boundary", "",
            "- Read-only catalogue query.",
            "- No customer-specific source or field mapping was added by ARIA.",
            "- Source suitability is validated only inside the requesting agent's workflow.",
        ])
        return CopilotResult(
            capability="INVENTORY",
            goal=question,
            answer=answer,
            plan=InvestigationPlan(capability="INVENTORY", goal=question, earliest="0", latest="now", time_range_explicit=True, execute_read_only_search=True, requirements=[]),
            context_actions=[
                "Build SPL using this deployment telemetry.",
                "Start an evidence-first investigation.",
                "Show sources with raw-profile access gaps.",
            ],
            metadata={"agent": "TELEMETRY_INTELLIGENCE_V3", "catalog_rows": len(catalog), "live_splunk_queries": True},
        )

    @staticmethod
    def _extract_spl(question: str, *, last_result: Any | None = None) -> str:
        text = str(question or "")
        fenced = re.search(r"```(?:spl)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL)
        if fenced:
            return fenced.group(1).strip()
        marker = re.search(r"\b(?:explain|review|analyse|analyze|optimise|optimize)\s+(?:this\s+)?spl\s*: ?", text, re.IGNORECASE)
        if marker:
            candidate = text[marker.end():].strip()
            if candidate:
                return candidate
        index_pos = re.search(r"(?:^|\n)\s*(?:search\s+)?index\s*=", text, re.IGNORECASE)
        if index_pos:
            return text[index_pos.start():].strip()

        def as_dict(value: Any | None) -> dict[str, Any]:
            if isinstance(value, dict):
                return value
            if hasattr(value, "model_dump"):
                dumped = value.model_dump()
                return dumped if isinstance(dumped, dict) else {}
            return {}

        def from_result(payload: dict[str, Any], seen: set[int]) -> str:
            if not payload or id(payload) in seen:
                return ""
            seen.add(id(payload))
            metadata = payload.get("metadata") or {}
            for key in ("deployment_spl", "generic_spl"):
                variant = metadata.get(key)
                if isinstance(variant, dict) and str(variant.get("spl") or "").strip():
                    return str(variant["spl"]).strip()
            for search in reversed(payload.get("searches") or []):
                if str(search.get("spl") or "").strip():
                    return str(search["spl"]).strip()
            context = metadata.get("evidence_context")
            if isinstance(context, dict):
                variants = context.get("spl_variants") or {}
                for key in ("deployment", "generic"):
                    variant = variants.get(key)
                    if isinstance(variant, dict) and str(variant.get("spl") or "").strip():
                        return str(variant["spl"]).strip()
                for search in reversed(context.get("searches") or []):
                    if str(search.get("spl") or "").strip():
                        return str(search["spl"]).strip()
            return ""

        return from_result(as_dict(last_result), set())

    @staticmethod
    def _clarification(question: str, prompt: str) -> CopilotResult:
        answer = "\n".join([
            "## ARIA needs one detail", "", prompt, "",
            "No Splunk query was run because the requested product outcome was not clear.",
        ])
        return CopilotResult(
            capability="SOC_CONVERSATION",
            goal=question,
            answer=answer,
            plan=InvestigationPlan(capability="SOC_CONVERSATION", goal=question, execute_read_only_search=False, requirements=[]),
            context_actions=[
                "Explain a security concept.",
                "Build SPL.",
                "Investigate using live Splunk evidence.",
                "Triage a finding.",
            ],
            metadata={"clarification_needed": True, "live_splunk_queries": False},
        )

    @staticmethod
    def _emit(progress: ProgressCallback | None, stage: str, label: str, detail: str = "") -> None:
        if progress is None:
            return
        try:
            progress(stage, label, detail)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.progress")

    @staticmethod
    def _audit(question: str, result: CopilotResult, *, status: str) -> None:
        try:
            audit_logger.log_interaction(
                prompt=question,
                answer=result.answer,
                capability=result.capability,
                route="ARIA_V3_ORCHESTRATOR",
                status=status,
                metadata={
                    "architecture": "ARIA_V3_MULTI_AGENT",
                    "agent": result.metadata.get("agent"),
                    "duration_seconds": result.metadata.get("duration_seconds"),
                    "search_count": len(result.searches),
                    "finding": result.finding.verdict if result.finding else None,
                    "confidence": result.confidence.score if result.confidence else None,
                },
            )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.audit")
