from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from typing import Any

from aria.copilot.contracts import IntentRoute
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import compact_text
from aria.ollama_client import OllamaClient
from aria.suppressed_exception_logger import log_suppressed_exception


class LLMIntentRouter:
    """Reliable intent router with an optional local-model refinement path.

    The control plane does not depend on a generative model. Unambiguous product
    intents are resolved deterministically before any telemetry action. The local
    model is used only for genuinely ambiguous prose and can never turn a timeout
    into a product-wide COPILOT_ERROR.

    The deterministic rules describe product capabilities and language grammar;
    they do not contain customer indexes, sourcetypes, fields, event IDs, entity
    values, vendors, thresholds, or security-use-case-to-telemetry mappings.
    """

    LIVE_CAPABILITIES = {
        "INVENTORY",
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

    CONVERSATIONAL_CAPABILITIES = {
        "IDENTITY",
        "SAFETY",
        "SOC_CONVERSATION",
        "EXPLAIN_SPL",
        "BUILD_SPL",
        "SCOPE_GUARD",
    }

    SPL_PIPE_COMMANDS = {
        "search", "tstats", "stats", "chart", "timechart", "table", "fields",
        "where", "eval", "rex", "rename", "dedup", "sort", "head", "tail",
        "bin", "bucket", "eventstats", "streamstats", "transaction", "join",
        "append", "appendcols", "lookup", "inputlookup", "datamodel", "from",
        "makeresults", "spath", "mvexpand", "fillnull", "convert", "top", "rare",
    }

    # Product-domain vocabulary only. This is not a use-case-to-data map.
    SECOPS_TERMS = {
        "security", "cyber", "cybersecurity", "secops", "soc", "threat", "attack",
        "attacker", "adversary", "incident", "alert", "detection", "triage", "hunt",
        "malware", "ransomware", "phishing", "exploit", "vulnerability", "dns",
        "network", "firewall", "proxy", "endpoint", "identity", "authentication",
        "authorisation", "authorization", "account", "credential", "cloud", "siem",
        "soar", "splunk", "spl", "telemetry", "log", "logs", "event", "events",
        "risk", "rba", "ers", "mitre", "atlas", "ttp", "ioc", "c2", "tunneling",
        "tunnelling", "ddos", "dos", "exfiltration", "persistence", "lateral",
        "privilege", "command", "process", "host", "ip", "domain", "certificate",
    }

    OUT_OF_SCOPE_TERMS = {
        "recipe", "cooking", "cook", "ingredient", "restaurant", "holiday",
        "vacation", "fashion", "movie", "music", "horoscope", "gardening",
        "workout", "dating", "celebrity", "sports score", "shopping list",
    }

    def __init__(self, ollama: OllamaClient) -> None:
        self.ollama = ollama

    def route(
        self,
        question: str,
        *,
        history: list[Any] | None = None,
        last_result: Any | None = None,
    ) -> IntentRoute:
        text = str(question or "").strip()
        if not text:
            return self._clarification_route("Please enter a SecOps question or Splunk task.")

        contextual_followup = self.is_contextual_followup(text)
        routed_history = (history or []) if contextual_followup else []
        routed_result = last_result if contextual_followup else None

        deterministic = self._deterministic_route(
            text,
            history=routed_history,
            last_result=routed_result,
        )
        if deterministic is not None:
            return self._normalise(deterministic)

        # Ambiguous prose receives a bounded local-model attempt. A timeout is a
        # recoverable classification gap, not a fatal request error.
        try:
            route = self.ollama.structured_chat(
                system_prompt=self._llm_system_prompt(),
                user_prompt=self._llm_user_prompt(
                    text,
                    routed_history,
                    routed_result,
                    contextual_followup,
                ),
                response_model=IntentRoute,
                model_role="fast",
                num_predict=420,
                timeout=int(evidence_policy().get("intent_model_timeout_seconds", 20)),
            )
            route.goal = compact_text(text, 800) or route.goal
            return self._normalise(self._quality_guard(text, route))
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.intent_router.optional_llm")
            return self._normalise(self._safe_ambiguous_fallback(text))

    def _deterministic_route(
        self,
        question: str,
        *,
        history: list[Any],
        last_result: Any | None,
    ) -> IntentRoute | None:
        normalised = " ".join(question.lower().split())
        tokens = set(re.findall(r"[a-z0-9]+", normalised))
        actual_spl = self._looks_like_spl(question)
        build_spl = self._is_build_spl_request(question)

        if self._awaiting_build_time_range(last_result) and self._contains_time_range(question):
            return self._route(
                "BUILD_SPL", "SPL_BUILD", question, False,
                "The analyst supplied the missing time range for the prior dual SPL build request.",
                followups=[
                    "Execute the live-qualified SPL as a safe bounded search.",
                    "Explain the differences between the generic and live-qualified SPL.",
                    "Change the time range and rebuild both SPL variants.",
                ],
            )

        if re.fullmatch(
            r"(?:hi|hello|hey|greetings|good morning|good afternoon|good evening)[!. ]*",
            normalised,
        ):
            return self._route(
                "IDENTITY", "CONVERSATION", question, False,
                "Deterministic greeting route; no telemetry access required.",
                followups=[
                    "Show me ARIA's SOC copilot capabilities.",
                    "Explain a cybersecurity concept.",
                    "Show available Splunk telemetry.",
                    "Start an evidence-first investigation.",
                ],
            )

        if any(phrase in normalised for phrase in (
            "who are you", "what can you do", "your capabilities",
            "how can you help", "help me get started",
        )):
            return self._route(
                "IDENTITY", "CONVERSATION", question, False,
                "Deterministic identity/capability route.",
            )

        if any(phrase in normalised for phrase in (
            "safety boundary", "safety boundaries", "guardrails",
            "what will you not do", "read-only boundary", "security model",
        )):
            return self._route(
                "SAFETY", "CONVERSATION", question, False,
                "Deterministic product-safety route.",
            )

        if build_spl:
            if self._requests_live_execution(question):
                return self._live_route(
                    "QUERY_SPLUNK",
                    question,
                    "The analyst asked ARIA to build and validate or execute SPL against live Splunk.",
                )
            return self._route(
                "BUILD_SPL", "SPL_BUILD", question, False,
                "Explicit natural-language-to-SPL build request; no live execution requested.",
                followups=[
                    "Validate this SPL against live telemetry.",
                    "Add exact analyst-supplied filter conditions.",
                    "Explain the generated SPL.",
                    "Run a safe bounded version.",
                ],
            )

        if actual_spl:
            return self._route(
                "EXPLAIN_SPL", "SPL_EXPLANATION", question, False,
                "The current message contains actual SPL grammar.",
                followups=[
                    "Optimise this SPL.",
                    "Validate this SPL against live telemetry.",
                    "Run a safe bounded version.",
                ],
            )

        # Explicit product deliverables are capability grammar, not scenarios.
        if "soar" in tokens and any(term in tokens for term in {"playbook", "workflow", "draft", "create"}):
            return self._live_route("SOAR_PLAYBOOK", question, "Explicit SOAR deliverable request.")
        if "tdir" in tokens or ("response" in tokens and "workflow" in tokens):
            return self._live_route("TDIR_WORKFLOW", question, "Explicit TDIR/response workflow request.")
        if "rba" in tokens or "ers" in tokens or ("risk" in tokens and "score" in tokens):
            return self._live_route("RISK_SCORING", question, "Explicit risk-scoring deliverable request.")
        if "detection" in tokens and any(term in tokens for term in {"build", "create", "draft", "candidate", "engineer"}):
            return self._live_route("DETECTION_ENGINEERING", question, "Explicit detection-engineering request.")

        inventory_cues = (
            ("splunk" in tokens or "telemetry" in tokens)
            and any(term in tokens for term in {"available", "inventory", "list", "show", "give", "discover"})
            and any(term in tokens for term in {"data", "telemetry", "source", "sources", "index", "indexes", "sourcetype", "sourcetypes", "instance"})
            and not bool(tokens & {"investigate", "detect", "hunt", "analyse", "analyze", "test", "validate"})
        )
        if inventory_cues:
            return self._route(
                "INVENTORY", "LIVE_EVIDENCE", question, True,
                "Direct connected-Splunk inventory request.",
                evidence_plan=False,
                followups=[
                    "Summarise the available telemetry by index.",
                    "Show the most active source groups.",
                    "Use this inventory for an evidence-first investigation.",
                ],
            )

        live_cues = any(phrase in normalised for phrase in (
            "live splunk", "connected splunk", "splunk instance", "my environment",
            "our environment", "query splunk", "search splunk", "use splunk evidence",
            "using splunk evidence", "live telemetry", "execute the search",
            "run the search", "run this search", "across all available time",
        ))
        action_cues = bool(tokens & {
            "investigate", "find", "identify", "detect", "hunt", "query", "search",
            "validate", "analyse", "analyze", "show", "discover", "examine", "test",
        })
        if live_cues and action_cues:
            capability = "THREAT_ANALYSIS" if any(
                phrase in normalised for phrase in ("test hypothesis", "test a hypothesis", "threat analysis")
            ) else "QUERY_SPLUNK"
            return self._live_route(
                capability,
                question,
                "Explicit live-evidence request; generative routing is not required.",
            )

        # Explicit follow-ups can inherit a prior live context without inheriting
        # stale scope decisions or goals.
        if self.is_contextual_followup(question) and last_result:
            if any(term in tokens for term in {"query", "search", "investigate", "validate", "run", "test"}):
                return self._live_route(
                    "QUERY_SPLUNK",
                    question,
                    "Explicit contextual follow-up requesting live evidence.",
                )

        conceptual_opening = bool(re.match(
            r"^(?:explain|compare|describe|define|what is|what are|how does|how do|why does|why is|tell me about)\b",
            normalised,
        ))
        security_overlap = bool(tokens & self.SECOPS_TERMS)
        if conceptual_opening and security_overlap:
            return self._route(
                "SOC_CONVERSATION", "CONVERSATION", question, False,
                "Conceptual SecOps question; no live evidence was requested.",
                followups=[
                    "Show how this could be investigated with live Splunk evidence.",
                    "Turn this into a defender-focused threat hypothesis.",
                    "Explain the telemetry a SOC would need.",
                    "Summarise this for a SOC analyst.",
                ],
            )

        if self._has_out_of_scope_signal(normalised, tokens) and not security_overlap:
            return self._route(
                "SCOPE_GUARD", "DOMAIN_REDIRECT", question, False,
                "The request is unrelated to SecOps or Splunk.",
                domain="OUT_OF_SCOPE",
                followups=[
                    "Explain a cybersecurity concept.",
                    "Explain or optimise an SPL search.",
                    "Show available Splunk telemetry.",
                    "Start an evidence-first security investigation.",
                ],
            )

        # Domain vocabulary is enough to keep a security question conversational,
        # but does not imply live Splunk access.
        if security_overlap:
            return self._route(
                "SOC_CONVERSATION", "CONVERSATION", question, False,
                "SecOps-domain prose without an explicit live-evidence request.",
            )

        return None


    @classmethod
    def _has_out_of_scope_signal(cls, normalised: str, tokens: set[str]) -> bool:
        """Return True for clear non-SecOps scope signals, including minor typos.

        This is product-domain grammar, not scenario routing. Exact phrases are
        checked first. Single-word scope terms of five or more characters then
        receive a conservative typo-tolerant comparison. The comparison never
        grants Splunk access and is ignored when SecOps vocabulary is present.
        """
        if any(term in normalised for term in cls.OUT_OF_SCOPE_TERMS):
            return True

        candidates = {
            term for term in cls.OUT_OF_SCOPE_TERMS
            if " " not in term and len(term) >= 5
        }
        for token in tokens:
            if len(token) < 5:
                continue
            for candidate in candidates:
                threshold = 0.90 if min(len(token), len(candidate)) <= 6 else 0.86
                if SequenceMatcher(None, token, candidate).ratio() >= threshold:
                    return True
        return False

    def _quality_guard(self, question: str, route: IntentRoute) -> IntentRoute:
        """Enforce route-shape invariants after optional model classification."""
        route.goal = compact_text(question, 800) or route.goal
        if self._is_build_spl_request(question):
            if self._requests_live_execution(question):
                return self._live_route(
                    "QUERY_SPLUNK",
                    question,
                    "Explicit build-and-execute language overrides an incompatible model route.",
                )
            return self._route(
                "BUILD_SPL", "SPL_BUILD", question, False,
                "Explicit SPL build language overrides an incompatible model route.",
            )
        if self._looks_like_spl(question):
            return self._route(
                "EXPLAIN_SPL", "SPL_EXPLANATION", question, False,
                "Actual SPL grammar overrides an incompatible model route.",
            )
        normalised = " ".join(question.lower().split())
        if any(phrase in normalised for phrase in (
            "live splunk", "connected splunk", "splunk instance", "my environment",
            "our environment", "use splunk evidence", "using splunk evidence",
        )):
            if route.capability in self.CONVERSATIONAL_CAPABILITIES:
                return self._live_route(
                    "QUERY_SPLUNK",
                    question,
                    "Explicit live-evidence language overrides a conversational model route.",
                )
        return route

    def _safe_ambiguous_fallback(self, question: str) -> IntentRoute:
        return IntentRoute(
            capability="SOC_CONVERSATION",
            domain_scope="SECOPS",
            mode="CONVERSATION",
            goal=compact_text(question, 800),
            requires_live_splunk=False,
            requires_evidence_plan=False,
            clarification_needed=True,
            clarifying_question=(
                "Should ARIA provide a conceptual SecOps explanation, review supplied SPL, "
                "or query the connected Splunk instance using read-only evidence?"
            ),
            response_depth="brief",
            routing_confidence=35,
            routing_summary=(
                "The optional local intent model was unavailable and the message did not "
                "contain an unambiguous product intent. ARIA failed safely without querying Splunk."
            ),
            suggested_followups=[
                "Explain this as a SecOps concept.",
                "Review the SPL I provide.",
                "Query the connected Splunk instance.",
            ],
        )

    def _clarification_route(self, prompt: str) -> IntentRoute:
        route = self._safe_ambiguous_fallback(prompt)
        route.clarifying_question = prompt
        return route

    def _route(
        self,
        capability: str,
        mode: str,
        goal: str,
        live: bool,
        summary: str,
        *,
        domain: str = "SECOPS",
        evidence_plan: bool | None = None,
        followups: list[str] | None = None,
    ) -> IntentRoute:
        return IntentRoute(
            capability=capability,  # type: ignore[arg-type]
            domain_scope=domain,  # type: ignore[arg-type]
            mode=mode,  # type: ignore[arg-type]
            goal=compact_text(goal, 800),
            requires_live_splunk=live,
            requires_evidence_plan=(live and capability != "INVENTORY") if evidence_plan is None else evidence_plan,
            generic_template_only=False,
            unsafe_action_requested=False,
            clarification_needed=False,
            response_depth="standard",
            routing_confidence=98,
            routing_summary=summary,
            suggested_followups=(followups or []),
        )

    def _live_route(self, capability: str, goal: str, summary: str) -> IntentRoute:
        return self._route(
            capability,
            "LIVE_EVIDENCE",
            goal,
            True,
            summary,
            evidence_plan=(capability != "INVENTORY"),
        )

    def _normalise(self, route: IntentRoute) -> IntentRoute:
        if route.domain_scope == "OUT_OF_SCOPE" or route.mode == "DOMAIN_REDIRECT":
            route.capability = "SCOPE_GUARD"
            route.mode = "DOMAIN_REDIRECT"
            route.requires_live_splunk = False
            route.requires_evidence_plan = False
        elif route.capability in self.CONVERSATIONAL_CAPABILITIES:
            route.requires_live_splunk = False
            route.requires_evidence_plan = False
            if route.capability == "EXPLAIN_SPL":
                route.mode = "SPL_EXPLANATION"
            elif route.capability == "BUILD_SPL":
                route.mode = "SPL_BUILD"
            else:
                route.mode = "CONVERSATION"
        elif route.capability in self.LIVE_CAPABILITIES and not route.generic_template_only:
            route.requires_live_splunk = True
            route.requires_evidence_plan = route.capability != "INVENTORY"
            route.mode = "LIVE_EVIDENCE"

        cleaned: list[str] = []
        for item in route.suggested_followups:
            prompt = " ".join(str(item or "").split()).strip()
            if prompt and prompt.lower() not in {value.lower() for value in cleaned}:
                cleaned.append(prompt)
        route.suggested_followups = cleaned[:4]
        return route


    @classmethod
    def _is_build_spl_request(cls, question: str) -> bool:
        """Recognise explicit natural-language-to-SPL product grammar.

        This is capability routing only. It does not infer telemetry, fields, event
        identifiers, vendors or security scenarios.
        """
        text = " ".join(str(question or "").lower().split()).strip()
        patterns = (
            r"^(?:please\s+)?(?:build|create|generate|write|construct|draft|produce)\s+(?:me\s+)?(?:an?\s+)?spl\b",
            r"^(?:please\s+)?give\s+me\s+(?:an?\s+)?spl\b",
            r"\btranslate\b.+\b(?:into|to)\s+spl\b",
            r"\bnatural[- ]language\s+to\s+spl\b",
            r"\bconvert\b.+\b(?:into|to)\s+spl\b",
        )
        return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)

    @staticmethod
    def _requests_live_execution(question: str) -> bool:
        text = " ".join(str(question or "").lower().split()).strip()
        phrases = (
            "build and run", "build and execute", "generate and run",
            "generate and execute", "create and run", "create and execute",
            "run the generated spl", "execute the generated spl",
            "run it in splunk", "execute it in splunk", "execute the spl",
        )
        return any(phrase in text for phrase in phrases)

    @staticmethod
    def _awaiting_build_time_range(last_result: Any | None) -> bool:
        if not last_result:
            return False
        if hasattr(last_result, "model_dump"):
            try:
                last_result = last_result.model_dump()
            except Exception:
                return False
        if not isinstance(last_result, dict):
            return False
        metadata = last_result.get("metadata") or {}
        return (
            str(last_result.get("capability") or "").upper() == "BUILD_SPL"
            and bool(metadata.get("awaiting_time_range"))
        )

    @staticmethod
    def _contains_time_range(question: str) -> bool:
        text = " ".join(str(question or "").lower().split())
        if re.search(r"\b(?:earliest|latest)\s*=", text):
            return True
        if any(phrase in text for phrase in (
            "all available time", "all historical time", "across all time",
            "from the beginning", "earliest available",
        )):
            return True
        return bool(re.search(
            r"\b(?:last|past)\s+[1-9][0-9]{0,3}\s*(?:seconds?|minutes?|hours?|days?|weeks?)\b",
            text,
        ))

    @classmethod
    def is_contextual_followup(cls, question: str) -> bool:
        text = " ".join(str(question or "").lower().split()).strip()
        if not text:
            return False
        if cls._contains_time_range(text):
            return True
        if re.match(r"^(?:and|also|then|now|next|so|but)\b", text):
            return True
        references = (
            "use the previous", "use previous", "based on that", "based on this",
            "from that", "from this", "continue", "follow up", "follow-up",
            "same search", "same source", "same entity", "that result", "those results",
            "previous result", "previous search", "previous evidence", "the above",
            "earlier result", "turn this", "turn that", "summarise this",
            "summarize this", "investigate it", "validate it", "run it",
            "optimise it", "optimize it", "explain it", "what about", "how about",
        )
        return any(reference in text for reference in references)

    @classmethod
    def _looks_like_spl(cls, question: str) -> bool:
        text = str(question or "")
        lower = text.lower()
        if re.search(r"```\s*spl\b", lower):
            return True
        if re.search(r"\bindex\s*=\s*[^\s|]+", lower):
            return True
        if re.search(r"\bearliest\s*=\s*[^\s|]+", lower) and "|" in text:
            return True
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        for line in lines:
            candidate = line.lstrip("|").strip()
            first = candidate.split(None, 1)[0].lower() if candidate else ""
            if line.startswith("|") and first in cls.SPL_PIPE_COMMANDS:
                return True
            if first in {"search", "tstats", "from", "makeresults", "datamodel"}:
                if "=" in candidate or "|" in text or first in {"tstats", "makeresults", "datamodel"}:
                    return True
        if "|" in text:
            for stage in [part.strip() for part in text.split("|")[1:]]:
                first = stage.split(None, 1)[0].lower() if stage else ""
                if first in cls.SPL_PIPE_COMMANDS:
                    return True
        return False

    @staticmethod
    def _history_text(history: list[Any]) -> str:
        lines: list[str] = []
        for item in history[-6:]:
            if isinstance(item, dict):
                role = str(item.get("role") or "message")
                content = compact_text(item.get("content"), 400)
            else:
                role = "message"
                content = compact_text(item, 400)
            if content:
                lines.append(f"{role}: {content}")
        return "\n".join(lines)

    @staticmethod
    def _result_text(last_result: Any | None) -> str:
        if not last_result:
            return ""
        try:
            if isinstance(last_result, dict):
                compact = {
                    "capability": last_result.get("capability"),
                    "goal": last_result.get("goal"),
                    "finding": last_result.get("finding"),
                    "confidence": last_result.get("confidence"),
                }
                return compact_text(json.dumps(compact, ensure_ascii=False), 1200)
            return compact_text(last_result, 1200)
        except Exception:
            return compact_text(last_result, 1200)

    @staticmethod
    def _llm_system_prompt() -> str:
        return """You are ARIA's optional ambiguity resolver for an air-gapped Splunk SOC copilot.
Choose one product capability. Do not invent customer telemetry or results.
Use IDENTITY for greetings/capabilities, SAFETY for product boundaries, SOC_CONVERSATION for conceptual cybersecurity discussion, EXPLAIN_SPL only when actual SPL is supplied, BUILD_SPL for an explicit natural-language request to build or generate SPL without execution, INVENTORY for available connected Splunk data, QUERY_SPLUNK for live natural-language searches or build-and-execute requests, INVESTIGATE_ENTITY only for a supplied entity, and SCOPE_GUARD for unrelated general-purpose requests.
Ambiguous prose must not default to live Splunk. Return only the IntentRoute schema."""

    def _llm_user_prompt(
        self,
        question: str,
        history: list[Any],
        last_result: Any | None,
        contextual: bool,
    ) -> str:
        return f"""Current analyst message:\n{question}\n\nContext mode: {'FOLLOW_UP' if contextual else 'STANDALONE'}\n\nRecent context:\n{self._history_text(history) or 'None'}\n\nActive result:\n{self._result_text(last_result) or 'None'}"""
