from __future__ import annotations

import re
from typing import Any

from aria.v3.contracts import V3Route
from aria.v3.utils import normalise, tokens


class V3Router:
    """Deterministic control-plane router.

    Local models may enrich an agent response but never decide whether Splunk is
    queried, whether generated SPL is executed, or whether a request is in scope.
    """

    def route(self, question: str, *, history: list[Any] | None = None, last_result: Any | None = None) -> V3Route:
        text = normalise(question)
        token_set = set(tokens(question))

        if not text:
            return V3Route(
                capability="SOC_CONVERSATION",
                clarification_needed=True,
                clarifying_question="What SOC outcome should ARIA deliver?",
                rationale="Empty analyst message.",
            )

        if (
            text in {"hi", "hello", "hey", "who are you", "what are you"}
            or any(phrase in text for phrase in (
                "who are you",
                "what can you do",
                "what can you help me with",
                "what can you help with",
                "how can you help",
                "your capabilities",
                "help me get started",
            ))
        ):
            return V3Route(capability="IDENTITY", rationale="Product identity request.")

        if any(phrase in text for phrase in ("safety boundary", "what can you execute", "security model")):
            return V3Route(capability="SAFETY", rationale="Product safety request.")

        if self._is_out_of_scope(text, token_set):
            return V3Route(capability="SCOPE_GUARD", rationale="Request is unrelated to cybersecurity or Splunk operations.")

        if self._requests_unsafe_action(text):
            return V3Route(
                capability="SAFETY",
                requires_splunk=False,
                execute_search=False,
                rationale="Write-capable or disruptive action request was blocked before agent execution.",
            )

        if self._is_triage(text, token_set):
            return V3Route(capability="TRIAGE", requires_splunk=True, execute_search=True, rationale="Incident or finding triage request.")

        deliverable = self._deliverable_capability(text, token_set)
        if deliverable:
            return V3Route(
                capability=deliverable,
                requires_splunk=False,
                execute_search=False,
                rationale="Evidence-bound analyst deliverable request using the current structured result.",
            )

        if self._is_spl_review(question, text, token_set, last_result):
            return V3Route(capability="EXPLAIN_SPL", rationale="Existing SPL review request.")

        if self._is_build_spl(text):
            execute = self._requests_execution(text)
            if execute:
                return V3Route(capability="INVESTIGATION", requires_splunk=True, execute_search=True, rationale="Explicit build-and-execute request.")
            return V3Route(capability="BUILD_SPL", requires_splunk=False, execute_search=False, rationale="SPL construction request.")

        if (
            self._prior_capability(last_result) == "BUILD_SPL"
            and self._is_build_continuation(text, token_set)
        ):
            return V3Route(
                capability="BUILD_SPL",
                requires_splunk=False,
                execute_search=False,
                rationale="Analyst refinement of the current SPL Builder request.",
            )

        inventory = (
            bool(token_set & {"splunk", "telemetry", "data"})
            and bool(token_set & {"show", "give", "list", "inventory", "available", "discover", "summarise", "summarize"})
            and bool(token_set & {"source", "sources", "index", "indexes", "sourcetype", "sourcetypes", "telemetry", "instance", "data"})
            and not bool(token_set & {"investigate", "hunt", "detect", "validate", "triage"})
        )
        if inventory:
            return V3Route(capability="INVENTORY", requires_splunk=True, rationale="Connected Splunk telemetry inventory request.")

        live_cue = any(phrase in text for phrase in (
            "live splunk", "connected splunk", "splunk evidence", "query splunk", "search splunk",
            "using live telemetry", "use live telemetry", "across all available time", "execute a safe",
        ))
        investigation_cue = bool(token_set & {"investigate", "hunt", "detect", "find", "identify", "validate", "query", "search", "examine"})
        if live_cue or investigation_cue:
            return V3Route(capability="INVESTIGATION", requires_splunk=True, execute_search=True, rationale="Evidence-first investigation request.")

        if any(phrase in text for phrase in ("read only", "read-only")):
            return V3Route(capability="SAFETY", rationale="Product safety request.")

        if text in {"use all available time", "use the last 24 hours", "use the last 7 days"} or text.startswith("use earliest="):
            prior = self._prior_capability(last_result)
            if prior == "BUILD_SPL":
                return V3Route(capability="BUILD_SPL", requires_splunk=True, rationale="Time-range continuation for SPL builder.")

        return V3Route(capability="SOC_CONVERSATION", rationale="In-scope SOC conversational request.")

    @staticmethod
    def _contains_spl(text: str) -> bool:
        return bool(re.search(r"(?:^|\n)\s*(?:search\s+)?(?:index\s*=|\|\s*[a-z][a-z0-9_]*)", str(text or ""), re.IGNORECASE))

    @staticmethod
    def _is_build_spl(text: str) -> bool:
        patterns = (
            r"\bbuild\b.{0,100}\bspl\b",
            r"\bgive\s+me\b.{0,100}\bspl\b",
            r"\bcreate\b.{0,100}\bspl\b",
            r"\bgenerate\b.{0,100}\bspl\b",
            r"\bwrite\b.{0,100}\bspl\b",
            r"\btranslate\b.*\binto\s+spl\b",
        )
        return any(re.search(pattern, text) for pattern in patterns)

    @classmethod
    def _is_spl_review(
        cls,
        question: str,
        text: str,
        token_set: set[str],
        last_result: Any | None,
    ) -> bool:
        review_verb = bool(
            token_set
            & {"explain", "review", "analyse", "analyze", "optimise", "optimize"}
        )
        if not review_verb:
            return False
        if "explain spl" in text or "review spl" in text:
            return True
        if re.search(
            r"\b(?:explain|review|analyse|analyze|optimise|optimize)\b"
            r".{0,50}\b(?:generated|current|previous|supplied|this)\s+spl\b",
            text,
        ):
            return True
        if "spl" not in token_set:
            return False
        if cls._contains_spl(question):
            return True
        return cls._prior_capability(last_result) in {
            "BUILD_SPL",
            "INVESTIGATION",
            "DETECTION_ENGINEERING",
        }

    @staticmethod
    def _is_build_continuation(text: str, token_set: set[str]) -> bool:
        if token_set & {
            "investigate",
            "triage",
            "review",
            "explain",
            "rba",
            "ers",
            "tdir",
            "soar",
            "playbook",
        }:
            return False
        refinement_terms = {
            "add",
            "apply",
            "change",
            "distinct",
            "earliest",
            "entities",
            "entity",
            "field",
            "fields",
            "filter",
            "group",
            "latest",
            "limit",
            "observation",
            "parent",
            "refine",
            "sourcetype",
            "threshold",
            "thresholds",
            "window",
        }
        return bool(token_set & refinement_terms) or text.startswith(
            ("use ", "add ", "apply ", "change ", "refine ", "limit ", "group ")
        )

    @staticmethod
    def _requests_execution(text: str) -> bool:
        """Return True only for an affirmative request to run generated SPL.

        BUILD_SPL prompts commonly state the safety boundary as "do not execute"
        or "without running". A bare keyword check turns those negative
        instructions into execution authority, so every run/execute occurrence
        is evaluated with its local negation context.
        """

        for match in re.finditer(r"\b(?:execute|executing|run|running)\b", text):
            prefix = text[max(0, match.start() - 80):match.start()]
            negated = re.search(
                r"(?:\bdo\s+not|\bdon't|\bnever|\bmust\s+not|\bshould\s+not|\bwithout)"
                r"\s+(?:\w+\s+){0,3}$",
                prefix,
            )
            if not negated:
                return True
        return False

    @classmethod
    def _requests_unsafe_action(cls, text: str) -> bool:
        patterns = (
            r"\b(?:delete|deletes|deleted|deleting|erase|remove|purge)\b.{0,80}\bevents?\b",
            r"\b(?:outputlookup|outputcsv|collect|mcollect|sendalert|map)\b",
            r"\b(?:create|write|update|submit)\b.{0,60}\b(?:risk\s+event|notable|lookup)\b",
            r"\b(?:contain|isolate|disable|block|quarantine)\b.{0,60}\b(?:host|user|account|endpoint|entity|system)\b",
            r"\b(?:execute|run|start)\b.{0,60}\b(?:response\s+action|soar\s+playbook|playbook)\b",
        )
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                prefix = text[max(0, match.start() - 90):match.start()]
                if not re.search(
                    r"(?:\bdo\s+not|\bdon't|\bnever|\bmust\s+not|\bshould\s+not|\bwithout)"
                    r"(?:\s+\w+){0,6}\s*$",
                    prefix,
                ):
                    return True
        return False

    @staticmethod
    def _deliverable_capability(text: str, token_set: set[str]) -> str | None:
        if (
            "soar" in token_set
            and token_set & {"playbook", "workflow", "draft", "create"}
        ):
            return "SOAR_PLAYBOOK"
        if "tdir" in token_set or (
            "response" in token_set and "workflow" in token_set
        ):
            return "TDIR_WORKFLOW"
        if (
            token_set & {"rba", "ers"}
            or "entity risk scoring" in text
            or "risk scoring" in text
        ):
            return "RISK_SCORING"
        if (
            "detection" in token_set
            and token_set & {"build", "create", "draft", "candidate", "engineer"}
        ):
            return "DETECTION_ENGINEERING"
        return None

    @staticmethod
    def _is_triage(text: str, token_set: set[str]) -> bool:
        if "triage" in token_set:
            return True
        return any(phrase in text for phrase in (
            "true positive", "false positive", "verdict and confidence", "triage this finding",
            "triage this notable", "incident id", "notable id", "finding id",
        ))

    @staticmethod
    def _prior_capability(last_result: Any | None) -> str:
        if isinstance(last_result, dict):
            return str(last_result.get("capability") or "")
        return str(getattr(last_result, "capability", "") or "")

    @staticmethod
    def _is_out_of_scope(text: str, token_set: set[str]) -> bool:
        secops = token_set & {
            "security", "cyber", "cybersecurity", "soc", "splunk", "siem", "incident", "alert",
            "detection", "malware", "phishing", "authentication", "dns", "network", "endpoint",
            "threat", "risk", "notable", "finding", "triage", "spl", "log", "logs", "telemetry",
        }
        if secops:
            return False
        typo_normalised = text.replace("reciepe", "recipe").replace("receipe", "recipe")
        unrelated = (
            "recipe", "cook", "cooking", "poem", "holiday", "vacation", "gym", "workout",
            "noodles", "butter chicken", "restaurant", "weather", "movie", "song",
        )
        return any(term in typo_normalised for term in unrelated)
