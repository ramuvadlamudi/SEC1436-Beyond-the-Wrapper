from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from aria.copilot.policy import evidence_policy
from aria.copilot.utils import compact_text, safe_time, spl_quote
from aria.ollama_client import OllamaClient
from aria.spl_validator import StaticSPLValidator
from aria.suppressed_exception_logger import log_suppressed_exception


_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_.:/-]{1,240}$")
_PLACEHOLDER_PATTERN = re.compile(r"\{[A-Z][A-Z0-9_]{1,80}\}")

_INTENT_STOP_WORDS = {
    "a", "an", "and", "all", "analyse", "analyze", "analysing", "analyzing",
    "activity", "behaviour", "behavior", "build", "create", "detect", "detection",
    "event", "events", "execute", "execution", "for", "from", "generate", "give",
    "in", "investigate", "investigation", "me", "of", "on", "or", "please",
    "query", "search", "spl", "splunk", "the", "this", "to", "using", "with",
    "unusual", "suspicious", "specific", "specified", "time", "range", "use", "available",
}


class GenericSPLProposal(BaseModel):
    intent_summary: str
    spl: str
    assumptions: list[str] = Field(default_factory=list)
    unresolved_inputs: list[str] = Field(default_factory=list)


@dataclass
class SPLBuildOutcome:
    spl: str
    executable: bool
    safety_status: str
    safety_errors: list[str] = field(default_factory=list)
    resolved_bindings: dict[str, str] = field(default_factory=dict)
    unresolved_bindings: list[str] = field(default_factory=list)
    preserved_conditions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    intent_summary: str = ""
    generation_path: str = "DETERMINISTIC_FALLBACK"
    time_range_explicit: bool = False


class DeterministicSPLBuilder:
    """Build a generic intent SPL without inventing environment facts.

    The local model may design a useful generic pipeline, but unresolved indexes,
    sourcetypes, fields, values and thresholds must remain visible placeholders.
    The deterministic fallback preserves analyst-supplied values and remains
    available when the local model is slow or unavailable.
    """

    def __init__(self, validator: StaticSPLValidator, ollama: OllamaClient | None = None) -> None:
        self.validator = validator
        self.ollama = ollama
        self.policy = evidence_policy()

    def build(self, question: str, *, context: str = "") -> SPLBuildOutcome:
        current = str(question or "").strip()
        contextual = str(context or "").strip()
        combined = self._combine_request(current, contextual)

        index = self._extract_binding(combined, "index")
        sourcetype = self._extract_binding(combined, "sourcetype")
        earliest, latest = self._extract_time(combined)
        time_explicit = bool(earliest or latest)
        conditions = self._extract_explicit_conditions(combined, excluded={index, sourcetype})
        limit = self._extract_limit(combined)
        intent = self.extract_intent(combined)

        fallback = self._deterministic_build(
            combined,
            index=index,
            sourcetype=sourcetype,
            earliest=earliest,
            latest=latest,
            conditions=conditions,
            limit=limit,
            intent=intent,
        )
        if self.ollama is None:
            return fallback

        system = """You are ARIA's generic SPL design agent.

Create a useful read-only SPL draft from the analyst's security intent.

Hard rules:
- This is a generic draft, not a claim about the connected Splunk environment.
- Preserve analyst-supplied index, sourcetype, time values and literal conditions exactly.
- When an index, sourcetype, field, value, threshold or time bound was not supplied, use an uppercase placeholder in braces, for example {INDEX}, {SOURCETYPE}, {ACTIVITY_FIELD}, {ENTITY_FIELD}, {INTENT_CONDITION}, {EARLIEST}, {LATEST}.
- Never invent event IDs, field names, lookup names, data models, vendors, thresholds, ATT&CK mappings or values.
- Literal filter values must come from the analyst request. You may normalise punctuation or case, but you may not add synonyms or related indicators that the analyst did not supply.
- Do not repeat the base search stage. There must be exactly one index/sourcetype/time search stage.
- In table, stats, eval and where clauses, use only placeholders or Splunk metadata fields `_time`, `_raw`, `host`, `source`, and `sourcetype` unless the analyst supplied an exact field name.
- Use placeholders without quotation marks.
- Use only read-only SPL. Do not use collect, mcollect, outputlookup, sendalert, notable, delete, map, rest, script, dbxquery, inputlookup or any action command.
- Produce an analyst-useful pipeline, not merely `head` and `table`, when the intent supports aggregation or filtering.
- Keep the query bounded with head or a bounded aggregation.
- Return only the GenericSPLProposal schema.
"""
        user = f"""Analyst request:
{combined}

Normalised intent:
{intent}

Supplied bindings:
index={index or '{INDEX}'}
sourcetype={sourcetype or '{SOURCETYPE}'}
earliest={earliest or '{EARLIEST}'}
latest={latest or '{LATEST}'}

Literal analyst conditions:
{conditions or ['{CONDITION}']}

Requested result limit:
{limit}
"""
        try:
            proposal = self.ollama.structured_chat(
                system_prompt=system,
                user_prompt=user,
                response_model=GenericSPLProposal,
                model_role="fast",
                num_predict=700,
                timeout=int(self.policy.get("build_spl_generic_timeout_seconds", 45)),
            )
            spl = self._clean_spl(proposal.spl)
            if not spl:
                return fallback
            spl = self._normalise_generic_spl(
                spl,
                index=index,
                sourcetype=sourcetype,
                earliest=earliest,
                latest=latest,
                conditions=conditions,
            )
            if not spl or not self._generic_fields_are_defensible(spl, combined):
                return fallback
            if not self._generic_literals_are_defensible(spl, combined):
                return fallback
            if conditions and not all(condition.lower() in spl.lower() for condition in conditions):
                return fallback
            validation = self.validator.validate(self._placeholder_safe_validation_copy(spl))
            safe = bool(getattr(validation, "safe", False))
            if not safe:
                return fallback

            resolved: dict[str, str] = {}
            if index:
                resolved["index"] = index
            if sourcetype:
                resolved["sourcetype"] = sourcetype
            if earliest:
                resolved["earliest"] = earliest
            if latest:
                resolved["latest"] = latest

            unresolved = list(proposal.unresolved_inputs)
            if not index:
                unresolved.append("index")
            if not sourcetype:
                unresolved.append("sourcetype")
            if not time_explicit:
                unresolved.append("time range")
            if not conditions:
                unresolved.append("detection or filtering condition")
            placeholders = [item.strip("{} ").lower().replace("_", " ") for item in _PLACEHOLDER_PATTERN.findall(spl)]
            unresolved.extend(placeholders)
            executable = not _PLACEHOLDER_PATTERN.search(spl)

            return SPLBuildOutcome(
                spl=spl,
                executable=executable,
                safety_status="PASS" if executable else "NOT_RUN_PLACEHOLDER_TEMPLATE",
                safety_errors=[],
                resolved_bindings=resolved,
                unresolved_bindings=list(dict.fromkeys(item for item in unresolved if item)),
                preserved_conditions=conditions,
                notes=[
                    "The generic draft was designed by the local fast model under deterministic placeholder and safety constraints.",
                    "It does not claim that placeholder fields or values exist in the connected Splunk environment.",
                    "Environment-specific SPL is produced separately only after live source, field and co-occurrence validation.",
                    *[compact_text(item, 300) for item in proposal.assumptions],
                ],
                intent_summary=compact_text(proposal.intent_summary or intent, 400),
                generation_path="LOCAL_LLM_CONSTRAINED_GENERIC",
                time_range_explicit=time_explicit,
            )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.spl_builder.generic_llm")
            return fallback

    def _deterministic_build(
        self,
        text: str,
        *,
        index: str | None,
        sourcetype: str | None,
        earliest: str | None,
        latest: str | None,
        conditions: list[str],
        limit: int,
        intent: str,
    ) -> SPLBuildOutcome:
        resolved: dict[str, str] = {}
        unresolved: list[str] = []
        base_parts = ["search"]

        if index:
            resolved["index"] = index
            base_parts.append(f"index={spl_quote(index)}")
        else:
            unresolved.append("index")
            base_parts.append("index={INDEX}")

        if sourcetype:
            resolved["sourcetype"] = sourcetype
            base_parts.append(f"sourcetype={spl_quote(sourcetype)}")
        else:
            unresolved.append("sourcetype")
            base_parts.append("sourcetype={SOURCETYPE}")

        if earliest:
            resolved["earliest"] = earliest
            base_parts.append(f"earliest={earliest}")
        else:
            unresolved.append("time range")
            base_parts.append("earliest={EARLIEST}")
        if latest:
            resolved["latest"] = latest
            base_parts.append(f"latest={latest}")
        else:
            base_parts.append("latest={LATEST}")

        if conditions:
            base_parts.extend(conditions)
            lines = [
                " ".join(base_parts),
                f"| head {limit}",
                "| table _time host source sourcetype _raw",
            ]
        else:
            terms = self.intent_terms(intent)
            if terms:
                term_conditions = []
                for term in terms[:3]:
                    variants = self.term_variants(term)
                    variant_conditions = []
                    for value in variants[:3]:
                        escaped_value = value.replace("%", "\\%").replace("_", "\\_")
                        pattern = "%" + escaped_value + "%"
                        variant_conditions.append("like(aria_text," + spl_quote(pattern) + ")")
                    term_conditions.append("(" + " OR ".join(variant_conditions) + ")")
                lines = [
                    " ".join(base_parts),
                    "| eval aria_text=lower(tostring(_raw))",
                    "| where " + " AND ".join(term_conditions),
                    "| stats count as event_count earliest(_time) as first_seen latest(_time) as last_seen by host source sourcetype",
                    "| sort - event_count",
                    f"| head {limit}",
                ]
            else:
                unresolved.append("detection or filtering condition")
                lines = [
                    " ".join(base_parts),
                    "| where {INTENT_CONDITION}",
                    "| stats count as event_count earliest(_time) as first_seen latest(_time) as last_seen by {ENTITY_FIELD} {ACTIVITY_FIELD}",
                    "| sort - event_count",
                    f"| head {limit}",
                ]

        spl = "\n".join(lines)
        executable = not _PLACEHOLDER_PATTERN.search(spl)
        safety_status = "NOT_RUN_PLACEHOLDER_TEMPLATE"
        safety_errors: list[str] = []
        if executable:
            validation = self.validator.validate(spl)
            safe = bool(getattr(validation, "safe", False))
            safety_status = "PASS" if safe else "BLOCKED"
            safety_errors = list(getattr(validation, "errors", []) or [])

        return SPLBuildOutcome(
            spl=spl,
            executable=executable,
            safety_status=safety_status,
            safety_errors=safety_errors,
            resolved_bindings=resolved,
            unresolved_bindings=list(dict.fromkeys(unresolved)),
            preserved_conditions=conditions,
            notes=[
                "The local generic SPL model was unavailable or its output failed deterministic constraints, so ARIA used the safe generic fallback.",
                "Only analyst-supplied bindings, intent terms, Splunk metadata fields and visible placeholders are present.",
                "No event IDs, vendor fields, lookup names, thresholds or ATT&CK mappings were invented.",
            ],
            intent_summary=intent,
            generation_path="DETERMINISTIC_GENERIC_FALLBACK",
            time_range_explicit=bool(earliest or latest),
        )

    @classmethod
    def extract_intent(cls, text: str) -> str:
        value = " ".join(str(text or "").split())
        value = re.sub(
            r"^(?:please\s+)?(?:build|create|generate|write|construct|draft|produce|give\s+me)\s+(?:me\s+)?(?:an?\s+)?spl\s*(?:for|to|that|which)?\s*",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.sub(r"\b(?:using|with)\s+live\s+splunk\s+evidence\b", " ", value, flags=re.IGNORECASE)
        value = re.sub(r"\b(?:discover|validate|verify|execute|report)\b.*$", " ", value, flags=re.IGNORECASE)
        return compact_text(" ".join(value.strip(" ,:-").split()), 500) or "analyst-requested security activity"

    @classmethod
    def intent_terms(cls, text: str) -> list[str]:
        output: list[str] = []
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", str(text or "")):
            value = token.strip("_.:/-")
            lower = value.lower()
            if len(lower) < 3 or lower in _INTENT_STOP_WORDS or lower.isdigit():
                continue
            if lower not in {item.lower() for item in output}:
                output.append(value)
        return output[:8]

    @staticmethod
    def term_variants(term: str) -> list[str]:
        lower = str(term or "").strip().lower()
        if not lower:
            return []
        spaced = re.sub(r"[-_./:]+", " ", lower)
        compact = re.sub(r"[-_./:\s]+", "", lower)
        variants = [lower, spaced, compact]
        return list(dict.fromkeys(value for value in variants if len(value) >= 2))

    @staticmethod
    def has_explicit_time(text: str) -> bool:
        earliest, latest = DeterministicSPLBuilder._extract_time(text)
        return bool(earliest or latest)

    @classmethod
    def explicit_condition_literals(cls, text: str) -> list[str]:
        literals: list[str] = []
        for condition in cls._extract_explicit_conditions(text, excluded=set()):
            for token in re.findall(r"[A-Za-z0-9_.:/-]{2,120}", condition):
                if token.upper() in {"AND", "OR", "NOT"}:
                    continue
                if token not in literals:
                    literals.append(token)
        return literals[:20]

    @staticmethod
    def _combine_request(current: str, context: str) -> str:
        if DeterministicSPLBuilder.has_explicit_time(current) and context:
            prior_builds = []
            for line in context.splitlines():
                line = line.strip()
                if re.search(r"\b(?:build|create|generate|write|give\s+me)\b.*\bspl\b", line, flags=re.IGNORECASE):
                    prior_builds.append(line)
            if prior_builds:
                return prior_builds[-1] + "\n" + current
        return current

    @staticmethod
    def _clean_spl(value: str) -> str:
        text = str(value or "").strip()
        text = re.sub(r"^```(?:spl)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        return text.strip()


    @classmethod
    def _normalise_generic_spl(
        cls,
        spl: str,
        *,
        index: str | None,
        sourcetype: str | None,
        earliest: str | None,
        latest: str | None,
        conditions: list[str],
    ) -> str:
        """Normalise an LLM draft into one defensible generic pipeline.

        The model is allowed to design pipeline shape, but source/time bindings are
        controlled deterministically and duplicate base searches are removed.
        """
        raw = cls._clean_spl(spl)
        if not raw:
            return ""
        stages = [" ".join(stage.strip().split()) for stage in raw.split("|") if stage.strip()]
        if not stages:
            return ""

        required = [
            ("index", spl_quote(index) if index else "{INDEX}"),
            ("sourcetype", spl_quote(sourcetype) if sourcetype else "{SOURCETYPE}"),
            ("earliest", earliest or "{EARLIEST}"),
            ("latest", latest or "{LATEST}"),
        ]
        first = stages[0]
        if not re.match(r"^(?:search\s+)?index\s*=", first, flags=re.IGNORECASE):
            first = "search " + " ".join(f"{name}={value}" for name, value in required)
        else:
            if not first.lower().startswith("search "):
                first = "search " + first
            for name, value in required:
                pattern = rf"\b{name}\s*=\s*(?:\{{[^}}]+\}}|\"[^\"]*\"|'[^']*'|[^\s|]+)"
                if re.search(pattern, first, flags=re.IGNORECASE):
                    first = re.sub(pattern, f"{name}={value}", first, count=1, flags=re.IGNORECASE)
                else:
                    first += f" {name}={value}"

        cleaned = [first]
        for stage in stages[1:]:
            if re.match(r"^search\b", stage, flags=re.IGNORECASE):
                remainder = re.sub(r"^search\s+", "", stage, flags=re.IGNORECASE)
                for name, _value in required:
                    remainder = re.sub(
                        rf"\b{name}\s*=\s*(?:\{{[^}}]+\}}|\"[^\"]*\"|'[^']*'|[^\s|]+)",
                        " ",
                        remainder,
                        flags=re.IGNORECASE,
                    )
                remainder = " ".join(remainder.split()).strip()
                if not remainder or remainder in {'"{CONDITION}"', "'{CONDITION}'", '"{INTENT_CONDITION}"', "'{INTENT_CONDITION}'"}:
                    continue
                stage = "search " + remainder
            cleaned.append(stage)

        if conditions and not any(condition.lower() in " | ".join(cleaned).lower() for condition in conditions):
            cleaned.insert(1, "search " + " ".join(conditions))
        return "\n| ".join([cleaned[0], *[item[2:] if item.startswith('| ') else item for item in cleaned[1:]]]).strip()

    @classmethod
    def _generic_fields_are_defensible(cls, spl: str, analyst_text: str) -> bool:
        """Reject model-invented schema while retaining placeholders and metadata."""
        allowed = {"_time", "_raw", "host", "source", "sourcetype"}
        supplied_fields = set()
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_.:-]{1,100})\s*=", analyst_text):
            name = match.group(1)
            if name.lower() not in {"index", "sourcetype", "earliest", "latest"}:
                supplied_fields.add(name)

        def valid_field(token: str) -> bool:
            value = token.strip().strip("'\"")
            if not value:
                return True
            if _PLACEHOLDER_PATTERN.fullmatch(value):
                return True
            if value in allowed or value in supplied_fields:
                return True
            if value.lower() in {"event_count", "first_seen", "last_seen"} or value.lower().startswith("aria_"):
                return True
            return False

        for table in re.findall(r"\|\s*table\s+([^|]+)", "| " + spl, flags=re.IGNORECASE):
            for token in re.split(r"[\s,]+", table.strip()):
                if token and not valid_field(token):
                    return False
        for by_clause in re.findall(r"\bstats\b[^|]*?\bby\s+([^|]+)", spl, flags=re.IGNORECASE):
            for token in re.split(r"[\s,]+", by_clause.strip()):
                if token and not valid_field(token):
                    return False
        for function_arg in re.findall(r"\b(?:tostring|lower|upper|len|coalesce|isnotnull|isnull)\s*\(\s*([^,\)]+)", spl, flags=re.IGNORECASE):
            if not valid_field(function_arg):
                return False
        return True

    @classmethod
    def _generic_literals_are_defensible(cls, spl: str, analyst_text: str) -> bool:
        """Reject model-added filter literals that are absent from the analyst request."""
        analyst_norm = re.sub(r"[^a-z0-9]+", "", str(analyst_text or "").lower())
        supplied_values = {
            re.sub(r"[^a-z0-9]+", "", value.lower())
            for value in cls.explicit_condition_literals(analyst_text)
            if value
        }
        for match in re.finditer(r"""(["'])(.*?)(?<!\\)\1""", spl, flags=re.DOTALL):
            literal = match.group(2).strip()
            if not literal or _PLACEHOLDER_PATTERN.fullmatch(literal):
                continue
            stripped = literal.strip("%*").strip()
            if not stripped:
                continue
            normalised = re.sub(r"[^a-z0-9]+", "", stripped.lower())
            if not normalised:
                continue
            if normalised in analyst_norm or normalised in supplied_values:
                continue
            # Source and time bindings are already deterministically enforced.
            if normalised in {"now"} or re.fullmatch(r"[0-9]+[smhdw]?", normalised):
                continue
            return False
        return True

    @staticmethod
    def _enforce_required_bindings(
        spl: str,
        *,
        index: str | None,
        sourcetype: str | None,
        earliest: str | None,
        latest: str | None,
    ) -> str:
        output = spl
        required = [
            ("index", spl_quote(index) if index else "{INDEX}"),
            ("sourcetype", spl_quote(sourcetype) if sourcetype else "{SOURCETYPE}"),
            ("earliest", earliest or "{EARLIEST}"),
            ("latest", latest or "{LATEST}"),
        ]
        first_line, *rest = output.splitlines()
        if not re.match(r"^\s*(?:search\s+)?index\s*=", first_line, flags=re.IGNORECASE):
            first_line = "search " + " ".join(f"{name}={value}" for name, value in required) + " " + first_line
        else:
            for name, value in required:
                pattern = rf"\b{name}\s*=\s*(?:\{{[^}}]+\}}|\"[^\"]*\"|'[^']*'|[^\s|]+)"
                if re.search(pattern, first_line, flags=re.IGNORECASE):
                    first_line = re.sub(pattern, f"{name}={value}", first_line, count=1, flags=re.IGNORECASE)
                else:
                    first_line += f" {name}={value}"
        return "\n".join([first_line, *rest]).strip()

    @staticmethod
    def _placeholder_safe_validation_copy(spl: str) -> str:
        replacements = {
            "{INDEX}": "aria_placeholder_index",
            "{SOURCETYPE}": "aria:placeholder",
            "{EARLIEST}": "-24h",
            "{LATEST}": "now",
            "{CONDITION}": "isnotnull(_time)",
            "{INTENT_CONDITION}": "isnotnull(_raw)",
            "{ENTITY_FIELD}": "host",
            "{ACTIVITY_FIELD}": "_raw",
            "{OUTCOME_FIELD}": "source",
        }
        output = spl
        for placeholder in set(_PLACEHOLDER_PATTERN.findall(output)):
            output = output.replace(placeholder, replacements.get(placeholder, "aria_placeholder"))
        return output

    @classmethod
    def _extract_binding(cls, text: str, name: str) -> str | None:
        escaped = re.escape(name)
        patterns = [
            rf"\b{escaped}\s*=\s*[\"']([^\"']+)[\"']",
            rf"\b{escaped}\s*=\s*([^\s|,;]+)",
            rf"\b{escaped}\s*\(\s*[\"']?([^\)\"']+)[\"']?\s*\)",
            rf"\b{escaped}\s+(?:named|called)\s+[\"']?([^\s|,;\"']+)[\"']?",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if not match:
                continue
            value = cls._clean_value(match.group(1))
            if value:
                return value
        return None

    @staticmethod
    def _clean_value(value: Any) -> str | None:
        text = str(value or "").strip().strip("\"'").strip()
        return text if _VALUE_PATTERN.fullmatch(text) else None

    @staticmethod
    def _extract_time(text: str) -> tuple[str | None, str | None]:
        earliest_match = re.search(r"\bearliest\s*=\s*([^\s|,;]+)", text, flags=re.IGNORECASE)
        latest_match = re.search(r"\blatest\s*=\s*([^\s|,;]+)", text, flags=re.IGNORECASE)
        earliest = safe_time(earliest_match.group(1), "") if earliest_match else None
        latest = safe_time(latest_match.group(1), "") if latest_match else None

        if not earliest:
            relative = re.search(
                r"\b(?:last|past)\s+([1-9][0-9]{0,3})\s*(seconds?|minutes?|hours?|days?|weeks?)\b",
                text,
                flags=re.IGNORECASE,
            )
            if relative:
                amount = relative.group(1)
                unit_word = relative.group(2).lower()
                unit = "s" if unit_word.startswith("second") else "m" if unit_word.startswith("minute") else "h" if unit_word.startswith("hour") else "d" if unit_word.startswith("day") else "w"
                earliest = f"-{amount}{unit}"
                latest = latest or "now"
        if re.search(r"\ball available time\b|\bacross all time\b|\ball historical time\b", text, flags=re.IGNORECASE):
            earliest = "0"
            latest = latest or "now"
        return earliest or None, latest or None

    @staticmethod
    def _extract_limit(text: str) -> int:
        match = re.search(r"\b(?:head|limit|top|first)\s+([1-9][0-9]{0,3})\b", text, flags=re.IGNORECASE)
        if not match:
            return 100
        return max(1, min(int(match.group(1)), 1000))

    @classmethod
    def _extract_explicit_conditions(
        cls,
        text: str,
        *,
        excluded: set[str | None],
    ) -> list[str]:
        output: list[str] = []
        excluded_values = {str(item).lower() for item in excluded if item}

        for group in re.findall(r"\(([^()\n]+)\)", text):
            candidate = " ".join(group.split()).strip()
            lowered = candidate.lower()
            if lowered in excluded_values:
                continue
            if not re.search(r"\b(?:AND|OR|NOT)\b", candidate, flags=re.IGNORECASE):
                continue
            if "|" in candidate or len(candidate) > 500:
                continue
            output.append(f"({candidate})")

        if not output:
            for line in text.splitlines():
                candidate = " ".join(line.strip().split())
                if not candidate or "|" in candidate:
                    continue
                if re.search(r"\bindex\s*=|\bsourcetype\s*=", candidate, flags=re.IGNORECASE):
                    trailing = re.split(
                        r"\bsourcetype\s*=\s*(?:[\"'][^\"']+[\"']|[^\s]+)",
                        candidate,
                        maxsplit=1,
                        flags=re.IGNORECASE,
                    )
                    candidate = trailing[-1].strip() if len(trailing) > 1 else ""
                if candidate and re.search(r"\b(?:AND|OR|NOT)\b", candidate, flags=re.IGNORECASE):
                    output.append(candidate)
                    break

        return list(dict.fromkeys(compact_text(item, 500) for item in output if item))[:3]
