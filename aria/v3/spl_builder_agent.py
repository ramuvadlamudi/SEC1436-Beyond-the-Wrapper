from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from aria.copilot.contracts import CopilotResult, InvestigationPlan
from aria.ollama_client import OllamaClient
from aria.spl_validator import StaticSPLValidator
from aria.suppressed_exception_logger import log_suppressed_exception
from aria.v3.contracts import (
    AnalystAggregation,
    BehaviourIntent,
    IntentConcept,
    SourceAssessment,
    SourceConstraint,
    SPLVariant,
)
from aria.v3.telemetry_intelligence import TelemetryIntelligenceService
from aria.v3.utils import (
    compact_text,
    extract_explicit_constraints,
    markdown_table,
    parse_time_range,
    quote_like,
    salient_terms,
    spl_field,
    spl_quote,
    term_variants,
)


class SPLBuilderAgent:
    """Two-track SPL Builder.

    Track 1 translates the analyst's behavioural intent into portable SPL using an
    LLM-produced semantic plan and a deterministic compiler. Track 2 validates the
    connected deployment and substitutes only live source and field bindings.
    """

    def __init__(
        self,
        ollama: OllamaClient,
        telemetry: TelemetryIntelligenceService,
        validator: StaticSPLValidator,
    ) -> None:
        self.ollama = ollama
        self.telemetry = telemetry
        self.validator = validator

    def build(
        self,
        question: str,
        *,
        history: list[Any] | None = None,
        last_result: Any | None = None,
        progress: Any | None = None,
    ) -> CopilotResult:
        started = time.monotonic()
        effective = self._reconstruct_request(question, history or [], last_result)
        raw = extract_explicit_constraints(effective)
        semantic_request = self._semantic_request(effective)
        aggregation = self._aggregation_intent(effective)
        preferred_source = self._preferred_source(last_result)
        intent = self._intent(semantic_request, limit=int(raw["limit"]))
        self._apply_aggregation_intent(intent, aggregation)
        constraint = SourceConstraint(
            index=raw["index"],
            sourcetype=raw["sourcetype"],
            earliest=raw["earliest"],
            latest=raw["latest"],
            literal_condition=raw["literal_condition"],
            explicit=bool(raw["index"] or raw["sourcetype"]),
        )
        generic = self._generic_variant(intent, constraint, aggregation)
        lines = self._generic_section(intent, generic, constraint, aggregation)

        if not raw["time_explicit"]:
            lines.extend([
                "## 2. Deployment-qualified SPL", "",
                "**Status:** `WAITING_FOR_TIME_RANGE`", "",
                "Select a time range before ARIA queries the connected Splunk catalogue and profiles live schemas:", "",
                "- `Use the last 24 hours.`",
                "- `Use the last 7 days.`",
                "- `Use all available time.`",
                "- `Use earliest=<value> latest=<value>.`", "",
                "The original build intent is retained for the next turn.",
            ])
            return self._result(
                question=question,
                effective=effective,
                semantic_request=semantic_request,
                intent=intent,
                aggregation=aggregation,
                preferred_source=preferred_source,
                answer="\n".join(lines),
                generic=generic,
                live=None,
                source_assessments=[],
                awaiting_time=True,
                duration=time.monotonic() - started,
            )

        earliest = str(raw["earliest"] or "-24h")
        latest = str(raw["latest"] or "now")
        if progress:
            progress("v3_build_catalog", "Discovering deployment telemetry", "ARIA is querying the live catalogue for the analyst-selected time range.")
        catalog = self.telemetry.catalog(earliest, latest)
        candidate_limit = max(
            1,
            int(
                os.getenv(
                    "ARIA_V3_AGGREGATION_CANDIDATE_LIMIT"
                    if aggregation is not None
                    else "ARIA_V3_BUILD_CANDIDATE_LIMIT",
                    "3" if aggregation is not None else "8",
                )
            ),
        )
        candidates = self.telemetry.rank_sources(
            intent,
            catalog,
            constraint,
            limit=candidate_limit,
        )
        candidates = self._prioritise_source(
            candidates,
            catalog,
            preferred_source,
            candidate_limit,
        )
        assessments: list[SourceAssessment] = []
        selected_profile = None
        selected_assessment = None
        for position, candidate in enumerate(candidates, start=1):
            if progress:
                progress("v3_build_profile", "Profiling deployment source", f"Profiling candidate {position} of {len(candidates)} from the live catalogue.")
            profile = self.telemetry.profile(candidate, earliest=earliest, latest=latest)
            assessment = self.telemetry.assess_source(profile, intent)
            assessments.append(assessment)
            # Explicitly supplied sources are authoritative input: validate that
            # exact source first and report its capability rather than scanning the
            # deployment for a different interpretation.
            if constraint.index and constraint.sourcetype:
                selected_profile = profile
                selected_assessment = assessment
                break
            if assessment.schema_qualified:
                selected_profile = profile
                selected_assessment = assessment
                break

        live: SPLVariant | None = None
        if (
            selected_profile
            and selected_assessment
            and (aggregation is None or selected_assessment.schema_qualified)
            and selected_profile.fields
            and not selected_profile.profile_error
        ):
            live = self._deployment_variant(
                intent,
                constraint,
                selected_profile,
                selected_assessment,
                earliest,
                latest,
                aggregation,
            )
        lines.extend(self._live_section(
            earliest=earliest,
            latest=latest,
            catalog_count=len(catalog),
            candidates=candidates,
            assessments=assessments,
            selected=selected_assessment,
            live=live,
            preferred_source=preferred_source,
        ))
        return self._result(
            question=question,
            effective=effective,
            semantic_request=semantic_request,
            intent=intent,
            aggregation=aggregation,
            preferred_source=preferred_source,
            answer="\n".join(lines),
            generic=generic,
            live=live,
            source_assessments=assessments,
            awaiting_time=False,
            duration=time.monotonic() - started,
        )

    def _intent(self, question: str, *, limit: int) -> BehaviourIntent:
        system = """You are ARIA v3's semantic SPL planning agent.
Translate the analyst request into a portable behavioural intent, not raw SPL.
Rules:
- Do not name or guess indexes, sourcetypes, field names, event IDs, lookups, vendors, thresholds, entities or values not explicitly present in the analyst request.
- behaviour_terms must be short literal concepts present in the analyst request, not extra detections or indicators.
- concepts describe generic observable roles such as activity content, entity context, target context and outcome.
- The activity concept is required. Other concepts are optional unless the analyst explicitly requires them.
- desired_shape describes the analytical output, not a customer schema.
Return only the BehaviourIntent schema."""
        try:
            intent = self.ollama.structured_chat(
                system_prompt=system,
                user_prompt=question,
                response_model=BehaviourIntent,
                model_role="fast",
                num_predict=650,
                timeout=int(os.getenv("ARIA_V3_SPL_INTENT_TIMEOUT_SECONDS", "45")),
            )
            intent.limit = limit
            self._validate_intent(intent, question)
            return intent
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.spl_builder.intent")
            terms = salient_terms(self._strip_control_language(question), limit=6)
            summary = compact_text(self._strip_control_language(question), 300) or "analyst-requested security activity"
            return BehaviourIntent(
                summary=summary,
                behaviour_terms=terms,
                concepts=[
                    IntentConcept(concept_id="A1", role="activity", description="event content representing the requested behaviour", required=True),
                    IntentConcept(concept_id="E1", role="entity", description="originating entity context", required=False),
                    IntentConcept(concept_id="T1", role="target", description="target or related entity context", required=False),
                    IntentConcept(concept_id="O1", role="outcome", description="event outcome or state", required=False),
                ],
                desired_shape="events",
                limit=limit,
            )

    @staticmethod
    def _validate_intent(intent: BehaviourIntent, question: str) -> None:
        normalised_question = question.lower().replace("_", " ").replace("-", " ")
        constraints = extract_explicit_constraints(question)
        blocked_tokens = {
            "index", "sourcetype", "source", "earliest", "latest", "now",
            "build", "create", "generate", "write", "spl", "splunk", "execute",
            "live", "qualified", "deployment", "portable", "schema",
            "detect", "detecting", "possible", "use", "using", "qualify",
            "suitable", "observed", "selected", "explain", "evidence", "gaps",
            "assume", "analyst", "supplied", "threshold", "thresholds",
            "refinement", "window", "validation", "final", "generated",
        }
        for value in (constraints.get("index"), constraints.get("sourcetype")):
            if value:
                blocked_tokens.update(salient_terms(str(value), limit=20))
        filtered: list[str] = []
        for term in intent.behaviour_terms:
            value = str(term or "").strip().lower()
            if not value:
                continue
            value_tokens = set(salient_terms(value, limit=20))
            if value in blocked_tokens or (value_tokens and value_tokens.issubset(blocked_tokens)):
                continue
            variants = term_variants(value)
            if any(item and item.replace("-", " ").replace("_", " ") in normalised_question for item in variants):
                filtered.append(value)
        intent.behaviour_terms = list(dict.fromkeys(filtered))[:8]
        if not intent.concepts:
            raise ValueError("Intent model returned no observable concepts.")
        if not any(item.role == "activity" for item in intent.concepts):
            raise ValueError("Intent model returned no activity concept.")

    def _generic_variant(
        self,
        intent: BehaviourIntent,
        constraint: SourceConstraint,
        aggregation: AnalystAggregation | None,
    ) -> SPLVariant:
        index = spl_quote(constraint.index) if constraint.index else "{INDEX}"
        sourcetype = spl_quote(constraint.sourcetype) if constraint.sourcetype else "{SOURCETYPE}"
        earliest = constraint.earliest or "{EARLIEST}"
        latest = constraint.latest or "{LATEST}"
        lines = [f"search index={index} sourcetype={sourcetype} earliest={earliest} latest={latest}"]
        if constraint.literal_condition:
            lines.append(f"| search ({constraint.literal_condition})")
        elif intent.behaviour_terms and aggregation is None:
            lines.append("| eval aria_text=lower(tostring(_raw))")
            lines.append("| where " + self._term_expression("aria_text", intent.behaviour_terms))
        elif aggregation is None:
            lines.append("| where {BEHAVIOUR_CONDITION}")
        if aggregation is not None:
            lines.extend(self._portable_aggregation_lines(aggregation, intent.limit))
        elif intent.desired_shape == "timeline":
            lines.extend(["| timechart count as event_count", f"| head {intent.limit}"])
        else:
            lines.extend(["| table _time index sourcetype source _raw", f"| head {intent.limit}"])
        spl = "\n".join(lines)
        status = "PROPOSED" if constraint.earliest and constraint.latest else "WAITING_FOR_TIME_RANGE"
        return SPLVariant(
            name="GENERIC_INTENT_SPL",
            spl=spl,
            status=status,
            safe=False,
            notes=[
                "The LLM produced semantic intent only; deterministic code compiled the SPL.",
                "Unresolved deployment values remain visible placeholders.",
                "No customer field, event ID, threshold or source was invented.",
            ],
        )

    def _deployment_variant(
        self,
        intent: BehaviourIntent,
        constraint: SourceConstraint,
        profile: Any,
        assessment: SourceAssessment,
        earliest: str,
        latest: str,
        aggregation: AnalystAggregation | None,
    ) -> SPLVariant:
        lines = [
            f"search index={spl_quote(profile.index)} sourcetype={spl_quote(profile.sourcetype)} earliest={earliest} latest={latest}"
        ]
        if constraint.literal_condition:
            lines.append(f"| search ({constraint.literal_condition})")
        elif intent.behaviour_terms and aggregation is None:
            # `_raw` is the only universal event-content surface in Splunk. It is
            # used for portable behaviour terms; observed deployment fields are
            # added for context, grouping and display only after live profiling.
            lines.append("| eval aria_text=lower(tostring(_raw))")
            lines.append("| where " + self._term_expression("aria_text", intent.behaviour_terms))
        activity = next((item for item in assessment.bindings if item.role == "activity" and item.field), None)
        entity = next((item for item in assessment.bindings if item.role == "entity" and item.field), None)
        target = next((item for item in assessment.bindings if item.role == "target" and item.field), None)
        outcome = next((item for item in assessment.bindings if item.role == "outcome" and item.field), None)
        context_fields = list(dict.fromkeys(
            item.field for item in (entity, target, outcome, activity) if item and item.field
        ))
        if aggregation is not None:
            measured = next(
                (
                    item
                    for item in assessment.bindings
                    if item.concept_id == aggregation.measured_concept_id and item.field
                ),
                None,
            )
            aggregation_entity = next(
                (
                    item
                    for item in assessment.bindings
                    if aggregation.entity_concept_id
                    and item.concept_id == aggregation.entity_concept_id
                    and item.field
                ),
                None,
            )
            grouping = next(
                (
                    item
                    for item in assessment.bindings
                    if aggregation.grouping_concept_id
                    and item.concept_id == aggregation.grouping_concept_id
                    and item.field
                ),
                None,
            )
            if measured is None:
                raise ValueError("Schema-qualified aggregation is missing its measured field binding.")
            lines.extend(
                self._bound_aggregation_lines(
                    aggregation,
                    measured.field,
                    aggregation_entity.field if aggregation_entity else None,
                    grouping.field if grouping else None,
                    intent.limit,
                )
            )
        elif intent.desired_shape in {"distribution", "relationship", "ratio", "sequence"} and context_fields:
            group = " ".join(spl_field(field) for field in context_fields[:4])
            lines.extend([
                f"| stats count as event_count earliest(_time) as first_seen latest(_time) as last_seen by {group}",
                "| sort - event_count",
                f"| head {intent.limit}",
            ])
        else:
            table = ["_time", *context_fields[:5], "index", "sourcetype", "source", "_raw"]
            lines.extend(["| table " + " ".join(spl_field(field) for field in list(dict.fromkeys(table))), f"| head {intent.limit}"])
        spl = "\n".join(lines)
        validation = self.validator.validate(spl)
        safe = bool(getattr(validation, "safe", False))
        status = "SCHEMA_QUALIFIED" if safe else "BLOCKED"
        notes = [
            "The source was selected from the connected Splunk catalogue for the requested time range.",
            "Every non-metadata deployment field in the SPL was observed in the bounded source profile.",
            "SCHEMA_QUALIFIED means the telemetry can express the query; it does not claim matching attack events currently exist.",
            "The generated SPL was not executed by BUILD_SPL.",
        ]
        return SPLVariant(
            name="DEPLOYMENT_QUALIFIED_SPL",
            spl=spl,
            status=status,
            safe=safe,
            validation_errors=list(getattr(validation, "errors", []) or []),
            validation_warnings=list(getattr(validation, "warnings", []) or []),
            executed=False,
            notes=notes,
        )

    @staticmethod
    def _term_expression(field: str, terms: list[str]) -> str:
        groups: list[str] = []
        for term in terms[:8]:
            variants = term_variants(term)
            conditions = [f"like({field},{quote_like(value)})" for value in variants[:3]]
            if conditions:
                groups.append("(" + " OR ".join(conditions) + ")")
        return " AND ".join(groups) if groups else "{BEHAVIOUR_CONDITION}"

    def _generic_section(
        self,
        intent: BehaviourIntent,
        generic: SPLVariant,
        constraint: SourceConstraint,
        aggregation: AnalystAggregation | None,
    ) -> list[str]:
        lines = [
            "## ARIA v3 SPL Builder", "",
            "**Capability:** `BUILD_SPL`  ",
            "**Contract:** `LLM_SEMANTIC_INTENT + DETERMINISTIC_SPL + LIVE_DEPLOYMENT_QUALIFICATION`  ",
            "**Final SPL execution:** `NO`", "",
            "## Intent interpretation", "",
            f"- Summary: {intent.summary}",
            f"- Behaviour terms: {', '.join(f'`{item}`' for item in intent.behaviour_terms) or 'No literal behaviour terms extracted'}",
            f"- Analytical shape: `{intent.desired_shape}`", "",
        ]
        if aggregation is not None:
            lines.extend([
                "### Analyst-supplied aggregation contract", "",
                f"- Observation window: `{aggregation.window_span or 'not supplied'}`",
                f"- Metric: `distinct count` of `{aggregation.measured_concept}`",
                f"- Entity grouping: `{aggregation.entity_concept or 'not supplied'}`",
                f"- Related-value grouping: `{aggregation.grouping_concept or 'not supplied'}`",
                f"- Threshold: `{aggregation.operator} {aggregation.threshold}`",
                "- Interpretation: analyst-supplied detection logic; not evidence of maliciousness.", "",
            ])
        lines.extend([
            "## 1. Portable generic SPL", "",
            f"**Status:** `{generic.status}`", "",
            "```spl", generic.spl, "```", "",
            *[f"- {note}" for note in generic.notes], "",
        ])
        return lines

    def _live_section(
        self,
        *,
        earliest: str,
        latest: str,
        catalog_count: int,
        candidates: list[dict[str, Any]],
        assessments: list[SourceAssessment],
        selected: SourceAssessment | None,
        live: SPLVariant | None,
        preferred_source: dict[str, str] | None,
    ) -> list[str]:
        lines = [
            "## 2. Deployment-qualified SPL", "",
            f"- Time range: `{earliest}` to `{latest}`",
            f"- Live catalogue rows evaluated: `{catalog_count}`",
            f"- Candidate sources profiled: `{len(assessments)}`",
            "- Final SPL execution: `NO`", "",
        ]
        if preferred_source:
            lines.extend([
                f"- Parent Builder source revalidated first: "
                f"`{preferred_source['index']}` / `{preferred_source['sourcetype']}`", "",
            ])
        if assessments:
            rows = [
                [
                    item.index,
                    item.sourcetype,
                    item.fields_observed,
                    f"{item.required_bindings_supported}/{item.required_bindings_total}",
                    "YES" if item.schema_qualified else "NO",
                    compact_text("; ".join(item.rationale), 180),
                ]
                for item in assessments[:8]
            ]
            lines.extend([
                "### Source capability assessment", "",
                markdown_table(["Index", "Sourcetype", "Observed fields", "Required bindings", "Schema qualified", "Basis"], rows), "",
            ])
        if not live or not selected:
            lines.extend([
                "**Status:** `NO_SCHEMA_QUALIFIED_SPL`", "",
                "ARIA could not corroborate every required measurement and grouping "
                "field within the bounded candidate set. The portable SPL remains "
                "available, but embedding similarity alone cannot create a "
                "deployment-specific field binding.", "",
            ])
            return lines
        binding_rows = [
            [item.role, item.description, item.field or "—", f"{item.score:.3f}", item.method]
            for item in selected.bindings
        ]
        lines.extend([
            "### Selected live source", "",
            f"`{selected.index}` / `{selected.sourcetype}`", "",
            "### Observed schema bindings", "",
            markdown_table(["Role", "Observable concept", "Observed field", "Score", "Method"], binding_rows), "",
            f"**Status:** `{live.status}`  ",
            f"**Safety gate:** `{'PASS' if live.safe else 'BLOCKED'}`", "",
            "```spl", live.spl, "```", "",
            *[f"- {note}" for note in live.notes],
        ])
        if live.validation_errors:
            lines.extend(["", "### Validation errors", "", *[f"- {item}" for item in live.validation_errors]])
        return lines

    def _result(
        self,
        *,
        question: str,
        effective: str,
        semantic_request: str,
        intent: BehaviourIntent,
        aggregation: AnalystAggregation | None,
        preferred_source: dict[str, str] | None,
        answer: str,
        generic: SPLVariant,
        live: SPLVariant | None,
        source_assessments: list[SourceAssessment],
        awaiting_time: bool,
        duration: float,
    ) -> CopilotResult:
        plan = InvestigationPlan(
            capability="BUILD_SPL",
            goal=effective,
            earliest=extract_explicit_constraints(effective)["earliest"] or "-24h",
            latest=extract_explicit_constraints(effective)["latest"] or "now",
            time_range_explicit=not awaiting_time,
            execute_read_only_search=False,
            requirements=[],
        )
        metadata = {
            "agent": "SPL_BUILDER_AGENT_V3",
            "architecture": "SEMANTIC_PLAN_THEN_DETERMINISTIC_COMPILE",
            "live_splunk_queries": not awaiting_time,
            "spl_executed": False,
            "awaiting_time_range": awaiting_time,
            "effective_request": effective,
            "semantic_request": semantic_request,
            "behaviour_intent": intent.model_dump(),
            "analyst_aggregation": aggregation.model_dump() if aggregation else None,
            "preferred_source": preferred_source,
            "generic_spl": generic.model_dump(),
            "deployment_spl": live.model_dump() if live else None,
            "source_assessments": [item.model_dump() for item in source_assessments],
            "duration_seconds": round(duration, 2),
        }
        if awaiting_time:
            actions = [
                "Use the last 24 hours.",
                "Use the last 7 days.",
                "Use all available time.",
                "Use earliest=-1h latest=now.",
            ]
        elif live is None:
            actions = [
                "Explain the portable SPL placeholders.",
                "Review the observed field-binding gaps.",
                "Choose an explicit source and rebuild.",
                "Refine the requested measurement or grouping concepts.",
            ]
        else:
            actions = [
                "Execute the deployment-qualified SPL as a safe bounded search.",
                "Explain the portable and deployment-qualified SPL differences.",
                "Change the time range and rebuild.",
                "Turn the deployment-qualified SPL into a detection candidate.",
            ]
        return CopilotResult(
            capability="BUILD_SPL",
            goal=effective,
            answer=answer,
            plan=plan,
            context_actions=actions,
            metadata=metadata,
        )

    @staticmethod
    def _strip_control_language(question: str) -> str:
        text = re.sub(
            r"\b(?:build|create|generate|write|give\s+me)\b.{0,120}?\bspl\b\s*(?:for|to)?",
            "",
            question,
            flags=re.IGNORECASE | re.DOTALL,
        )
        text = re.sub(r"\b(?:using|use)\s+(?:live\s+)?splunk(?:\s+data|\s+evidence)?\b", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\b(?:index|sourcetype|earliest|latest)\s*=\s*(?:\"[^\"]+\"|'[^']+'|[^\s|]+)", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\b(?:across|over|during|for)\s+all\s+available\s+time\b", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\b(?:during|over|for|in)\s+the\s+last\s+\d+\s+(?:minutes?|hours?|days?|weeks?)\b", "", text, flags=re.IGNORECASE)
        text = re.sub(
            r"\b(?:use|evaluate|discover|qualify|validate)\s+(?:the\s+)?(?:live\s+)?(?:connected\s+)?"
            r"(?:splunk\s+)?(?:deployment|catalogue|catalog|source|schema|fields?|telemetry)\b[^.\n]*[.\n]?",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"\b(?:do\s+not|don't)\s+(?:assume|invent|execute|run|activate|create|write)\b[^.\n]*[.\n]?",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"\bexplain\b[^.\n]*(?:telemetry|validation|evidence\s+gaps?|selected\s+source)[^.\n]*[.\n]?",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"\btreat\s+(?:these|this)\s+as\s+analyst-supplied\b[^.\n]*[.\n]?",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(r"\banalyst\s+refinement\s*:\s*", "", text, flags=re.IGNORECASE)
        return " ".join(text.split())

    @classmethod
    def _semantic_request(cls, question: str) -> str:
        text = cls._strip_control_language(question)
        text = re.sub(
            r"^\s*(?:for\s+)?(?:detect|detecting|find|finding|identify|identifying)\s+"
            r"(?:possible\s+)?",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"(?<=[.!?])\s+use\s+(?=(?:a|an|the|\d|zero|one|two|three|four|"
            r"five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
            r"fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|"
            r"forty|fifty|sixty|seventy|eighty|ninety)\b)",
            " ",
            text,
            flags=re.IGNORECASE,
        )
        return " ".join(text.split())

    @classmethod
    def _aggregation_intent(cls, text: str) -> AnalystAggregation | None:
        number = (
            r"(?:\d+|zero|one|two|three|four|five|six|seven|eight|nine|ten|"
            r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
            r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|"
            r"eighty|ninety|hundred|thousand)(?:[-\s](?:one|two|three|four|"
            r"five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
            r"fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|"
            r"forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand))*"
        )
        pattern = re.compile(
            rf"\b(?P<operator>more\s+than|greater\s+than|over|at\s+least|"
            rf"no\s+fewer\s+than|fewer\s+than|less\s+than|at\s+most|exactly)\s+"
            rf"(?P<number>{number})\s+distinct\s+"
            r"(?P<measured>[A-Za-z][A-Za-z0-9 _/:-]{0,80}?)"
            r"(?=\s+of\s+the\s+same\s+|\s+(?:per|by)\s+|[.,;\n]|$)",
            re.IGNORECASE,
        )
        matches = list(pattern.finditer(str(text or "")))
        if not matches:
            return None
        match = matches[-1]
        threshold = cls._number_value(match.group("number"))
        if threshold is None:
            return None
        operator = {
            "more than": ">",
            "greater than": ">",
            "over": ">",
            "at least": ">=",
            "no fewer than": ">=",
            "fewer than": "<",
            "less than": "<",
            "at most": "<=",
            "exactly": "=",
        }[" ".join(match.group("operator").lower().split())]
        measured = cls._clean_concept(match.group("measured"))

        tail = str(text or "")[match.end():]
        grouping_match = re.match(
            r"\s+of\s+the\s+same\s+(?P<group>[A-Za-z][A-Za-z0-9 _/:-]{0,80}?)"
            r"(?=[.,;\n]|$)",
            tail,
            re.IGNORECASE,
        )
        grouping = cls._clean_concept(grouping_match.group("group")) if grouping_match else None

        prefix = str(text or "")[:match.start()]
        entity_matches = list(re.finditer(
            r"\b(?:identify|find|show|return|detect)\s+(?:the\s+)?"
            r"(?P<entity>[A-Za-z][A-Za-z0-9 _/:-]{0,50}?)\s+"
            r"[A-Za-z][A-Za-z0-9_-]*ing\s*$",
            prefix,
            re.IGNORECASE,
        ))
        entity = cls._clean_concept(entity_matches[-1].group("entity")) if entity_matches else None

        window_matches = list(re.finditer(
            rf"\b(?P<number>{number})(?:\s*-\s*|\s+)"
            r"(?P<unit>seconds?|minutes?|hours?|days?|weeks?)\s+"
            r"(?:(?:observation|aggregation|sliding|tumbling)\s+)?window\b",
            str(text or ""),
            re.IGNORECASE,
        ))
        window_span = None
        if window_matches:
            window = window_matches[-1]
            window_value = cls._number_value(window.group("number"))
            unit = window.group("unit").lower()[0]
            if window_value is not None and window_value > 0:
                window_span = f"{window_value}{unit}"

        source_end = match.end() + (grouping_match.end() if grouping_match else 0)
        source_start = max(
            str(text or "").rfind(".", 0, match.start()),
            str(text or "").rfind("\n", 0, match.start()),
        ) + 1
        source_text = compact_text(str(text or "")[source_start:source_end].strip(), 400)
        return AnalystAggregation(
            measured_concept=measured,
            entity_concept=entity,
            entity_concept_id="ARIA_ENTITY_GROUP" if entity else None,
            grouping_concept=grouping,
            grouping_concept_id="ARIA_RELATED_GROUP" if grouping else None,
            window_span=window_span,
            operator=operator,
            threshold=threshold,
            source_text=source_text,
        )

    @staticmethod
    def _clean_concept(value: str | None) -> str:
        text = " ".join(str(value or "").strip(" .,:;\n\t").split())
        text = re.sub(r"^(?:a|an|the)\s+", "", text, flags=re.IGNORECASE)
        return compact_text(text, 100)

    @staticmethod
    def _number_value(value: str) -> int | None:
        text = str(value or "").strip().lower()
        if text.isdigit():
            return int(text)
        units = {
            "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
            "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
            "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
            "fourteen": 14, "fifteen": 15, "sixteen": 16,
            "seventeen": 17, "eighteen": 18, "nineteen": 19,
        }
        tens = {
            "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
            "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
        }
        total = 0
        current = 0
        for token in re.split(r"[-\s]+", text):
            if token in units:
                current += units[token]
            elif token in tens:
                current += tens[token]
            elif token == "hundred":
                current = max(1, current) * 100
            elif token == "thousand":
                total += max(1, current) * 1000
                current = 0
            else:
                return None
        return total + current

    @staticmethod
    def _apply_aggregation_intent(
        intent: BehaviourIntent,
        aggregation: AnalystAggregation | None,
    ) -> None:
        if aggregation is None:
            return
        for concept in intent.concepts:
            if concept.role == "activity":
                concept.required = False
        retained_ids = {
            aggregation.measured_concept_id,
            aggregation.entity_concept_id,
            aggregation.grouping_concept_id,
        }
        intent.concepts = [
            concept
            for concept in intent.concepts
            if concept.concept_id not in retained_ids
        ]
        intent.concepts.append(IntentConcept(
            concept_id=aggregation.measured_concept_id,
            role="quantity",
            description=f"{aggregation.measured_concept} used as the distinct-count value",
            required=True,
        ))
        if aggregation.entity_concept and aggregation.entity_concept_id:
            intent.concepts.append(IntentConcept(
                concept_id=aggregation.entity_concept_id,
                role="entity",
                description=f"{aggregation.entity_concept} that originate the measured activity",
                required=True,
            ))
        if aggregation.grouping_concept and aggregation.grouping_concept_id:
            intent.concepts.append(IntentConcept(
                concept_id=aggregation.grouping_concept_id,
                role="context",
                description=f"{aggregation.grouping_concept} used to group related distinct values",
                required=True,
            ))
        intent.desired_shape = "distribution"
        details = [
            f"distinct count of {aggregation.measured_concept}",
            f"{aggregation.operator} {aggregation.threshold}",
        ]
        if aggregation.window_span:
            details.append(f"within {aggregation.window_span} windows")
        if aggregation.entity_concept:
            details.append(f"by {aggregation.entity_concept}")
        if aggregation.grouping_concept:
            details.append(f"by {aggregation.grouping_concept}")
        intent.summary = compact_text(
            f"{intent.summary.rstrip('.')}; analyst aggregation: {', '.join(details)}.",
            500,
        )

    @staticmethod
    def _portable_aggregation_lines(
        aggregation: AnalystAggregation,
        limit: int,
    ) -> list[str]:
        group_fields: list[str] = []
        if aggregation.window_span:
            group_fields.append("_time")
        if aggregation.entity_concept:
            group_fields.append("{ENTITY_FIELD}")
        if aggregation.grouping_concept:
            group_fields.append("{GROUPING_FIELD}")
        lines = ["| where isnotnull({DISTINCT_VALUE_FIELD})"]
        if aggregation.window_span:
            lines.append(f"| bin _time span={aggregation.window_span}")
        by_clause = f" by {' '.join(group_fields)}" if group_fields else ""
        lines.extend([
            f"| stats dc({{DISTINCT_VALUE_FIELD}}) as aria_distinct_value_count{by_clause}",
            f"| where aria_distinct_value_count {aggregation.operator} {aggregation.threshold}",
            "| sort - aria_distinct_value_count",
            f"| head {limit}",
        ])
        return lines

    @staticmethod
    def _bound_aggregation_lines(
        aggregation: AnalystAggregation,
        measured_field: str,
        entity_field: str | None,
        grouping_field: str | None,
        limit: int,
    ) -> list[str]:
        measured = spl_field(measured_field)
        required = [measured]
        group_fields: list[str] = []
        if aggregation.window_span:
            group_fields.append("_time")
        if entity_field:
            required.append(spl_field(entity_field))
            group_fields.append(spl_field(entity_field))
        if grouping_field:
            required.append(spl_field(grouping_field))
            group_fields.append(spl_field(grouping_field))
        lines = [
            "| where " + " AND ".join(
                f"isnotnull({field}) AND tostring({field})!=\"\"" for field in required
            )
        ]
        if aggregation.window_span:
            lines.append(f"| bin _time span={aggregation.window_span}")
        by_clause = f" by {' '.join(group_fields)}" if group_fields else ""
        lines.extend([
            f"| stats dc({measured}) as aria_distinct_value_count{by_clause}",
            f"| where aria_distinct_value_count {aggregation.operator} {aggregation.threshold}",
            "| sort - aria_distinct_value_count",
            f"| head {limit}",
        ])
        return lines

    @staticmethod
    def _reconstruct_request(question: str, history: list[Any], last_result: Any | None) -> str:
        _, _, has_time = parse_time_range(question)
        previous_capability = ""
        previous_effective = ""
        if isinstance(last_result, dict):
            previous_capability = str(last_result.get("capability") or "")
            metadata = last_result.get("metadata") or {}
            previous_effective = str(metadata.get("effective_request") or "")
        explicit_new_build = bool(re.search(
            r"\b(?:build|create|generate|write|give\s+me)\b.{0,100}\bspl\b",
            question,
            re.IGNORECASE | re.DOTALL,
        ))
        if (
            previous_capability == "BUILD_SPL"
            and previous_effective
            and not explicit_new_build
        ):
            return previous_effective + "\n\nAnalyst refinement:\n" + question
        if has_time:
            for item in reversed(history):
                if isinstance(item, dict) and str(item.get("role") or "").lower() == "user":
                    content = str(item.get("content") or "")
                    if re.search(r"\b(?:build|create|generate|write|give\s+me)\b.*\bspl\b", content, re.IGNORECASE | re.DOTALL):
                        return content + "\n\n" + question
        return question

    @staticmethod
    def _preferred_source(last_result: Any | None) -> dict[str, str] | None:
        if not isinstance(last_result, dict):
            return None
        if str(last_result.get("capability") or "") != "BUILD_SPL":
            return None
        metadata = last_result.get("metadata") or {}
        assessments = list(metadata.get("source_assessments") or [])
        qualified = next(
            (
                item
                for item in assessments
                if item.get("schema_qualified")
                and str(item.get("index") or "")
                and str(item.get("sourcetype") or "")
            ),
            None,
        )
        selected = qualified or next(
            (
                item
                for item in assessments
                if str(item.get("index") or "")
                and str(item.get("sourcetype") or "")
            ),
            None,
        )
        if not selected:
            return None
        return {
            "index": str(selected["index"]),
            "sourcetype": str(selected["sourcetype"]),
        }

    @staticmethod
    def _prioritise_source(
        ranked: list[dict[str, Any]],
        catalog: list[dict[str, Any]],
        preferred: dict[str, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        if not preferred:
            return ranked[:limit]
        preferred_row = next(
            (
                dict(item)
                for item in catalog
                if str(item.get("index") or "") == preferred["index"]
                and str(item.get("sourcetype") or "") == preferred["sourcetype"]
            ),
            None,
        )
        if preferred_row is None:
            return ranked[:limit]
        output = [preferred_row]
        for item in ranked:
            if (
                str(item.get("index") or "") == preferred["index"]
                and str(item.get("sourcetype") or "") == preferred["sourcetype"]
            ):
                continue
            output.append(item)
            if len(output) >= limit:
                break
        return output
