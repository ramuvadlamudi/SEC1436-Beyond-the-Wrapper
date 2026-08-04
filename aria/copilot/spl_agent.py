from __future__ import annotations

import json
from typing import Any

from aria.copilot.contracts import (
    InvestigationPlan,
    MetricProposal,
    SearchExecutionRecord,
    SearchStrategyProposal,
    SourceEvidenceRecord,
    SourceProfileRecord,
)
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import (
    bounded_rows,
    is_numeric,
    safe_alias,
    safe_field,
    safe_span,
    safe_time,
    spl_field,
    spl_quote,
)
from aria.ollama_client import OllamaClient
from aria.spl_validator import StaticSPLValidator
from aria.splunk_client import SplunkClient
from aria.suppressed_exception_logger import log_suppressed_exception


class EvidenceBoundSPLAgent:
    def __init__(
        self,
        ollama: OllamaClient,
        splunk: SplunkClient,
        validator: StaticSPLValidator,
    ) -> None:
        self.ollama = ollama
        self.splunk = splunk
        self.validator = validator
        self.policy = evidence_policy()

    def propose_strategy(
        self,
        question: str,
        plan: InvestigationPlan,
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
        *,
        force_llm: bool = False,
    ) -> SearchStrategyProposal:
        if not force_llm and not bool(self.policy.get("strategy_llm_enabled", False)):
            return self._deterministic_strategy(source, profile)

        allowed_fields = self._allowed_field_payload(source, profile)
        allowed_values = self._allowed_values(source, profile, plan)

        system = """You are ARIA's evidence-bound SPL planning agent.

Create a read-only search strategy using only the supplied live source, validated fields and allowed values.

Rules:
- Use only the supplied candidate_id.
- Use only field names in allowed_fields.
- Filter values must come from allowed_values. Never invent event IDs, field values, thresholds, hosts, users, IPs, domains or vendor semantics.
- Use exists when a field's presence is relevant but no observed value proves the behaviour.
- Use contains, equals, in or numeric comparison only when the value is explicitly allowed.
- Do not force a behaviour filter when evidence is weak. In that case create an exploratory aggregation that exposes distributions for analyst review.
- Prefer grouping by validated entity, relationship or activity fields.
- Metrics and aliases must be generic and read-only.
- Never use collect, mcollect, outputlookup, sendalert, notable, rest, map, script, inputlookup, loadjob, dbxquery, delete or any action command.
- The strategy is a bounded investigation query, not a production detection.
"""
        user = f"""Analyst question:
{question}

Investigation plan:
{plan.model_dump_json(indent=2)}

Accepted source evidence:
{source.model_dump_json(indent=2)}

Live source profile:
{profile.model_dump_json(indent=2)}

Allowed fields:
{json.dumps(allowed_fields, ensure_ascii=False, indent=2)}

Allowed values:
{json.dumps(allowed_values, ensure_ascii=False, indent=2)}

Return only the SearchStrategyProposal schema."""
        try:
            return self.ollama.structured_chat(
                system_prompt=system,
                user_prompt=user,
                response_model=SearchStrategyProposal,
                model_role="fast",
                num_predict=900,
                timeout=int(self.policy.get("strategy_model_timeout_seconds", 60)),
            )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.spl_agent.strategy")
            return self._deterministic_strategy(source, profile)

    def _deterministic_strategy(
        self,
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
    ) -> SearchStrategyProposal:
        """Build a bounded, row-preserving summary from validated fields.

        ``stats ... by <field>`` can silently return no rows when the grouping
        field is unavailable in the execution search context. Conditional
        aggregate metrics retain one result row, expose field presence and
        values, and allow qualification/execution consistency to be checked.
        """
        profile_fields = {str(item.get("name") or "") for item in profile.fields}
        required_fields: list[str] = []
        for binding in source.requirement_bindings:
            if not binding.required or binding.status not in {"SUPPORTED", "PARTIAL"}:
                continue
            for field in binding.fields:
                if field in profile_fields and field not in required_fields:
                    required_fields.append(field)

        # Evidence qualification validates co-occurrence for required fields.
        # Optional context fields may be populated elsewhere in the source but
        # need not co-occur with those required fields. Including an unvalidated
        # optional field in `stats ... by` can silently remove every row because
        # Splunk omits events whose grouping value is null. Keep deterministic
        # execution aligned to the exact field set that passed qualification.
        bound_fields: list[str] = required_fields[:4]
        if not bound_fields:
            role_order = ["activity", "entity", "relationship", "outcome", "context"]
            for role in role_order:
                for binding in source.requirement_bindings:
                    if binding.role != role or binding.status not in {"SUPPORTED", "PARTIAL"}:
                        continue
                    for field in binding.fields:
                        if field in profile_fields and field not in bound_fields:
                            bound_fields.append(field)
                    if len(bound_fields) >= 4:
                        break
                if len(bound_fields) >= 4:
                    break
        if not bound_fields:
            for item in profile.fields:
                name = str(item.get("name") or "")
                if name and safe_field(name) and not name.startswith("_"):
                    bound_fields.append(name)
                if len(bound_fields) >= 2:
                    break
        metrics = [MetricProposal(function="count", alias="event_count")]
        used_aliases = {"event_count"}
        for position, field in enumerate(bound_fields[:4], start=1):
            alias_base = safe_alias(field, f"field_{position}")
            distinct_alias = safe_alias(
                f"aria_{alias_base}_distinct",
                f"aria_field_{position}_distinct",
            )
            values_alias = safe_alias(
                f"aria_{alias_base}_values",
                f"aria_field_{position}_values",
            )
            if distinct_alias not in used_aliases:
                metrics.append(
                    MetricProposal(
                        function="dc",
                        field=field,
                        alias=distinct_alias,
                    )
                )
                used_aliases.add(distinct_alias)
            if values_alias not in used_aliases:
                metrics.append(
                    MetricProposal(
                        function="values",
                        field=field,
                        alias=values_alias,
                    )
                )
                used_aliases.add(values_alias)

        return SearchStrategyProposal(
            candidate_id=source.candidate_id,
            purpose=(
                "Row-preserving bounded evidence summary over the required fields "
                "that passed live evidence qualification. No unobserved values or "
                "behaviour thresholds are introduced."
            ),
            filters=[],
            group_by=[],
            display_fields=bound_fields[:6],
            metrics=metrics,
            preserve_result_row=True,
            sort_by="event_count",
            descending=True,
            limit=min(30, int(self.policy.get("result_limit", 30))),
        )

    def compile_and_execute(
        self,
        plan: InvestigationPlan,
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
        strategy: SearchStrategyProposal,
        execution_number: int,
    ) -> SearchExecutionRecord:
        try:
            spl = self.compile(plan, source, profile, strategy)
        except Exception as exc:
            return SearchExecutionRecord(
                evidence_id=f"QRY-{execution_number}",
                candidate_id=source.candidate_id,
                index=source.index,
                sourcetype=source.sourcetype,
                purpose=strategy.purpose,
                spl="",
                safe=False,
                validation_errors=[f"Compilation failed: {exc.__class__.__name__}: {exc}"],
            )

        validation = self.validator.validate(spl)
        safe = bool(getattr(validation, "safe", False))
        record = SearchExecutionRecord(
            evidence_id=f"QRY-{execution_number}",
            candidate_id=source.candidate_id,
            index=source.index,
            sourcetype=source.sourcetype,
            purpose=strategy.purpose,
            spl=spl,
            safe=safe,
            validation_errors=list(getattr(validation, "errors", []) or []),
            validation_warnings=list(getattr(validation, "warnings", []) or []),
        )
        if not safe:
            return record

        try:
            rows = self.splunk.search(spl)
            record.rows = bounded_rows(rows, int(self.policy.get("result_limit", 30)))
            record.observed_event_count = self._observed_event_count(
                record.rows,
                strategy,
            )
            required_fields = self._required_execution_fields(
                source,
                {
                    str(item.get("name") or "")
                    for item in profile.fields
                    if str(item.get("name") or "")
                },
            )
            record.required_field_presence = self._required_field_presence(
                record.rows,
                required_fields,
            )
            record.missing_required_fields = [
                field
                for field in required_fields
                if record.required_field_presence.get(field, 0) <= 0
            ]
            if required_fields:
                record.fully_bound_event_count = self._sum_alias(
                    record.rows,
                    "aria_required_all_present",
                )
            if source.sampled_events > 0:
                record.qualification_consistent = bool(
                    record.rows
                    and record.observed_event_count is not None
                    and record.observed_event_count > 0
                    and not record.missing_required_fields
                    and (
                        not required_fields
                        or (
                            record.fully_bound_event_count is not None
                            and record.fully_bound_event_count > 0
                        )
                    )
                )
                if not record.qualification_consistent:
                    missing = (
                        ", ".join(record.missing_required_fields)
                        if record.missing_required_fields
                        else "none"
                    )
                    record.execution_error = (
                        "QUALIFICATION_EXECUTION_INCONSISTENCY: source qualification "
                        f"observed {source.sampled_events} bounded event(s) and "
                        f"{source.fully_bound_events} fully-bound event(s), but "
                        "execution did not reproduce both positive event volume "
                        f"and required-field presence. Missing required fields: {missing}."
                    )
        except Exception as exc:
            record.execution_error = f"{exc.__class__.__name__}: {exc}"
        return record

    def compile(
        self,
        plan: InvestigationPlan,
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
        strategy: SearchStrategyProposal,
    ) -> str:
        if strategy.candidate_id != source.candidate_id:
            raise ValueError("Strategy candidate does not match accepted source.")

        field_map = {str(item.get("name") or ""): item for item in profile.fields}
        allowed_fields = set(field_map)
        allowed_fields.update({"_raw", "_time", "host", "source", "sourcetype"})
        allowed_values = self._allowed_values(source, profile, plan)
        allowed_value_set = {value for values in allowed_values.values() for value in values}
        allowed_value_set.update(plan.explicit_entities)
        allowed_value_set.update(plan.explicit_values)

        filter_expressions: list[str] = []
        for proposal in strategy.filters:
            field = safe_field(proposal.field)
            if not field or field not in allowed_fields:
                continue
            field_ref = spl_field(field)
            values = [str(value) for value in proposal.values if str(value) in allowed_value_set]
            operator = proposal.operator

            if operator == "exists":
                filter_expressions.append(f"isnotnull({field_ref}) AND tostring({field_ref})!=\"\"")
            elif operator == "equals" and values:
                filter_expressions.append(f"tostring({field_ref})={spl_quote(values[0])}")
            elif operator == "contains" and values:
                escaped = values[0].replace("%", "\\%").replace("_", "\\_").lower()
                filter_expressions.append(
                    f"like(lower(tostring({field_ref})),{spl_quote('%' + escaped + '%')})"
                )
            elif operator == "contains_any" and values:
                ors = []
                for value in values[:12]:
                    escaped = value.replace("%", "\\%").replace("_", "\\_").lower()
                    ors.append(
                        f"like(lower(tostring({field_ref})),{spl_quote('%' + escaped + '%')})"
                    )
                if ors:
                    filter_expressions.append("(" + " OR ".join(ors) + ")")
            elif operator == "in" and values:
                ors = " OR ".join(f"tostring({field_ref})={spl_quote(value)}" for value in values[:20])
                filter_expressions.append(f"({ors})")
            elif operator in {"gt", "gte", "lt", "lte"} and values and is_numeric(values[0]):
                symbol = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[operator]
                filter_expressions.append(f"tonumber({field_ref}) {symbol} {float(values[0])}")

        group_by = [field for field in strategy.group_by if field in allowed_fields and safe_field(field)]
        if not group_by and not strategy.preserve_result_row:
            group_by = self._fallback_group_fields(source, allowed_fields)

        metrics: list[str] = []
        aliases: list[str] = []
        for position, metric in enumerate(strategy.metrics, start=1):
            alias = safe_alias(metric.alias, f"metric_{position}")
            if alias in aliases:
                continue
            if metric.function == "count":
                metrics.append(f"count as {alias}")
                aliases.append(alias)
                continue
            field = safe_field(metric.field)
            if not field or field not in allowed_fields:
                continue
            metrics.append(f"{metric.function}({spl_field(field)}) as {alias}")
            aliases.append(alias)

        if not metrics:
            metrics = ["count as event_count", "earliest(_time) as first_seen", "latest(_time) as last_seen"]
            aliases = ["event_count", "first_seen", "last_seen"]

        required_execution_fields = self._required_execution_fields(
            source,
            allowed_fields,
        )
        presence_conditions: list[str] = []
        for position, field in enumerate(required_execution_fields, start=1):
            reference = spl_field(field)
            condition = f"isnotnull({reference}) AND tostring({reference})!=\"\""
            alias = self._presence_alias(position)
            metrics.append(
                f"sum(eval(if({condition},1,0))) as {alias}"
            )
            aliases.append(alias)
            presence_conditions.append(f"({condition})")
        if presence_conditions:
            all_present = " AND ".join(presence_conditions)
            metrics.append(
                "sum(eval(if("
                + all_present
                + ",1,0))) as aria_required_all_present"
            )
            aliases.append("aria_required_all_present")

        lines = [
            f"search index={spl_quote(source.index)} sourcetype={spl_quote(source.sourcetype)} earliest={safe_time(plan.earliest, '-24h')} latest={safe_time(plan.latest, 'now')}"
        ]
        execution_event_limit = max(
            1,
            int(self.policy.get("execution_event_limit", 500)),
        )
        lines.append(f"| head {execution_event_limit}")
        lines.append("| extract")
        lines.append("| spath")
        if filter_expressions:
            lines.append("| where " + " AND ".join(f"({item})" for item in filter_expressions))

        span = safe_span(strategy.time_bucket)
        by_fields = list(group_by)
        if span:
            lines.append(f"| bin _time span={span}")
            by_fields = ["_time", *by_fields]

        rendered_by_fields = ["_time" if field == "_time" else spl_field(field) for field in by_fields]
        by_clause = " by " + " ".join(rendered_by_fields) if rendered_by_fields else ""
        lines.append("| stats " + " ".join(metrics) + by_clause)

        sort_by = strategy.sort_by if strategy.sort_by in aliases or strategy.sort_by in by_fields else None
        if not sort_by:
            sort_by = aliases[0]
        rendered_sort = sort_by if sort_by in aliases or sort_by == "_time" else spl_field(sort_by)
        direction = "-" if strategy.descending else "+"
        lines.append(f"| sort {direction} {rendered_sort}")
        limit = max(1, min(strategy.limit, int(self.policy.get("result_limit", 30))))
        lines.append(f"| head {limit}")
        return "\n".join(lines)

    @staticmethod
    def _observed_event_count(
        rows: list[dict[str, Any]],
        strategy: SearchStrategyProposal,
    ) -> int | None:
        count_aliases = [
            safe_alias(metric.alias, f"metric_{position}")
            for position, metric in enumerate(strategy.metrics, start=1)
            if metric.function == "count"
        ]
        if not count_aliases:
            return None
        observed = 0
        parsed = False
        for row in rows:
            for alias in count_aliases:
                if alias not in row:
                    continue
                try:
                    observed += max(0, int(float(row.get(alias) or 0)))
                    parsed = True
                except (TypeError, ValueError):
                    continue
        return observed if parsed else None

    @staticmethod
    def _required_execution_fields(
        source: SourceEvidenceRecord,
        allowed_fields: set[str],
    ) -> list[str]:
        output: list[str] = []
        for binding in source.requirement_bindings:
            if not binding.required or binding.status not in {"SUPPORTED", "PARTIAL"}:
                continue
            for field in binding.fields:
                if (
                    field in allowed_fields
                    and safe_field(field)
                    and field not in output
                ):
                    output.append(field)
        return output[:4]

    @staticmethod
    def _presence_alias(position: int) -> str:
        return f"aria_required_{position}_present"

    @classmethod
    def _required_field_presence(
        cls,
        rows: list[dict[str, Any]],
        fields: list[str],
    ) -> dict[str, int]:
        return {
            field: cls._sum_alias(rows, cls._presence_alias(position))
            for position, field in enumerate(fields, start=1)
        }

    @staticmethod
    def _sum_alias(
        rows: list[dict[str, Any]],
        alias: str,
    ) -> int:
        total = 0
        for row in rows:
            try:
                total += max(0, int(float(row.get(alias) or 0)))
            except (TypeError, ValueError):
                continue
        return total

    @staticmethod
    def _fallback_group_fields(source: SourceEvidenceRecord, allowed_fields: set[str]) -> list[str]:
        output: list[str] = []
        role_order = ["entity", "relationship", "activity", "outcome", "context"]
        for role in role_order:
            for binding in source.requirement_bindings:
                if binding.role == role:
                    for field in binding.fields:
                        if field in allowed_fields and field not in output:
                            output.append(field)
                            break
                if len(output) >= 3:
                    break
            if len(output) >= 3:
                break
        return output

    @staticmethod
    def _allowed_field_payload(
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
    ) -> list[dict[str, Any]]:
        roles: dict[str, list[str]] = {}
        for binding in source.requirement_bindings:
            for field in binding.fields:
                roles.setdefault(field, []).append(binding.role)
        output: list[dict[str, Any]] = []
        for item in profile.fields:
            name = str(item.get("name") or "")
            if name not in roles:
                continue
            output.append(
                {
                    "field": name,
                    "roles": sorted(set(roles[name])),
                    "count": item.get("count"),
                    "distinct_count": item.get("distinct_count"),
                    "sample_values": item.get("sample_values") or [],
                }
            )
        return output

    @staticmethod
    def _allowed_values(
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
        plan: InvestigationPlan,
    ) -> dict[str, list[str]]:
        field_map = {str(item.get("name") or ""): item for item in profile.fields}
        output: dict[str, list[str]] = {}
        bound_fields = {field for binding in source.requirement_bindings for field in binding.fields}
        for field in bound_fields:
            item = field_map.get(field, {})
            values = [str(value) for value in (item.get("sample_values") or []) if str(value)]
            if values:
                output[field] = list(dict.fromkeys(values))[:10]
        output["__analyst_supplied__"] = list(
            dict.fromkeys([*plan.explicit_entities, *plan.explicit_values])
        )
        return output
