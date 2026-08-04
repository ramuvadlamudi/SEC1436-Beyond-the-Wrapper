from __future__ import annotations

import json
import re
from typing import Any

from aria.copilot.contracts import InvestigationPlan, SourceProfileRecord
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import bounded_rows, parse_samples, safe_field, safe_time, spl_field, spl_quote
from aria.config import settings
from aria.models import CandidateSource
from aria.splunk_client import SplunkClient


class LiveTelemetryAgent:
    """Collect and qualify telemetry from the connected Splunk instance in real time."""

    def __init__(self, splunk: SplunkClient) -> None:
        self.splunk = splunk
        self.policy = evidence_policy()

    def live_catalog(
        self,
        earliest: str | None = None,
        latest: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return live catalog rows, scoped to the investigation range when supplied."""
        rows: list[dict[str, Any]] = []

        if earliest is not None or latest is not None:
            safe_earliest = safe_time(earliest or "-24h", "-24h")
            safe_latest = safe_time(latest or "now", "now")
            limit = max(1, int(settings.catalog_limit))
            spl = f"""| tstats count as event_count earliest(_time) as first_seen latest(_time) as last_seen where index=* earliest={safe_earliest} latest={safe_latest} by index sourcetype
| sort - event_count
| head {limit}"""
            try:
                raw_rows = self.splunk.search(spl)
            except Exception:
                raw_rows = []
            for position, row in enumerate(raw_rows, start=1):
                index = str(row.get("index") or "").strip()
                sourcetype = str(row.get("sourcetype") or "").strip()
                if not index or not sourcetype:
                    continue
                try:
                    event_count = int(float(row.get("event_count") or 0))
                except Exception:
                    event_count = 0
                rows.append(
                    {
                        "candidate_id": f"C{position}",
                        "index": index,
                        "sourcetype": sourcetype,
                        "event_count": event_count,
                        "first_seen": row.get("first_seen"),
                        "last_seen": row.get("last_seen"),
                        "catalog_scope": f"{safe_earliest}..{safe_latest}",
                    }
                )
            if rows:
                return rows

        items = self.splunk.discover_catalog()
        for position, item in enumerate(items, start=1):
            rows.append(
                {
                    "candidate_id": f"C{position}",
                    "index": item.index,
                    "sourcetype": item.sourcetype,
                    "event_count": int(item.event_count or 0),
                    "first_seen": item.first_seen,
                    "last_seen": item.last_seen,
                    "catalog_scope": "all_available_time",
                }
            )
        return rows

    def locate_explicit_values(
        self,
        plan: InvestigationPlan,
        limit: int,
    ) -> tuple[list[dict[str, Any]], str, bool]:
        values = [*plan.explicit_entities, *plan.explicit_values]
        values = list(dict.fromkeys(value for value in values if value))
        if not values:
            return [], plan.earliest, False

        earliest = safe_time(plan.earliest, "-24h")
        latest = safe_time(plan.latest, "now")
        rows = self._value_locator(values, earliest, latest, limit)
        fallback_used = False

        if not rows and not plan.time_range_explicit and earliest != "0":
            rows = self._value_locator(values, "0", latest, limit)
            if rows:
                earliest = "0"
                fallback_used = True

        output: list[dict[str, Any]] = []
        for position, row in enumerate(rows, start=1):
            index = str(row.get("index") or "").strip()
            sourcetype = str(row.get("sourcetype") or "").strip()
            if not index or not sourcetype:
                continue
            output.append(
                {
                    "candidate_id": f"V{position}",
                    "index": index,
                    "sourcetype": sourcetype,
                    "event_count": int(float(row.get("event_count") or 0)),
                    "first_seen": row.get("first_seen"),
                    "last_seen": row.get("last_seen"),
                    "locator_values": values,
                    "locator_method": "analyst_value_raw_search",
                }
            )
        return output, earliest, fallback_used

    def _value_locator(
        self,
        values: list[str],
        earliest: str,
        latest: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        value_search = " OR ".join(spl_quote(value) for value in values)
        spl = f"""search index=* earliest={earliest} latest={latest} ({value_search})
| stats count as event_count earliest(_time) as first_seen latest(_time) as last_seen by index sourcetype
| sort - event_count
| head {max(1, min(limit, 20))}"""
        return self.splunk.search(spl)

    def profile_candidates(
        self,
        candidates: list[dict[str, Any]],
        plan: InvestigationPlan,
    ) -> list[SourceProfileRecord]:
        output: list[SourceProfileRecord] = []
        field_limit = int(self.policy.get("profile_field_limit", 32))
        sample_limit = int(self.policy.get("profile_sample_value_limit", 4))

        for candidate in candidates:
            candidate_id = str(candidate.get("candidate_id") or "")
            index = str(candidate.get("index") or "")
            sourcetype = str(candidate.get("sourcetype") or "")
            if not candidate_id or not index or not sourcetype:
                continue

            try:
                candidate_source = CandidateSource(
                    index=index,
                    sourcetype=sourcetype,
                    rationale="live_profile",
                )
                profile = self.splunk.profile_source(
                    candidate_source,
                    earliest=plan.earliest,
                    latest=plan.latest,
                )
                fields: list[dict[str, Any]] = []
                for field in profile.fields[:field_limit]:
                    if not safe_field(field.name):
                        continue
                    fields.append(
                        {
                            "name": field.name,
                            "count": field.count,
                            "distinct_count": field.distinct_count,
                            "sample_values": parse_samples(field.sample_values, sample_limit),
                        }
                    )

                catalog_event_count = int(candidate.get("event_count") or 0)
                source_event_count = 0
                profile_error: str | None = None
                if not fields:
                    try:
                        source_event_count = self.splunk.source_event_count(
                            candidate=candidate_source,
                            earliest=plan.earliest,
                            latest=plan.latest,
                        )
                    except Exception as count_exc:
                        profile_error = (
                            "LIVE_SOURCE_COUNT_PROBE_FAILED: "
                            f"{count_exc.__class__.__name__}: {count_exc}"
                        )

                    if profile_error is None and source_event_count > 0:
                        profile_error = (
                            "RAW_EVENTS_VISIBLE_BUT_FIELDS_UNAVAILABLE: "
                            "the read-only source count succeeded but bounded raw profiling "
                            "returned no usable observed fields"
                        )
                    elif profile_error is None and catalog_event_count > 0:
                        profile_error = (
                            "CATALOG_VISIBLE_RAW_SEARCH_UNAVAILABLE: "
                            "tstats catalog metadata shows events, but the current Splunk "
                            "search context returned no raw events for field validation"
                        )

                output.append(
                    SourceProfileRecord(
                        candidate_id=candidate_id,
                        index=index,
                        sourcetype=sourcetype,
                        event_count=max(catalog_event_count, source_event_count),
                        first_seen=candidate.get("first_seen"),
                        last_seen=candidate.get("last_seen"),
                        fields=fields,
                        profile_error=profile_error,
                    )
                )
            except Exception as exc:
                output.append(
                    SourceProfileRecord(
                        candidate_id=candidate_id,
                        index=index,
                        sourcetype=sourcetype,
                        event_count=int(candidate.get("event_count") or 0),
                        first_seen=candidate.get("first_seen"),
                        last_seen=candidate.get("last_seen"),
                        fields=[],
                        profile_error=f"{exc.__class__.__name__}: {exc}",
                    )
                )
        return output

    def cooccurrence_probe(
        self,
        profile: SourceProfileRecord,
        fields: list[str],
        earliest: str,
        latest: str,
    ) -> dict[str, Any]:
        unique_fields = list(dict.fromkeys(field for field in fields if safe_field(field)))
        if not unique_fields:
            return {"sampled_events": 0, "fully_bound_events": 0, "field_presence": {}}

        event_limit = int(self.policy.get("cooccurrence_event_limit", 500))
        field_expressions: list[str] = []
        all_conditions: list[str] = []
        for position, field in enumerate(unique_fields, start=1):
            reference = spl_field(field)
            condition = f"isnotnull({reference}) AND tostring({reference})!=\"\""
            all_conditions.append(f"({condition})")
            field_expressions.append(f"sum(eval(if({condition},1,0))) as aria_field_{position}_present")

        all_present = " AND ".join(all_conditions)
        metrics = ", ".join(field_expressions)
        spl = f"""search index={spl_quote(profile.index)} sourcetype={spl_quote(profile.sourcetype)} earliest={safe_time(earliest, '-24h')} latest={safe_time(latest, 'now')}
| head {event_limit}
| extract
| spath
| stats count as sampled_events sum(eval(if({all_present},1,0))) as fully_bound_events {metrics}"""
        rows = self.splunk.search(spl)
        row = rows[0] if rows else {}
        presence: dict[str, int] = {}
        for position, field in enumerate(unique_fields, start=1):
            try:
                presence[field] = int(float(row.get(f"aria_field_{position}_present") or 0))
            except Exception:
                presence[field] = 0
        try:
            sampled = int(float(row.get("sampled_events") or 0))
        except Exception:
            sampled = 0
        try:
            fully_bound = int(float(row.get("fully_bound_events") or 0))
        except Exception:
            fully_bound = 0
        return {
            "sampled_events": sampled,
            "fully_bound_events": fully_bound,
            "field_presence": presence,
            "spl": spl,
        }

    def intent_value_probe(
        self,
        profile: SourceProfileRecord,
        terms: list[str],
        earliest: str,
        latest: str,
        *,
        field_limit: int | None = None,
    ) -> dict[str, Any]:
        """Validate analyst intent terms against bounded live values.

        The probe is scenario-agnostic. It derives term variants from analyst text,
        searches only the accepted live source, and measures value support per
        observed field plus Splunk's `_raw` event text. Field presence alone is not
        treated as intent evidence.
        """
        clean_terms = [str(term).strip() for term in terms if str(term).strip()]
        clean_terms = list(dict.fromkeys(clean_terms))[:6]
        if not clean_terms:
            return {
                "sampled_events": 0,
                "terms": [],
                "fields": [],
                "best_field": None,
                "all_terms_hits": 0,
                "validated_variants": {},
                "spl": "",
            }

        configured_limit = int(self.policy.get("build_spl_value_probe_field_limit", 24))
        max_fields = max(1, min(field_limit or configured_limit, configured_limit))
        observed_fields: list[str] = []
        for item in profile.fields:
            name = safe_field(str(item.get("name") or ""))
            if not name or name == "_raw" or name in observed_fields:
                continue
            observed_fields.append(name)
        fields = ["_raw", *observed_fields[: max_fields - 1]]

        def variants(term: str) -> list[str]:
            lower = term.lower().strip()
            spaced = re.sub(r"[-_./:]+", " ", lower)
            compact = re.sub(r"[-_./:\s]+", "", lower)
            return list(dict.fromkeys(value for value in (lower, spaced, compact) if len(value) >= 2))

        term_variants = {term: variants(term) for term in clean_terms}
        event_limit = int(self.policy.get("build_spl_value_probe_event_limit", 500))
        metrics = ["count as aria_value_probe_sampled"]
        aliases: dict[tuple[int, int], str] = {}
        all_aliases: dict[int, str] = {}

        for field_pos, field in enumerate(fields, start=1):
            field_ref = spl_field(field)
            term_conditions: list[str] = []
            for term_pos, term in enumerate(clean_terms, start=1):
                conditions = []
                for value in term_variants[term]:
                    escaped = value.replace("%", "\\%").replace("_", "\\_")
                    conditions.append(
                        f"like(lower(tostring({field_ref})),{spl_quote('%' + escaped + '%')})"
                    )
                condition = "(" + " OR ".join(conditions) + ")"
                term_conditions.append(condition)
                alias = f"aria_vf{field_pos}_t{term_pos}"
                aliases[(field_pos, term_pos)] = alias
                metrics.append(f"sum(eval(if({condition},1,0))) as {alias}")
            all_condition = " AND ".join(term_conditions)
            all_alias = f"aria_vf{field_pos}_all"
            all_aliases[field_pos] = all_alias
            metrics.append(f"sum(eval(if({all_condition},1,0))) as {all_alias}")

        spl = (
            f"search index={spl_quote(profile.index)} sourcetype={spl_quote(profile.sourcetype)} "
            f"earliest={safe_time(earliest, '-24h')} latest={safe_time(latest, 'now')}\n"
            f"| head {event_limit}\n"
            "| stats " + " ".join(metrics)
        )
        rows = self.splunk.search(spl)
        row = rows[0] if rows else {}
        try:
            sampled = int(float(row.get("aria_value_probe_sampled") or 0))
        except Exception:
            sampled = 0

        field_results: list[dict[str, Any]] = []
        best_field: str | None = None
        best_hits = 0
        best_score = (0, 0)
        best_validated: dict[str, list[str]] = {}
        for field_pos, field in enumerate(fields, start=1):
            term_hits: dict[str, int] = {}
            validated: dict[str, list[str]] = {}
            for term_pos, term in enumerate(clean_terms, start=1):
                try:
                    count = int(float(row.get(aliases[(field_pos, term_pos)]) or 0))
                except Exception:
                    count = 0
                term_hits[term] = count
                if count > 0:
                    validated[term] = term_variants[term]
            try:
                all_hits = int(float(row.get(all_aliases[field_pos]) or 0))
            except Exception:
                all_hits = 0
            field_results.append({
                "field": field,
                "all_terms_hits": all_hits,
                "term_hits": term_hits,
                "validated_variants": validated,
            })
            field_score = (all_hits, 1 if field != "_raw" else 0)
            if field_score > best_score:
                best_score = field_score
                best_hits = all_hits
                best_field = field
                best_validated = validated

        field_results.sort(
            key=lambda item: (int(item.get("all_terms_hits") or 0), item.get("field") != "_raw"),
            reverse=True,
        )
        return {
            "sampled_events": sampled,
            "terms": clean_terms,
            "fields": field_results,
            "best_field": best_field,
            "all_terms_hits": best_hits,
            "validated_variants": best_validated,
            "spl": spl,
        }

    def sample_rows(
        self,
        profile: SourceProfileRecord,
        fields: list[str],
        earliest: str,
        latest: str,
        limit: int = 20,
    ) -> tuple[str, list[dict[str, Any]]]:
        safe_fields = list(dict.fromkeys(field for field in fields if safe_field(field)))
        table_fields = " ".join(["_time", *safe_fields])
        spl = f"""search index={spl_quote(profile.index)} sourcetype={spl_quote(profile.sourcetype)} earliest={safe_time(earliest, '-24h')} latest={safe_time(latest, 'now')}
| table {table_fields}
| head {max(1, min(limit, 100))}"""
        return spl, bounded_rows(self.splunk.search(spl), limit)

    def profile_prompt_records(self, profiles: list[SourceProfileRecord]) -> list[dict[str, Any]]:
        """Return compact live profiles for bounded local-model qualification.

        Splunk metadata fields remain available to deterministic validation, but
        the generative model receives data-bearing fields first so a large
        fieldsummary cannot crowd the useful fields out of the prompt. This is
        generic prompt hygiene, not a customer field mapping.
        """
        limit = max(1, int(self.policy.get("qualification_prompt_field_limit", 24)))
        output: list[dict[str, Any]] = []
        for profile in profiles:
            record = profile.model_dump()
            fields = list(record.get("fields") or [])

            def metadata_rank(item: dict[str, Any]) -> tuple[int, int]:
                name = str(item.get("name") or "").lower()
                metadata = (
                    name.startswith("_")
                    or name.startswith("date_")
                    or name.startswith("time")
                    or name in {
                        "index", "sourcetype", "source", "splunk_server",
                        "splunk_server_group", "linecount", "punct",
                    }
                )
                populated = int(item.get("count") or 0)
                return (1 if metadata else 0, -populated)

            fields.sort(key=metadata_rank)
            record["fields"] = fields[:limit]
            output.append(record)
        return output
