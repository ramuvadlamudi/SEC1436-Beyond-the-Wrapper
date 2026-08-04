from __future__ import annotations

import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any

from aria.copilot.contracts import EvidenceRequirement, InvestigationPlan, SourceProfileRecord
from aria.copilot.telemetry_agent import LiveTelemetryAgent
from aria.ollama_client import OllamaClient
from aria.splunk_client import SplunkClient
from aria.suppressed_exception_logger import log_suppressed_exception
from aria.v3.contracts import BehaviourIntent, FieldBinding, SourceAssessment, SourceConstraint
from aria.v3.utils import compact_text, salient_terms, tokens


_METADATA_NAMES = {
    "index", "sourcetype", "source", "splunk_server", "splunk_server_group",
    "linecount", "punct",
}

_AGGREGATION_BINDING_NOISE = {
    "activity", "aggregation", "analyst", "count", "distinct", "field",
    "group", "grouping", "measured", "measurement", "originate", "originating",
    "related", "the", "used", "value", "values",
}


class TelemetryIntelligenceService:
    """Shared deployment intelligence for all ARIA v3 agents.

    The service discovers the connected Splunk catalogue and observed source schemas.
    It contains no customer index, sourcetype, event-ID or field mapping. Optional
    local embeddings rank live labels and observed fields; deterministic lexical
    ranking remains available when the embedding model is unavailable.
    """

    def __init__(self, splunk: SplunkClient, ollama: OllamaClient) -> None:
        self.splunk = splunk
        self.ollama = ollama
        self.telemetry = LiveTelemetryAgent(splunk)
        self.cache_path = Path(os.getenv("ARIA_V3_TELEMETRY_CACHE", "data/telemetry_intelligence_v3.json"))
        self.cache_ttl = max(60, int(os.getenv("ARIA_V3_TELEMETRY_CACHE_TTL_SECONDS", "900")))
        self._catalog_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._profile_cache: dict[str, tuple[float, SourceProfileRecord]] = {}
        self._embedding_cache: dict[str, list[float]] = {}
        self._load_cache()

    def catalog(self, earliest: str, latest: str, *, refresh: bool = False) -> list[dict[str, Any]]:
        key = f"{earliest}..{latest}"
        cached = self._catalog_cache.get(key)
        if cached and not refresh and time.time() - cached[0] <= self.cache_ttl:
            return [dict(item) for item in cached[1]]
        rows = self.telemetry.live_catalog(earliest, latest)
        self._catalog_cache[key] = (time.time(), [dict(item) for item in rows])
        self._save_cache()
        return rows

    def rank_sources(
        self,
        intent: BehaviourIntent,
        catalog: list[dict[str, Any]],
        constraint: SourceConstraint,
        *,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        explicit: list[dict[str, Any]] = []
        remaining: list[dict[str, Any]] = []
        for row in catalog:
            index = str(row.get("index") or "")
            sourcetype = str(row.get("sourcetype") or "")
            index_ok = constraint.index is None or index == constraint.index
            st_ok = constraint.sourcetype is None or sourcetype == constraint.sourcetype
            if index_ok and st_ok and (constraint.index is not None or constraint.sourcetype is not None):
                explicit.append(dict(row))
            else:
                remaining.append(dict(row))

        # When the analyst supplies both source coordinates, evaluate that exact
        # source first and do not burn the latency budget on unrelated telemetry.
        if constraint.index and constraint.sourcetype:
            return explicit[:1]

        query = self._intent_text(intent)
        query_tokens = set(tokens(query))
        labels = [self._catalog_text(row) for row in remaining]
        semantic_scores: list[float] | None = None
        try:
            vectors = self._embed_many([query, *labels])
            if len(vectors) == len(labels) + 1:
                semantic_scores = [self._cosine(vectors[0], vector) for vector in vectors[1:]]
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.telemetry.catalog_embedding")

        ranked: list[tuple[float, int, dict[str, Any]]] = []
        for position, row in enumerate(remaining):
            label_text = labels[position]
            label_tokens = set(tokens(label_text))
            overlap = len(query_tokens & label_tokens)
            lexical = overlap / max(1, len(query_tokens))
            semantic = semantic_scores[position] if semantic_scores is not None else 0.0
            exact = 1.0 if any(term in label_tokens for term in intent.behaviour_terms) else 0.0
            score = exact * 4.0 + lexical * 2.0 + semantic
            event_count = int(row.get("event_count") or 0)
            ranked.append((score, event_count, row))
        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
        output = [*explicit]
        seen = {(str(item.get("index")), str(item.get("sourcetype"))) for item in output}
        for _, _, row in ranked:
            key = (str(row.get("index")), str(row.get("sourcetype")))
            if key in seen:
                continue
            output.append(row)
            seen.add(key)
            if len(output) >= max(1, limit):
                break
        return output[: max(1, limit)]

    def profile(
        self,
        candidate: dict[str, Any],
        *,
        earliest: str,
        latest: str,
        refresh: bool = False,
    ) -> SourceProfileRecord:
        index = str(candidate.get("index") or "")
        sourcetype = str(candidate.get("sourcetype") or "")
        key = f"{index}|{sourcetype}|{earliest}|{latest}"
        cached = self._profile_cache.get(key)
        if cached and not refresh and time.time() - cached[0] <= self.cache_ttl:
            return cached[1].model_copy(deep=True)
        plan = InvestigationPlan(
            capability="QUERY_SPLUNK",
            goal="ARIA v3 telemetry profile",
            earliest=earliest,
            latest=latest,
            time_range_explicit=True,
            execute_read_only_search=False,
            requirements=[],
        )
        profiles = self.telemetry.profile_candidates([candidate], plan)
        profile = profiles[0] if profiles else SourceProfileRecord(
            candidate_id=str(candidate.get("candidate_id") or "C1"),
            index=index,
            sourcetype=sourcetype,
            event_count=int(candidate.get("event_count") or 0),
            fields=[],
            profile_error="PROFILE_NOT_RETURNED",
        )
        self._profile_cache[key] = (time.time(), profile.model_copy(deep=True))
        self._save_cache()
        return profile

    def assess_source(self, profile: SourceProfileRecord, intent: BehaviourIntent) -> SourceAssessment:
        bindings = self.bind_fields(profile, intent)
        required_ids = {item.concept_id for item in intent.concepts if item.required}
        supported = sum(1 for item in bindings if item.concept_id in required_ids and item.field)
        total = len(required_ids)
        has_profile = bool(profile.fields) and not bool(profile.profile_error)
        activity_supported = any(item.role == "activity" and item.field for item in bindings)
        strict_aggregation = any(
            item.required and item.role == "quantity"
            for item in intent.concepts
        )
        schema_qualified = has_profile and (
            total == 0
            or supported == total
            or (activity_supported and not strict_aggregation)
        )
        rationale: list[str] = []
        if profile.profile_error:
            rationale.append(profile.profile_error)
        if has_profile:
            rationale.append(f"Observed {len(profile.fields)} populated fields in the bounded live profile.")
        if activity_supported:
            rationale.append("At least one observed field can carry the requested activity context.")
        elif has_profile:
            rationale.append("No observed field was strong enough to bind to the activity concept; `_raw` remains available for generic text filtering.")
        if strict_aggregation and supported < total:
            missing = [
                item.description
                for item in intent.concepts
                if item.required
                and not any(
                    binding.concept_id == item.concept_id and binding.field
                    for binding in bindings
                )
            ]
            rationale.append(
                "Aggregation schema qualification requires every analyst-requested "
                "measurement and grouping concept to have deterministic lexical "
                "corroboration in an observed field name or sample; missing: "
                + ", ".join(missing)
                + "."
            )
        return SourceAssessment(
            candidate_id=profile.candidate_id,
            index=profile.index,
            sourcetype=profile.sourcetype,
            event_count=profile.event_count,
            first_seen=profile.first_seen,
            last_seen=profile.last_seen,
            profile_error=profile.profile_error,
            fields_observed=len(profile.fields),
            bindings=bindings,
            required_bindings_supported=supported,
            required_bindings_total=total,
            schema_qualified=schema_qualified,
            rationale=rationale,
        )

    def bind_fields(self, profile: SourceProfileRecord, intent: BehaviourIntent) -> list[FieldBinding]:
        field_items = [item for item in profile.fields if str(item.get("name") or "").strip()]
        if not field_items or not intent.concepts:
            return []
        field_texts = [self._field_text(item) for item in field_items]
        output: list[FieldBinding] = []
        reserved: set[str] = set()
        ordered_concepts = list(intent.concepts)
        if any(
            item.required and item.concept_id.startswith("ARIA_")
            for item in ordered_concepts
        ):
            ordered_concepts.sort(
                key=lambda item: (
                    0 if item.required and item.concept_id.startswith("ARIA_")
                    else 1 if item.required
                    else 2
                )
            )
        for concept in ordered_concepts:
            concept_text = f"Role: {concept.role}. Observable concept: {concept.description}."
            scores: list[float] = []
            method = "LEXICAL_OBSERVED_SCHEMA"
            try:
                vectors = self._embed_many([concept_text, *field_texts])
                if len(vectors) == len(field_texts) + 1:
                    scores = [self._cosine(vectors[0], vector) for vector in vectors[1:]]
                    method = "LOCAL_EMBEDDING+LEXICAL_VALIDATION"
            except Exception as exc:
                log_suppressed_exception(exc, component="aria.v3.telemetry.field_embedding")
            ranked: list[tuple[float, dict[str, Any]]] = []
            concept_tokens = set(tokens(concept.description))
            for position, item in enumerate(field_items):
                name = str(item.get("name") or "")
                field_tokens = set(tokens(self._field_text(item)))
                overlap = len(concept_tokens & field_tokens) / max(1, len(concept_tokens))
                semantic = scores[position] if scores else 0.0
                penalty = 0.18 if self._metadata_field(name) else 0.0
                score = max(0.0, semantic + overlap * 0.15 - penalty)
                ranked.append((score, item))
            ranked.sort(key=lambda pair: pair[0], reverse=True)
            threshold = float(os.getenv("ARIA_V3_FIELD_BINDING_MIN_SCORE", "0.50"))
            aggregation_required = bool(
                concept.required and concept.concept_id.startswith("ARIA_")
            )
            if aggregation_required:
                selected = next(
                    (
                        (score, item)
                        for score, item in ranked
                        if str(item.get("name")) not in reserved
                        and score >= threshold
                        and self._aggregation_binding_corroborated(concept, item)
                    ),
                    None,
                )
            else:
                selected = next(
                    (
                        (score, item)
                        for score, item in ranked
                        if str(item.get("name")) not in reserved
                    ),
                    None,
                )
            if selected and selected[0] >= threshold:
                score, item = selected
                name = str(item.get("name") or "")
                reserved.add(name)
                samples = [str(value) for value in (item.get("sample_values") or [])[:4]]
                binding_method = (
                    method + "+DETERMINISTIC_LEXICAL_CORROBORATION"
                    if aggregation_required
                    else method
                )
                output.append(FieldBinding(
                    concept_id=concept.concept_id,
                    role=concept.role,
                    description=concept.description,
                    field=name,
                    score=min(1.0, score),
                    method=binding_method,
                    observed_samples=samples,
                    populated_events=int(item.get("count") or 0),
                ))
            else:
                top_score = ranked[0][0] if ranked else 0.0
                output.append(FieldBinding(
                    concept_id=concept.concept_id,
                    role=concept.role,
                    description=concept.description,
                    field=None,
                    score=min(1.0, selected[0] if selected else top_score),
                    method=(
                        method + "+CORROBORATION_FAILED"
                        if aggregation_required
                        else method
                    ),
                ))
        return output

    @classmethod
    def _aggregation_binding_corroborated(
        cls,
        concept: Any,
        field: dict[str, Any],
    ) -> bool:
        """Require a second deterministic signal for aggregation field binding.

        Embedding similarity alone is insufficient for a field that will control
        an analyst-supplied metric or grouping. Corroboration uses only the
        analyst-derived concept and the live observed field name/samples.
        """

        concept_tokens = cls._binding_tokens(str(concept.description or ""))
        concept_tokens.difference_update(_AGGREGATION_BINDING_NOISE)
        if not concept_tokens:
            return False
        name = re.sub(r"[_:./-]+", " ", str(field.get("name") or ""))
        samples = " ".join(str(item) for item in (field.get("sample_values") or [])[:8])
        observed_tokens = cls._binding_tokens(f"{name} {samples}")
        return bool(concept_tokens & observed_tokens)

    @staticmethod
    def _binding_tokens(text: str) -> set[str]:
        output: set[str] = set()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9]*", str(text or "").lower()):
            output.add(token)
            if token.endswith("ies") and len(token) > 4:
                output.add(token[:-3] + "y")
            elif token.endswith("es") and len(token) > 4:
                output.add(token[:-2])
            elif token.endswith("s") and len(token) > 3:
                output.add(token[:-1])
        return output

    def cooccurrence(self, profile: SourceProfileRecord, fields: list[str], earliest: str, latest: str) -> dict[str, Any]:
        return self.telemetry.cooccurrence_probe(profile, fields, earliest, latest)

    def sample_rows(self, profile: SourceProfileRecord, fields: list[str], earliest: str, latest: str, limit: int = 20) -> tuple[str, list[dict[str, Any]]]:
        return self.telemetry.sample_rows(profile, fields, earliest, latest, limit)

    def _embed_many(self, texts: list[str]) -> list[list[float]]:
        missing = [text for text in texts if text not in self._embedding_cache]
        if missing:
            vectors = self.ollama.embed_texts(missing, timeout=int(os.getenv("ARIA_V3_EMBED_TIMEOUT_SECONDS", "20")))
            if len(vectors) != len(missing):
                raise RuntimeError("Embedding response count mismatch.")
            for text, vector in zip(missing, vectors):
                self._embedding_cache[text] = vector
        return [self._embedding_cache[text] for text in texts]

    @staticmethod
    def _cosine(left: list[float], right: list[float]) -> float:
        if not left or not right or len(left) != len(right):
            return 0.0
        dot = sum(a * b for a, b in zip(left, right))
        left_norm = math.sqrt(sum(a * a for a in left))
        right_norm = math.sqrt(sum(b * b for b in right))
        if left_norm == 0 or right_norm == 0:
            return 0.0
        return dot / (left_norm * right_norm)

    @staticmethod
    def _catalog_text(row: dict[str, Any]) -> str:
        index = str(row.get("index") or "")
        sourcetype = str(row.get("sourcetype") or "")
        readable = re.sub(r"[_:./-]+", " ", f"{index} {sourcetype}")
        return f"Live Splunk source label: {index} {sourcetype}. Readable label: {readable}."

    @staticmethod
    def _intent_text(intent: BehaviourIntent) -> str:
        concepts = "; ".join(item.description for item in intent.concepts)
        return compact_text(f"{intent.summary}. Terms: {' '.join(intent.behaviour_terms)}. Concepts: {concepts}", 1200)

    @staticmethod
    def _field_text(item: dict[str, Any]) -> str:
        name = str(item.get("name") or "")
        readable = re.sub(r"[_:./-]+", " ", name)
        samples = ", ".join(compact_text(value, 100) for value in (item.get("sample_values") or [])[:4])
        return compact_text(
            f"Observed field: {name}. Readable label: {readable}. Observed samples: {samples or 'none'}. "
            f"Populated events: {int(item.get('count') or 0)}. Distinct values: {int(item.get('distinct_count') or 0)}.",
            700,
        )

    @staticmethod
    def _metadata_field(name: str) -> bool:
        value = str(name or "").lower()
        return value.startswith("_") or value.startswith("date_") or value in _METADATA_NAMES

    def _load_cache(self) -> None:
        try:
            if not self.cache_path.exists():
                return
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            for key, record in (payload.get("catalog") or {}).items():
                self._catalog_cache[key] = (float(record.get("timestamp") or 0), list(record.get("rows") or []))
            for key, record in (payload.get("profiles") or {}).items():
                self._profile_cache[key] = (
                    float(record.get("timestamp") or 0),
                    SourceProfileRecord.model_validate(record.get("profile") or {}),
                )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.telemetry.cache_load")

    def _save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "catalog": {
                    key: {"timestamp": timestamp, "rows": rows}
                    for key, (timestamp, rows) in self._catalog_cache.items()
                },
                "profiles": {
                    key: {"timestamp": timestamp, "profile": profile.model_dump()}
                    for key, (timestamp, profile) in self._profile_cache.items()
                },
            }
            temp = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
            temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            temp.replace(self.cache_path)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.telemetry.cache_save")
