from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from aria.copilot.contracts import (
    InvestigationPlan,
    RequirementFieldProposal,
    SourceProfileRecord,
    SourceQualificationProposal,
    SourceQualificationSet,
)
from aria.copilot.policy import evidence_policy
from aria.copilot.utils import compact_text, parse_samples
from aria.ollama_client import OllamaClient
from aria.suppressed_exception_logger import log_suppressed_exception


_TOKEN_RE = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class FieldMatch:
    field: str
    score: float
    method: str
    samples: list[str]


class SemanticFieldBinder:
    """Recover missing field bindings from observed schema only.

    The binder is scenario-agnostic. It compares investigation concepts with
    field names and observed samples using the configured local embedding model.
    It never supplies an index, sourcetype, field, value, event ID, vendor or
    security meaning that was not present in the live profile.

    Generated bindings remain proposals. The deterministic evidence qualifier
    must still validate field existence, observed values and required-field
    co-occurrence before a source can be accepted.
    """

    def __init__(self, ollama: OllamaClient) -> None:
        self.ollama = ollama
        self.policy = evidence_policy()
        self._cache: dict[str, list[float]] = {}

    def enrich(
        self,
        *,
        plan: InvestigationPlan,
        profiles: list[SourceProfileRecord],
        proposals: SourceQualificationSet,
    ) -> SourceQualificationSet:
        if not bool(self.policy.get("semantic_field_binding_enabled", True)):
            return proposals

        proposal_by_id = {item.candidate_id: item for item in proposals.sources}
        output: list[SourceQualificationProposal] = []

        for profile in profiles:
            original = proposal_by_id.get(profile.candidate_id)
            existing = {
                item.requirement_id: item
                for item in (original.requirement_mappings if original else [])
            }
            available = {
                str(item.get("name") or ""): item
                for item in profile.fields
                if str(item.get("name") or "").strip()
                and int(item.get("count") or 0) > 0
            }

            mappings: list[RequirementFieldProposal] = []
            recovered_scores: list[float] = []
            required_recovered = 0
            reserved_fields: set[str] = set()

            for requirement in plan.requirements:
                current = existing.get(requirement.requirement_id)
                current_fields = [
                    field for field in (current.fields if current else [])
                    if field in available
                ]
                if current_fields:
                    reserved_fields.update(current_fields)
                    mappings.append(
                        RequirementFieldProposal(
                            requirement_id=requirement.requirement_id,
                            status=current.status,
                            fields=current_fields,
                            rationale=current.rationale,
                        )
                    )
                    continue

                match = self._best_match(
                    requirement,
                    available,
                    excluded_fields=reserved_fields,
                )
                if match is None:
                    mappings.append(
                        RequirementFieldProposal(
                            requirement_id=requirement.requirement_id,
                            status="UNSUPPORTED",
                            fields=[],
                            rationale=(
                                "No observed field met the generic semantic-binding threshold. "
                                "ARIA preserved abstention rather than inventing a mapping."
                            ),
                        )
                    )
                    continue

                strong = match.score >= float(
                    self.policy.get("semantic_field_strong_score", 0.62)
                )
                status = "SUPPORTED" if strong and match.samples else "PARTIAL"
                mappings.append(
                    RequirementFieldProposal(
                        requirement_id=requirement.requirement_id,
                        status=status,
                        fields=[match.field],
                        rationale=(
                            f"Observed-schema semantic binding via {match.method}; "
                            f"similarity={match.score:.3f}. The field exists in the live "
                            "profile and remains subject to co-occurrence validation."
                        ),
                    )
                )
                recovered_scores.append(match.score)
                reserved_fields.add(match.field)
                if requirement.required:
                    required_recovered += 1

            required_total = sum(1 for item in plan.requirements if item.required)
            mapped_required = sum(
                1
                for item in mappings
                if item.requirement_id
                in {r.requirement_id for r in plan.requirements if r.required}
                and item.fields
            )
            coverage = mapped_required / max(1, required_total)

            original_suitability = original.suitability if original else "NONE"
            suitability = original_suitability
            if coverage >= 1.0 and all(
                item.status == "SUPPORTED"
                for item in mappings
                if item.requirement_id
                in {r.requirement_id for r in plan.requirements if r.required}
            ):
                suitability = "HIGH"
            elif coverage >= float(self.policy.get("minimum_required_coverage", 0.60)):
                suitability = "MEDIUM"
            elif coverage > 0:
                suitability = "LOW"

            reasoning_parts = []
            if original and original.source_reasoning:
                reasoning_parts.append(original.source_reasoning)
            if recovered_scores:
                reasoning_parts.append(
                    "ARIA recovered missing mappings using the configured local embedding "
                    "model over live observed field names and samples. No scenario-specific "
                    "field dictionary was used."
                )
            if not reasoning_parts:
                reasoning_parts.append(
                    "No defensible field mapping was produced from the observed profile."
                )

            output.append(
                SourceQualificationProposal(
                    candidate_id=profile.candidate_id,
                    suitability=suitability,
                    requirement_mappings=mappings,
                    source_reasoning=" ".join(reasoning_parts),
                )
            )

        return SourceQualificationSet(sources=output)

    def _best_match(
        self,
        requirement: Any,
        available: dict[str, dict[str, Any]],
        *,
        excluded_fields: set[str] | None = None,
    ) -> FieldMatch | None:
        if not available:
            return None

        field_limit = max(
            1,
            int(self.policy.get("semantic_field_binding_field_limit", 48)),
        )
        excluded = excluded_fields or set()
        fields = [
            item for item in available.items()
            if item[0] not in excluded
        ]
        fields.sort(key=lambda item: self._field_priority(item[0], item[1]))
        fields = fields[:field_limit]
        requirement_text = self._requirement_text(requirement)
        field_texts = [self._field_text(name, metadata) for name, metadata in fields]

        embedding_scores: list[float] | None = None
        try:
            vectors = self._embed_many([requirement_text, *field_texts])
            if len(vectors) == len(field_texts) + 1:
                requirement_vector = vectors[0]
                embedding_scores = [
                    self._cosine(requirement_vector, vector)
                    for vector in vectors[1:]
                ]
        except Exception as exc:
            log_suppressed_exception(
                exc,
                component="aria.copilot.semantic_binder.embedding",
            )

        ranked: list[FieldMatch] = []
        for position, (name, metadata) in enumerate(fields):
            samples = parse_samples(metadata.get("sample_values"), 4)
            lexical_text = self._field_lexical_text(name, metadata)
            lexical = self._lexical_score(str(requirement.concept or ""), lexical_text)
            metadata_penalty = 0.12 if self._is_metadata_field(name) else 0.0
            if embedding_scores is not None:
                semantic = embedding_scores[position]
                score = min(1.0, semantic + lexical * float(
                    self.policy.get("semantic_field_exact_bonus", 0.10)
                )) - metadata_penalty
                method = "LOCAL_EMBEDDING+LEXICAL_VALIDATION"
            else:
                score = lexical - metadata_penalty
                method = "LEXICAL_OBSERVED_SCHEMA_FALLBACK"
            score = max(0.0, score)
            ranked.append(
                FieldMatch(
                    field=name,
                    score=score,
                    method=method,
                    samples=samples,
                )
            )

        ranked.sort(key=lambda item: item.score, reverse=True)
        if not ranked:
            return None

        minimum = float(self.policy.get("semantic_field_min_score", 0.52))
        top = ranked[0]
        if top.score < minimum:
            return None

        margin = float(self.policy.get("semantic_field_min_margin", 0.025))
        if len(ranked) > 1 and top.score - ranked[1].score < margin:
            # Exact token overlap can resolve an otherwise ambiguous embedding tie.
            top_metadata = available.get(top.field, {})
            second_metadata = available.get(ranked[1].field, {})
            top_exact = self._lexical_score(
                str(requirement.concept or ""),
                self._field_lexical_text(top.field, top_metadata),
            )
            second_exact = self._lexical_score(
                str(requirement.concept or ""),
                self._field_lexical_text(ranked[1].field, second_metadata),
            )
            if top_exact <= second_exact:
                return None
        return top

    def _embed_many(self, texts: list[str]) -> list[list[float]]:
        missing = [text for text in texts if text not in self._cache]
        if missing:
            vectors = self.ollama.embed_texts(
                missing,
                timeout=int(
                    self.policy.get("semantic_field_embedding_timeout_seconds", 25)
                ),
            )
            if len(vectors) != len(missing):
                raise RuntimeError(
                    "Embedding response count did not match the requested text count."
                )
            for text, vector in zip(missing, vectors):
                self._cache[text] = vector
        return [self._cache[text] for text in texts]

    @staticmethod
    def _requirement_text(requirement: Any) -> str:
        return compact_text(
            f"Evidence concept: {requirement.concept}. "
            f"Semantic role: {requirement.role}. "
            f"Purpose: {requirement.reason}.",
            500,
        )

    @staticmethod
    def _field_text(name: str, metadata: dict[str, Any]) -> str:
        readable_name = re.sub(r"[_:.\-/]+", " ", name)
        samples = parse_samples(metadata.get("sample_values"), 4)
        sample_text = ", ".join(compact_text(value, 100) for value in samples)
        return compact_text(
            f"Observed field name: {name}. Readable field label: {readable_name}. "
            f"Observed sample values: {sample_text or 'none'}. "
            f"Populated events: {int(metadata.get('count') or 0)}. "
            f"Distinct observed values: {int(metadata.get('distinct_count') or 0)}.",
            700,
        )


    @staticmethod
    def _is_metadata_field(name: str) -> bool:
        value = str(name or "").lower()
        return (
            value.startswith("_")
            or value.startswith("date_")
            or value in {
                "index", "sourcetype", "source", "splunk_server",
                "splunk_server_group", "linecount", "punct",
            }
        )

    @classmethod
    def _field_priority(cls, name: str, metadata: dict[str, Any]) -> tuple[int, int, int]:
        return (
            1 if cls._is_metadata_field(name) else 0,
            0 if parse_samples(metadata.get("sample_values"), 1) else 1,
            -int(metadata.get("count") or 0),
        )

    @staticmethod
    def _field_lexical_text(name: str, metadata: dict[str, Any]) -> str:
        readable = re.sub(r"[_:.\-/]+", " ", str(name or ""))
        samples = " ".join(parse_samples(metadata.get("sample_values"), 4))
        return f"{readable} {samples}".strip()

    @classmethod
    def _lexical_score(cls, concept: str, field: str) -> float:
        concept_tokens = cls._tokens(concept)
        field_tokens = cls._tokens(re.sub(r"[_:.\-/]+", " ", field))
        if not concept_tokens or not field_tokens:
            return 0.0
        overlap = concept_tokens & field_tokens
        if not overlap:
            return 0.0
        precision = len(overlap) / len(field_tokens)
        recall = len(overlap) / len(concept_tokens)
        return (2 * precision * recall) / max(1e-9, precision + recall)

    @staticmethod
    def _tokens(text: str) -> set[str]:
        output: set[str] = set()
        for token in _TOKEN_RE.findall(str(text or "").lower()):
            if len(token) > 3 and token.endswith("ies"):
                token = token[:-3] + "y"
            elif len(token) > 3 and token.endswith("s"):
                token = token[:-1]
            output.add(token)
        return output

    @staticmethod
    def _cosine(left: list[float], right: list[float]) -> float:
        if not left or not right or len(left) != len(right):
            return 0.0
        dot = sum(a * b for a, b in zip(left, right))
        left_norm = math.sqrt(sum(value * value for value in left))
        right_norm = math.sqrt(sum(value * value for value in right))
        if left_norm <= 0 or right_norm <= 0:
            return 0.0
        return max(-1.0, min(1.0, dot / (left_norm * right_norm)))
