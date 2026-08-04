from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Callable

from aria.copilot.catalog_ranker import deterministic_catalog_selection
from aria.copilot.contracts import (
    EvidenceRequirement,
    InvestigationHypothesis,
    InvestigationPlan,
    FilterProposal,
    MetricProposal,
    SearchStrategyProposal,
    SourceEvidenceRecord,
    SourceProfileRecord,
    SourceQualificationSet,
)
from aria.copilot.evidence_qualifier import DeterministicEvidenceQualifier
from aria.copilot.policy import evidence_policy
from aria.copilot.semantic_binder import SemanticFieldBinder
from aria.copilot.spl_agent import EvidenceBoundSPLAgent
from aria.copilot.spl_builder import DeterministicSPLBuilder, SPLBuildOutcome
from aria.copilot.telemetry_agent import LiveTelemetryAgent
from aria.copilot.utils import compact_text
from aria.ollama_client import OllamaClient
from aria.suppressed_exception_logger import log_suppressed_exception


ProgressCallback = Callable[[str, str, str], None]
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]*", re.IGNORECASE)
_CONTROL_WORDS = {
    "a", "an", "and", "all", "analyse", "analyze", "available", "build",
    "catalog", "connected", "create", "data", "discover", "environment",
    "execute", "for", "from", "generate", "give", "in", "intent", "live",
    "me", "of", "on", "or", "please", "query", "report", "search", "spl",
    "splunk", "the", "this", "time", "to", "using", "validate", "verify",
    "with", "write", "across", "but", "do", "not", "final", "generated",
    "activity", "behaviour", "behavior", "event", "events", "execution",
    "investigate", "investigation", "unusual", "suspicious", "specific",
    "specified", "range", "use", "analysing", "analyzing",
}


@dataclass
class BuildDiscoveryResult:
    plan: InvestigationPlan
    catalog_rows: int
    profiles: list[SourceProfileRecord]
    evidence: list[SourceEvidenceRecord]
    accepted: list[SourceEvidenceRecord]
    scanned_profiles: int
    total_catalog_rows: int
    scan_complete: bool
    elapsed_seconds: float
    value_probes: dict[str, dict[str, Any]]


class BuildSPLWorkbench:
    """Scenario-agnostic live schema discovery for the dual SPL builder.

    The workbench evaluates every visible catalogue label, ranks candidates using
    local embeddings plus generic lexical overlap, then profiles candidates in
    progressive batches. Source acceptance still requires observed fields and a
    bounded co-occurrence probe. No product dictionary maps security scenarios to
    indexes, sourcetypes or fields.
    """

    def __init__(
        self,
        *,
        ollama: OllamaClient,
        telemetry: LiveTelemetryAgent,
        binder: SemanticFieldBinder,
        qualifier: DeterministicEvidenceQualifier,
        spl_agent: EvidenceBoundSPLAgent,
        spl_builder: DeterministicSPLBuilder,
    ) -> None:
        self.ollama = ollama
        self.telemetry = telemetry
        self.binder = binder
        self.qualifier = qualifier
        self.spl_agent = spl_agent
        self.spl_builder = spl_builder
        self.policy = evidence_policy()
        self._embedding_cache: dict[str, list[float]] = {}

    def create_plan(self, question: str, generic: SPLBuildOutcome) -> InvestigationPlan:
        earliest = generic.resolved_bindings.get("earliest") or "-24h"
        latest = generic.resolved_bindings.get("latest") or "now"
        intent = compact_text(generic.intent_summary or self.spl_builder.extract_intent(question), 320)
        terms = self.salient_terms(intent)
        value_concept = " ".join(terms[:6]) or intent
        term_variants = [
            variant
            for term in terms
            for variant in self.spl_builder.term_variants(term)
        ]
        explicit_values = list(dict.fromkeys([
            *terms,
            *term_variants,
            *self.spl_builder.explicit_condition_literals(question),
        ]))[:30]

        requirements = [
            EvidenceRequirement(
                requirement_id="B1",
                concept=value_concept,
                role="activity",
                required=True,
                reason=(
                    "A live content-bearing field must be semantically aligned to the "
                    "analyst's requested security activity before environment-specific SPL is emitted."
                ),
            ),
            EvidenceRequirement(
                requirement_id="B2",
                concept="command, script, process, event message, or other activity content",
                role="context",
                required=False,
                reason="Provides a field that can express the analyst's activity filter.",
            ),
            EvidenceRequirement(
                requirement_id="B3",
                concept="originating host, user, process, or other entity context",
                role="entity",
                required=False,
                reason="Provides analyst context for grouping and review when observed.",
            ),
            EvidenceRequirement(
                requirement_id="B4",
                concept="event outcome, action, response, or state",
                role="outcome",
                required=False,
                reason="Provides an outcome dimension when the live schema exposes one.",
            ),
        ]
        return InvestigationPlan(
            capability="BUILD_SPL",
            goal=compact_text(question, 1000),
            earliest=earliest,
            latest=latest,
            time_range_explicit=generic.time_range_explicit,
            explicit_entities=[],
            explicit_values=explicit_values,
            execute_read_only_search=False,
            hypotheses=[
                InvestigationHypothesis(
                    hypothesis_id="BH1",
                    statement="The requested security intent can be expressed using at least one live observed source and field.",
                    supporting_requirement_ids=["B1"],
                    disconfirming_evidence=[
                        "No visible source exposes a populated field semantically aligned to the intent.",
                        "The selected field is only a reflection of the analyst prompt rather than target telemetry.",
                        "The required observed field is absent from bounded raw events.",
                    ],
                )
            ],
            requirements=requirements,
            success_criteria=[
                "Every visible catalogue label is evaluated for recall.",
                "At least one candidate is profiled using live raw events.",
                "The primary intent maps only to an observed populated field.",
                "Analyst-derived intent terms occur in bounded live values, not merely field names.",
                "The value-grounded field exists in bounded raw events.",
                "The generated SPL passes the deterministic read-only safety gate.",
            ],
            abstain_conditions=[
                "No source can express the primary intent.",
                "Observed fields exist but bounded live values do not support the analyst intent terms.",
                "Only prompt-echo or self-referential telemetry matches the request.",
                "Raw event fields are unavailable.",
            ],
        )

    def discover(
        self,
        *,
        question: str,
        generic: SPLBuildOutcome,
        progress: ProgressCallback | None = None,
    ) -> BuildDiscoveryResult:
        started = time.monotonic()
        plan = self.create_plan(question, generic)
        catalog = self.telemetry.live_catalog(plan.earliest, plan.latest)
        ranked = self._rank_catalog(question, plan, generic, catalog)

        max_profiles = max(
            1,
            min(
                len(ranked),
                int(self.policy.get("build_spl_max_profiles", 30)),
            ),
        )
        batch_size = max(1, int(self.policy.get("build_spl_profile_batch_size", 5)))
        budget = max(30, int(self.policy.get("build_spl_live_budget_seconds", 240)))
        deadline = started + budget

        all_profiles: list[SourceProfileRecord] = []
        all_evidence: list[SourceEvidenceRecord] = []
        accepted: list[SourceEvidenceRecord] = []
        value_probes: dict[str, dict[str, Any]] = {}
        scanned = 0

        for offset in range(0, max_profiles, batch_size):
            if time.monotonic() >= deadline:
                break
            batch = ranked[offset : min(offset + batch_size, max_profiles)]
            if not batch:
                break
            if progress:
                progress(
                    "build_profiling",
                    "Profiling live candidate sources",
                    f"ARIA is profiling catalogue candidates {offset + 1}-{offset + len(batch)} of up to {max_profiles}; all {len(catalog)} labels were evaluated for recall.",
                )
            profiles = self.telemetry.profile_candidates(batch, plan)
            scanned += len(profiles)
            all_profiles.extend(profiles)

            proposals = self.binder.enrich(
                plan=plan,
                profiles=profiles,
                proposals=SourceQualificationSet(sources=[]),
            )
            evidence = self.qualifier.qualify(plan, profiles, proposals)
            self._reject_prompt_echo(question, profiles, evidence)
            profile_by_id = {profile.candidate_id: profile for profile in profiles}
            intent_terms = self.salient_terms(plan.requirements[0].concept)
            for item in evidence:
                if not item.accepted:
                    continue
                profile = profile_by_id.get(item.candidate_id)
                if profile is None:
                    item.accepted = False
                    item.rejection_reasons.append("Accepted schema evidence had no matching live profile.")
                    continue
                probe = self.telemetry.intent_value_probe(
                    profile,
                    intent_terms,
                    plan.earliest,
                    plan.latest,
                )
                value_probes[item.candidate_id] = probe
                if intent_terms and int(probe.get("all_terms_hits") or 0) <= 0:
                    item.accepted = False
                    item.score = min(item.score, float(self.policy.get("minimum_source_score", 55.0)) - 0.1)
                    item.rejection_reasons.append(
                        "Observed fields were present, but no bounded live event contained all analyst-derived intent terms in the same value-bearing field. Schema presence was not promoted to intent evidence."
                    )
            all_evidence.extend(evidence)
            accepted = sorted(
                [item for item in all_evidence if item.accepted],
                key=lambda item: (
                    int(value_probes.get(item.candidate_id, {}).get("all_terms_hits") or 0),
                    item.score,
                ),
                reverse=True,
            )
            if accepted:
                break

        all_evidence = sorted(all_evidence, key=lambda item: item.score, reverse=True)
        return BuildDiscoveryResult(
            plan=plan,
            catalog_rows=len(catalog),
            profiles=all_profiles,
            evidence=all_evidence,
            accepted=accepted,
            scanned_profiles=scanned,
            total_catalog_rows=len(catalog),
            scan_complete=scanned >= min(max_profiles, len(ranked)),
            elapsed_seconds=round(time.monotonic() - started, 2),
            value_probes=value_probes,
        )


    def deterministic_intent_strategy(
        self,
        *,
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
        plan: InvestigationPlan,
        value_probe: dict[str, Any] | None = None,
    ) -> SearchStrategyProposal:
        """Create a live-value-grounded draft from observed fields and analyst terms."""
        observed = {str(item.get("name") or "") for item in profile.fields}
        observed.update({"_raw", "_time", "host", "source", "sourcetype"})
        probe = value_probe or {}
        primary = str(probe.get("best_field") or "")
        if primary not in observed:
            primary = "_raw" if "_raw" in observed else ""

        filters: list[FilterProposal] = []
        validated = probe.get("validated_variants") or {}
        for term in probe.get("terms") or []:
            values = [str(value) for value in validated.get(term, []) if str(value)]
            if primary and values:
                filters.append(
                    FilterProposal(
                        field=primary,
                        operator="contains_any",
                        values=values[:6],
                        rationale=(
                            "Analyst-derived term variants retained only after the bounded live value probe "
                            "observed the term group in this field."
                        ),
                    )
                )

        # BUILD_SPL uses platform context fields for defensible grouping. Semantic
        # field binding may suggest richer entity fields, but a field-name match is
        # not enough to declare an entity role in generated SPL.
        groups = [field for field in ("host", "source", "sourcetype") if field in observed]

        metrics = [MetricProposal(function="count", alias="event_count")]
        if primary and primary != "_raw":
            metrics.append(MetricProposal(function="values", field=primary, alias="observed_activity"))

        return SearchStrategyProposal(
            candidate_id=source.candidate_id,
            purpose=(
                "Environment-qualified draft using a bounded live value probe, analyst-derived "
                "term variants and live observed fields. The query is not executed by BUILD_SPL."
            ),
            filters=filters,
            group_by=groups,
            display_fields=list(dict.fromkeys([primary, *groups])) if primary else groups,
            metrics=metrics,
            sort_by="event_count",
            descending=True,
            limit=min(50, int(self.policy.get("result_limit", 30))),
        )

    def ground_strategy(
        self,
        *,
        proposed: SearchStrategyProposal,
        source: SourceEvidenceRecord,
        profile: SourceProfileRecord,
        plan: InvestigationPlan,
        value_probe: dict[str, Any],
    ) -> SearchStrategyProposal:
        """Retain an LLM analytical shape but replace filters with live-value evidence."""
        grounded = self.deterministic_intent_strategy(
            source=source,
            profile=profile,
            plan=plan,
            value_probe=value_probe,
        )
        observed = {str(item.get("name") or "") for item in profile.fields}
        observed.update({"_raw", "_time", "host", "source", "sourcetype"})
        # The local model may influence analytical shape, but it cannot promote an
        # arbitrary observed field to an entity or outcome dimension. Grouping and
        # metrics remain on deterministic value-grounded/context fields.
        allowed_group = grounded.group_by
        allowed_metrics = grounded.metrics
        return SearchStrategyProposal(
            candidate_id=source.candidate_id,
            purpose=(
                "Local-model analytical shape constrained by live observed schema, with filters "
                "replaced by bounded live value-grounded analyst terms."
            ),
            filters=grounded.filters,
            group_by=allowed_group[:3],
            display_fields=grounded.display_fields,
            metrics=allowed_metrics[:4],
            time_bucket=proposed.time_bucket,
            sort_by=proposed.sort_by or grounded.sort_by,
            descending=proposed.descending,
            limit=min(proposed.limit, grounded.limit),
        )

    def _rank_catalog(
        self,
        question: str,
        plan: InvestigationPlan,
        generic: SPLBuildOutcome,
        catalog: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not catalog:
            return []
        explicit_index = generic.resolved_bindings.get("index")
        explicit_sourcetype = generic.resolved_bindings.get("sourcetype")

        deterministic = deterministic_catalog_selection(
            question=question,
            plan=plan,
            catalog_rows=catalog,
            limit=len(catalog),
            positive_only=False,
        )
        deterministic_order = {
            item.candidate_id: position
            for position, item in enumerate(deterministic.candidates)
        }

        query_text = compact_text(
            f"Security intent: {plan.requirements[0].concept}. Analyst request: {question}",
            700,
        )
        label_texts = [
            compact_text(
                "Observed Splunk catalogue label: "
                f"index {row.get('index', '')}; sourcetype {row.get('sourcetype', '')}; "
                f"source {row.get('source', '')}.",
                400,
            )
            for row in catalog
        ]
        semantic_scores: list[float] = [0.0 for _ in catalog]
        try:
            vectors = self._embed_many([query_text, *label_texts])
            if len(vectors) == len(catalog) + 1:
                semantic_scores = [self._cosine(vectors[0], vector) for vector in vectors[1:]]
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.build_spl_workbench.catalog_embedding")

        ranked: list[tuple[float, int, dict[str, Any]]] = []
        for position, row in enumerate(catalog):
            candidate_id = str(row.get("candidate_id") or "")
            index = str(row.get("index") or "")
            sourcetype = str(row.get("sourcetype") or "")
            explicit = 0.0
            if explicit_index and index == explicit_index:
                explicit += 10000.0
            if explicit_sourcetype and sourcetype == explicit_sourcetype:
                explicit += 20000.0
            lexical_order = deterministic_order.get(candidate_id, len(catalog))
            lexical = max(0.0, float(len(catalog) - lexical_order))
            semantic = max(0.0, semantic_scores[position]) * 1000.0
            try:
                volume = math.log10(max(0, int(float(row.get("event_count") or 0))) + 1) / 100.0
            except (TypeError, ValueError):
                volume = 0.0
            score = explicit + semantic + lexical + volume
            candidate = dict(row)
            candidate["selection_rationale"] = (
                "BUILD_SPL live-catalog ranking from analyst-supplied bindings, local "
                f"embedding similarity={semantic_scores[position]:.3f}, generic lexical recall, "
                "and event volume as a tie-breaker only. Source acceptance still requires live fields."
            )
            ranked.append((score, -position, candidate))

        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [item[2] for item in ranked]

    def _reject_prompt_echo(
        self,
        question: str,
        profiles: list[SourceProfileRecord],
        evidence: list[SourceEvidenceRecord],
    ) -> None:
        by_candidate = {profile.candidate_id: profile for profile in profiles}
        for item in evidence:
            profile = by_candidate.get(item.candidate_id)
            if profile is None or not item.accepted:
                continue
            if self._profile_echoes_question(profile, question):
                item.accepted = False
                item.score = min(item.score, 5.0)
                item.rejection_reasons.append(
                    "The apparent match is a reflection of the current analyst prompt in observed telemetry, not independent target evidence."
                )

    @classmethod
    def _profile_echoes_question(cls, profile: SourceProfileRecord, question: str) -> bool:
        normalised_question = cls._normalise(question)
        if len(normalised_question) < 24:
            return False
        for field in profile.fields:
            for sample in field.get("sample_values") or []:
                normalised_sample = cls._normalise(sample)
                if len(normalised_sample) < 24:
                    continue
                if normalised_question in normalised_sample or normalised_sample in normalised_question:
                    return True
                if SequenceMatcher(None, normalised_question, normalised_sample).ratio() >= 0.82:
                    return True
        return False

    @classmethod
    def salient_terms(cls, text: str) -> list[str]:
        output: list[str] = []
        for token in _TOKEN_RE.findall(str(text or "")):
            value = token.strip("_.:/-")
            lower = value.lower()
            if len(lower) < 3 or lower in _CONTROL_WORDS or lower.isdigit():
                continue
            if value not in output:
                output.append(value)
        return output[:12]

    def _embed_many(self, texts: list[str]) -> list[list[float]]:
        missing = [text for text in texts if text not in self._embedding_cache]
        if missing:
            vectors = self.ollama.embed_texts(
                missing,
                timeout=int(self.policy.get("build_spl_catalog_embedding_timeout_seconds", 25)),
            )
            if len(vectors) != len(missing):
                raise RuntimeError("Embedding response count did not match request count.")
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
        if left_norm <= 0 or right_norm <= 0:
            return 0.0
        return dot / (left_norm * right_norm)

    @staticmethod
    def _normalise(value: Any) -> str:
        return " ".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))
