from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("OLLAMA_FAST_MODEL", "test-fast")
os.environ.setdefault("OLLAMA_REASONING_MODEL", "test-reasoning")
os.environ.setdefault("OLLAMA_EMBEDDING_MODEL", "test-embedding")
os.environ.setdefault("SPLUNK_URL", "https://127.0.0.1:8089")
os.environ.setdefault("SPLUNK_USERNAME", "test")
os.environ.setdefault("SPLUNK_PASSWORD", "test")
os.environ.setdefault("SPLUNK_VERIFY_SSL", "false")

from aria.copilot.contracts import (  # noqa: E402
    EvidenceRequirement,
    InvestigationPlan,
    SourceProfileRecord,
    SourceQualificationProposal,
    SourceQualificationSet,
)
from aria.copilot.evidence_qualifier import DeterministicEvidenceQualifier  # noqa: E402
from aria.copilot.semantic_binder import SemanticFieldBinder  # noqa: E402


class FakeEmbeddingClient:
    def embed_texts(self, texts, timeout=None):
        vectors = []
        for text in texts:
            lowered = text.lower()
            if "originating principal" in lowered or "actor_ref" in lowered:
                vectors.append([1.0, 0.0, 0.0, 0.0, 0.0])
            elif "destination system" in lowered or "target_node" in lowered:
                vectors.append([0.0, 1.0, 0.0, 0.0, 0.0])
            elif "event outcome" in lowered or "disposition" in lowered:
                vectors.append([0.0, 0.0, 1.0, 0.0, 0.0])
            elif "event timestamp" in lowered or "observed_at" in lowered:
                vectors.append([0.0, 0.0, 0.0, 1.0, 0.0])
            else:
                vectors.append([0.0, 0.0, 0.0, 0.0, 1.0])
        return vectors


class ProbeTelemetry:
    def cooccurrence_probe(self, profile, fields, earliest, latest):
        if fields == ["actor_ref", "target_node", "disposition", "observed_at"]:
            return {
                "sampled_events": 50,
                "fully_bound_events": 42,
                "field_presence": {field: 45 for field in fields},
            }
        return {
            "sampled_events": 50,
            "fully_bound_events": 0,
            "field_presence": {field: 0 for field in fields},
        }


def build_plan() -> InvestigationPlan:
    return InvestigationPlan(
        capability="QUERY_SPLUNK",
        goal="Test generic observed-schema binding",
        earliest="0",
        latest="now",
        time_range_explicit=True,
        requirements=[
            EvidenceRequirement(
                requirement_id="R1",
                concept="originating principal",
                role="entity",
                reason="Identify the initiating actor",
            ),
            EvidenceRequirement(
                requirement_id="R2",
                concept="destination system",
                role="entity",
                reason="Identify the affected system",
            ),
            EvidenceRequirement(
                requirement_id="R3",
                concept="event outcome",
                role="outcome",
                reason="Interpret the observed result",
            ),
            EvidenceRequirement(
                requirement_id="R4",
                concept="event timestamp",
                role="time",
                reason="Place the event in sequence",
            ),
        ],
    )


def build_profile() -> SourceProfileRecord:
    return SourceProfileRecord(
        candidate_id="C1",
        index="live_catalog_index",
        sourcetype="live_catalog_source",
        event_count=100,
        fields=[
            {"name": "actor_ref", "count": 50, "distinct_count": 5, "sample_values": ["a", "b"]},
            {"name": "target_node", "count": 50, "distinct_count": 4, "sample_values": ["n1", "n2"]},
            {"name": "disposition", "count": 50, "distinct_count": 2, "sample_values": ["ok", "denied"]},
            {"name": "observed_at", "count": 50, "distinct_count": 40, "sample_values": ["2026-01-01T00:00:00Z"]},
            {"name": "unrelated_metric", "count": 50, "distinct_count": 20, "sample_values": ["17"]},
        ],
    )


def main() -> int:
    plan = build_plan()
    profile = build_profile()
    initial = SourceQualificationSet(
        sources=[
            SourceQualificationProposal(
                candidate_id="C1",
                suitability="NONE",
                requirement_mappings=[],
                source_reasoning="The fast model returned no mapping.",
            )
        ]
    )
    binder = SemanticFieldBinder(FakeEmbeddingClient())
    enriched = binder.enrich(plan=plan, profiles=[profile], proposals=initial)
    qualifier = DeterministicEvidenceQualifier(ProbeTelemetry())
    evidence = qualifier.qualify(plan, [profile], enriched)[0]

    failures = []
    mapped = {
        binding.requirement_id: binding.fields[0]
        for binding in evidence.requirement_bindings
        if binding.fields
    }
    expected = {
        "R1": "actor_ref",
        "R2": "target_node",
        "R3": "disposition",
        "R4": "observed_at",
    }
    if mapped != expected:
        failures.append(f"unexpected mapping: {mapped}")
    if not evidence.accepted:
        failures.append(f"live co-occurring evidence was rejected: {evidence.rejection_reasons}")
    if evidence.fully_bound_events != 42:
        failures.append("co-occurrence was not validated")
    if any("unrelated_metric" in binding.fields for binding in evidence.requirement_bindings):
        failures.append("binder selected an unrelated observed field")
    if not all("semantic binding" in binding.rationale.lower() for binding in evidence.requirement_bindings):
        failures.append("binding provenance was not recorded")

    print("ARIA Generic Semantic Field Binding Test")
    print("========================================")
    if failures:
        for failure in failures:
            print(f"FAIL   {failure}")
        print("ARIA_SEMANTIC_FIELD_BINDING_TEST=FAIL")
        return 1

    print("PASS   missing LLM mappings recovered from observed schema")
    print("PASS   only live observed field names were selected")
    print("PASS   local embedding similarity remained scenario-agnostic")
    print("PASS   required-field co-occurrence remained mandatory")
    print("PASS   low LLM suitability did not veto validated live evidence")
    print("ARIA_SEMANTIC_FIELD_BINDING_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
