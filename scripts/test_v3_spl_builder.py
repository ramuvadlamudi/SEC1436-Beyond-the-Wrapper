from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("OLLAMA_FAST_MODEL", "test-fast")
os.environ.setdefault("OLLAMA_REASONING_MODEL", "test-reasoning")
os.environ.setdefault("OLLAMA_EMBEDDING_MODEL", "test-embed")
os.environ.setdefault("SPLUNK_URL", "https://127.0.0.1:8089")
os.environ.setdefault("SPLUNK_USERNAME", "test")
os.environ.setdefault("SPLUNK_PASSWORD", "test")
os.environ.setdefault("SPLUNK_VERIFY_SSL", "false")

from aria.models import CatalogItem, FieldEvidence, SourceProfile
from aria.copilot.contracts import SourceProfileRecord
from aria.spl_validator import StaticSPLValidator
from aria.v3.contracts import (
    AnalystAggregation,
    BehaviourIntent,
    FieldBinding,
    IntentConcept,
    SourceAssessment,
    SourceConstraint,
)
from aria.v3.spl_builder_agent import SPLBuilderAgent
from aria.v3.telemetry_intelligence import TelemetryIntelligenceService


class FakeOllama:
    def structured_chat(self, **kwargs):
        response_model = kwargs["response_model"]
        if response_model is BehaviourIntent:
            return BehaviourIntent(
                summary="analysing encoded command execution",
                behaviour_terms=["encoded-command"],
                concepts=[
                    IntentConcept(concept_id="A1", role="activity", description="command or script activity content", required=True),
                    IntentConcept(concept_id="E1", role="entity", description="originating system context", required=False),
                ],
                desired_shape="events",
                limit=20,
            )
        raise AssertionError(f"Unexpected response model {response_model}")

    def embed_texts(self, texts, timeout=None):
        raise RuntimeError("embedding deliberately unavailable")


class FailingOllama(FakeOllama):
    def structured_chat(self, **kwargs):
        raise RuntimeError("semantic model unavailable")


class WorkflowLeakingOllama(FakeOllama):
    """Reproduce the RC9 local-model output observed in the conference UI."""

    def structured_chat(self, **kwargs):
        response_model = kwargs["response_model"]
        if response_model is BehaviourIntent:
            return BehaviourIntent(
                summary="Detect possible DNS tunnelling using deployment-qualified telemetry.",
                behaviour_terms=[
                    "deployment-qualified",
                    "detecting",
                    "possible",
                    "dns",
                    "tunnelling",
                    "use",
                ],
                concepts=[
                    IntentConcept(
                        concept_id="A1",
                        role="activity",
                        description="DNS tunnelling activity",
                        required=True,
                    ),
                ],
                desired_shape="events",
                limit=100,
            )
        raise AssertionError(f"Unexpected response model {response_model}")


class AlwaysSimilarOllama(WorkflowLeakingOllama):
    def embed_texts(self, texts, timeout=None):
        return [[1.0, 0.0] for _ in texts]


class FakeSplunk:
    def __init__(self):
        self.profile_calls = []
        self.searches = []

    def search(self, spl):
        self.searches.append(spl)
        if "| tstats" in spl:
            return [
                {"index": "alpha", "sourcetype": "endpoint:events", "event_count": "200", "first_seen": "1", "last_seen": "2"},
                {"index": "alpha", "sourcetype": "network:events", "event_count": "100", "first_seen": "1", "last_seen": "2"},
            ]
        return []

    def discover_catalog(self):
        return [
            CatalogItem(index="alpha", sourcetype="endpoint:events", event_count=200),
            CatalogItem(index="alpha", sourcetype="network:events", event_count=100),
        ]

    def profile_source(self, candidate, earliest, latest):
        self.profile_calls.append((candidate.index, candidate.sourcetype, earliest, latest))
        return SourceProfile(
            index=candidate.index,
            sourcetype=candidate.sourcetype,
            fields=[
                FieldEvidence(name="activity_text", count=200, distinct_count=50, sample_values='["shell command", "script execution"]'),
                FieldEvidence(name="system_context", count=200, distinct_count=5, sample_values='["system-a"]'),
            ],
        )

    def source_event_count(self, candidate, earliest, latest):
        return 200


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 SPL Builder Agent Test")
    print("==============================")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARIA_V3_TELEMETRY_CACHE"] = str(Path(tmp) / "cache.json")
        ollama = FakeOllama()
        splunk = FakeSplunk()
        telemetry = TelemetryIntelligenceService(splunk, ollama)
        builder = SPLBuilderAgent(ollama, telemetry, StaticSPLValidator())

        first = builder.build("Build SPL for analysing encoded-command execution.")
        check(first.capability == "BUILD_SPL", "SPL build capability")
        check(first.metadata["awaiting_time_range"] is True, "missing time range asks a follow-up")
        check("GENERIC_INTENT_SPL" == first.metadata["generic_spl"]["name"], "portable generic SPL produced")
        check("eventcode" not in first.answer.lower(), "generic SPL does not invent event IDs")

        second = builder.build(
            'Build SPL for index="alpha" sourcetype="endpoint:events" across all available time. Use the literal conditions: (encoded OR base64). Return the first 20 events.',
        )
        deployment = second.metadata["deployment_spl"]
        check(deployment is not None, "deployment-qualified SPL produced")
        check(deployment["status"] == "SCHEMA_QUALIFIED", "schema qualification is distinct from result validation")
        check('index="alpha"' in deployment["spl"], "analyst-supplied index preserved")
        check('sourcetype="endpoint:events"' in deployment["spl"], "analyst-supplied sourcetype preserved")
        check(deployment["spl"].count("encoded OR base64") == 1, "literal condition emitted once")
        check(second.metadata["spl_executed"] is False, "BUILD_SPL does not execute final SPL")
        check(len(splunk.profile_calls) == 1, "explicit source is profiled before unrelated sources")
        check(splunk.profile_calls[0][:2] == ("alpha", "endpoint:events"), "exact analyst source receives priority")

        refinement = builder.build(
            "Use a ten-minute observation window and more than fifty distinct values as analyst-supplied thresholds.",
            last_result=second.model_dump(),
        )
        check(
            "Analyst refinement:" in refinement.metadata["effective_request"],
            "builder retains the original intent for threshold/window refinement",
        )
        check(
            "more than fifty distinct values" in refinement.metadata["effective_request"],
            "builder appends the analyst refinement without losing it",
        )
        aggregation = refinement.metadata["analyst_aggregation"]
        portable_refinement = refinement.metadata["generic_spl"]["spl"]
        check(aggregation["window_span"] == "10m", "worded observation window is deterministically retained")
        check(aggregation["threshold"] == 50 and aggregation["operator"] == ">", "worded distinct threshold is deterministically retained")
        check("span=10m" in portable_refinement, "portable SPL applies the analyst observation window")
        check("dc({DISTINCT_VALUE_FIELD})" in portable_refinement, "portable SPL applies distinct-count aggregation")
        check("aria_distinct_value_count > 50" in portable_refinement, "portable SPL applies the analyst threshold")

        leaking_ollama = WorkflowLeakingOllama()
        leaking_splunk = FakeSplunk()
        leaking_telemetry = TelemetryIntelligenceService(leaking_splunk, leaking_ollama)
        leaking_builder = SPLBuilderAgent(leaking_ollama, leaking_telemetry, StaticSPLValidator())
        original = leaking_builder.build(
            "Build portable and deployment-qualified SPL for detecting possible DNS "
            "tunnelling across all available time. Use the live Splunk catalogue and "
            "observed schema to qualify suitable telemetry. Do not assume an index, "
            "sourcetype, field name, value or threshold. Do not execute the final "
            "generated SPL. Explain the selected telemetry, validation state and evidence gaps."
        )
        exact_refinement = leaking_builder.build(
            "Use a ten-minute observation window and identify entities querying more than "
            "fifty distinct subdomains of the same parent domain. Treat these as "
            "analyst-supplied thresholds, not evidence of maliciousness.",
            last_result=original.model_dump(),
        )
        exact_aggregation = exact_refinement.metadata["analyst_aggregation"]
        exact_spl = exact_refinement.metadata["generic_spl"]["spl"]
        exact_terms = exact_refinement.metadata["behaviour_intent"]["behaviour_terms"]
        check(exact_aggregation["measured_concept"] == "subdomains", "distinct measured concept is retained")
        check(exact_aggregation["entity_concept"] == "entities", "entity grouping concept is retained")
        check(exact_aggregation["grouping_concept"] == "parent domain", "same-parent grouping concept is retained")
        check("{ENTITY_FIELD}" in exact_spl and "{GROUPING_FIELD}" in exact_spl, "portable SPL exposes unresolved grouping fields")
        check(
            not {"deployment-qualified", "detecting", "possible", "use"} & set(exact_terms),
            "workflow language cannot become behaviour filters",
        )
        check(
            all(f'%{term}%' not in exact_spl for term in ("deployment-qualified", "detecting", "possible", "use")),
            "workflow language cannot leak into compiled SPL",
        )
        preferred = exact_refinement.metadata["preferred_source"]
        first_assessment = exact_refinement.metadata["source_assessments"][0]
        check(preferred is not None, "builder carries the parent source into the refinement")
        check(
            first_assessment["index"] == preferred["index"]
            and first_assessment["sourcetype"] == preferred["sourcetype"],
            "builder revalidates the parent source before unrelated candidates",
        )
        if exact_refinement.metadata["deployment_spl"] is None:
            check(
                not any("Execute the deployment-qualified" in item for item in exact_refinement.context_actions),
                "an abstained deployment variant offers no misleading execute action",
            )

        similar_service = TelemetryIntelligenceService(FakeSplunk(), AlwaysSimilarOllama())
        exact_intent = BehaviourIntent.model_validate(exact_refinement.metadata["behaviour_intent"])
        misleading_profile = SourceProfileRecord(
            candidate_id="C-WRONG",
            index="runtime_index",
            sourcetype="runtime:telemetry",
            event_count=500,
            fields=[
                {"name": "bytes", "count": 500, "distinct_count": 400, "sample_values": ["128", "512"]},
                {"name": "protocol", "count": 500, "distinct_count": 3, "sample_values": ["tcp", "udp"]},
                {"name": "dst_ip", "count": 500, "distinct_count": 20, "sample_values": ["192.0.2.1"]},
            ],
        )
        rejected = similar_service.assess_source(misleading_profile, exact_intent)
        aggregation_bindings = [
            item for item in rejected.bindings if item.concept_id.startswith("ARIA_")
        ]
        check(not rejected.schema_qualified, "embedding-only aggregation mappings cannot schema-qualify")
        check(
            all(item.field is None for item in aggregation_bindings),
            "bytes, protocol and destination IP are rejected for unrelated analyst concepts",
        )
        check(
            all("CORROBORATION_FAILED" in item.method for item in aggregation_bindings),
            "failed deterministic binding corroboration is explicit",
        )

        corroborated_profile = SourceProfileRecord(
            candidate_id="C-GOOD",
            index="runtime_index",
            sourcetype="runtime:telemetry",
            event_count=500,
            fields=[
                {"name": "queried_subdomain", "count": 500, "distinct_count": 400, "sample_values": ["a.example.test"]},
                {"name": "source_entity", "count": 500, "distinct_count": 20, "sample_values": ["entity-a"]},
                {"name": "parent_domain", "count": 500, "distinct_count": 30, "sample_values": ["example.test"]},
            ],
        )
        corroborated = similar_service.assess_source(corroborated_profile, exact_intent)
        corroborated_fields = {
            item.concept_id: item.field
            for item in corroborated.bindings
            if item.concept_id.startswith("ARIA_")
        }
        check(corroborated.schema_qualified, "corroborated observed aggregation fields can schema-qualify")
        check(
            corroborated_fields == {
                "ARIA_MEASURED_VALUE": "queried_subdomain",
                "ARIA_ENTITY_GROUP": "source_entity",
                "ARIA_RELATED_GROUP": "parent_domain",
            },
            "only lexically corroborated live field bindings are retained",
        )
        bound_profile = SourceProfileRecord(
            candidate_id="C1",
            index="runtime_index",
            sourcetype="runtime:dns",
            event_count=500,
            fields=[
                {"name": "dns_query_name", "count": 500},
                {"name": "client_entity", "count": 500},
                {"name": "parent_domain", "count": 500},
            ],
        )
        bound_assessment = SourceAssessment(
            candidate_id="C1",
            index="runtime_index",
            sourcetype="runtime:dns",
            event_count=500,
            fields_observed=3,
            required_bindings_supported=3,
            required_bindings_total=3,
            schema_qualified=True,
            bindings=[
                FieldBinding(
                    concept_id="ARIA_MEASURED_VALUE",
                    role="quantity",
                    description="subdomains used as the distinct-count value",
                    field="dns_query_name",
                    score=0.9,
                    populated_events=500,
                ),
                FieldBinding(
                    concept_id="ARIA_ENTITY_GROUP",
                    role="entity",
                    description="entities that originate the measured activity",
                    field="client_entity",
                    score=0.9,
                    populated_events=500,
                ),
                FieldBinding(
                    concept_id="ARIA_RELATED_GROUP",
                    role="context",
                    description="parent domain used to group related distinct values",
                    field="parent_domain",
                    score=0.9,
                    populated_events=500,
                ),
            ],
        )
        bound_variant = leaking_builder._deployment_variant(
            BehaviourIntent.model_validate(exact_refinement.metadata["behaviour_intent"]),
            SourceConstraint(),
            bound_profile,
            bound_assessment,
            "0",
            "now",
            AnalystAggregation.model_validate(exact_aggregation),
        )
        check("span=10m" in bound_variant.spl, "deployment SPL applies the observation window")
        check("dc('dns_query_name')" in bound_variant.spl, "deployment SPL binds the observed measured field")
        check(
            "by _time 'client_entity' 'parent_domain'" in bound_variant.spl,
            "deployment SPL binds entity and related-value groupings",
        )
        check("aria_distinct_value_count > 50" in bound_variant.spl, "deployment SPL applies the analyst threshold")
        check(bound_variant.safe and bound_variant.status == "SCHEMA_QUALIFIED", "bound deployment aggregation passes the safety gate")

        fallback_splunk = FakeSplunk()
        fallback_telemetry = TelemetryIntelligenceService(fallback_splunk, FailingOllama())
        fallback_builder = SPLBuilderAgent(FailingOllama(), fallback_telemetry, StaticSPLValidator())
        fallback = fallback_builder.build('Build SPL for encoded-command execution using index="alpha" sourcetype="endpoint:events" across all available time.')
        generic_spl = fallback.metadata["generic_spl"]["spl"].lower()
        check('like(aria_text,"%alpha%")' not in generic_spl, "fallback intent excludes analyst source coordinates")
        check('like(aria_text,"%endpoint%")' not in generic_spl, "fallback intent excludes sourcetype label tokens")

    print("ARIA_V3_SCHEMA_BINDING_CORROBORATION_TEST=PASS")
    print("ARIA_V3_SPL_REFINEMENT_SEMANTICS_TEST=PASS")
    print("ARIA_V3_SPL_BUILDER_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
