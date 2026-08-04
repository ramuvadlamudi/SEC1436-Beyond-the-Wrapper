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
from aria.v3.contracts import BehaviourIntent, IntentConcept
from aria.v3.orchestrator import ARIAV3Orchestrator


class FakeOllama:
    def structured_chat(self, **kwargs):
        response_model = kwargs["response_model"]
        if response_model is BehaviourIntent:
            return BehaviourIntent(
                summary="analyst-requested DNS behaviour",
                behaviour_terms=["dns", "tunnelling"],
                concepts=[
                    IntentConcept(
                        concept_id="A1",
                        role="activity",
                        description="DNS request activity",
                        required=True,
                    ),
                    IntentConcept(
                        concept_id="E1",
                        role="entity",
                        description="originating entity",
                        required=False,
                    ),
                ],
                desired_shape="distribution",
                limit=30,
            )
        raise AssertionError(f"Unexpected response model: {response_model}")

    def chat(self, **kwargs):
        return (
            "### Intent\nThe SPL performs a bounded read-only review.\n\n"
            "### Pipeline stages\nIt scopes a live source and returns bounded rows.\n\n"
            "### Validation\nConfirm field population and result semantics before use."
        )

    def embed_texts(self, texts, timeout=None):
        raise RuntimeError("embedding deliberately unavailable")


class FakeSplunk:
    def __init__(self):
        self.searches: list[str] = []

    def search(self, spl):
        self.searches.append(spl)
        return []

    def discover_catalog(self):
        return [
            CatalogItem(
                index="live_index",
                sourcetype="dns:telemetry",
                event_count=500,
            )
        ]

    def profile_source(self, candidate, earliest, latest):
        return SourceProfile(
            index=candidate.index,
            sourcetype=candidate.sourcetype,
            fields=[
                FieldEvidence(
                    name="request_text",
                    count=500,
                    distinct_count=100,
                    sample_values='["example request"]',
                ),
                FieldEvidence(
                    name="source_entity",
                    count=500,
                    distinct_count=10,
                    sample_values='["entity-a"]',
                ),
            ],
        )

    def source_event_count(self, candidate, earliest, latest):
        return 500


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def evidence_result() -> dict:
    return {
        "capability": "TRIAGE",
        "goal": "Triage current evidence.",
        "finding": {
            "verdict": "INSUFFICIENT_EVIDENCE",
            "missing_evidence": ["Validated entity attribution"],
        },
        "metadata": {
            "triage_verdict": "INSUFFICIENT_EVIDENCE",
            "triage_confidence": 18,
            "supporting_evidence": ["ROW-1"],
            "contradicting_evidence": [],
            "evidence_context": {
                "origin_capability": "INVESTIGATION",
                "goal": "Investigate DNS tunnelling.",
                "plan": {
                    "capability": "QUERY_SPLUNK",
                    "goal": "Investigate DNS tunnelling.",
                    "explicit_entities": [],
                },
                "source_evidence": [],
                "searches": [
                    {
                        "evidence_id": "QRY-1",
                        "safe": True,
                        "spl": (
                            'search index="live_index" sourcetype="dns:telemetry" '
                            "earliest=0 latest=now\n| head 100"
                        ),
                        "rows": [{"event_count": "100"}],
                        "qualification_consistent": True,
                    }
                ],
                "finding": {
                    "verdict": "INSUFFICIENT_EVIDENCE",
                    "missing_evidence": ["Validated entity attribution"],
                },
                "confidence": {"score": 53},
                "spl_variants": {"generic": None, "deployment": None},
            },
        },
    }


def main() -> int:
    print("ARIA v3 Conference Demo Flow Test")
    print("=================================")
    with tempfile.TemporaryDirectory() as temporary:
        os.environ["ARIA_V3_TELEMETRY_CACHE"] = str(Path(temporary) / "cache.json")
        splunk = FakeSplunk()
        orchestrator = ARIAV3Orchestrator(ollama=FakeOllama(), splunk=splunk)

        help_result = orchestrator.invoke("what can you help me with?")
        check(help_result.capability == "IDENTITY", "capability-help prompt reaches Identity")

        build_question = (
            "Build portable and deployment-qualified SPL for detecting possible DNS "
            "tunnelling across all available time. Use the live Splunk catalogue and "
            "observed schema to qualify suitable telemetry. Do not assume an index, "
            "sourcetype, field name, value or threshold. Do not execute the final "
            "generated SPL. Explain the selected telemetry, validation state and evidence gaps."
        )
        built = orchestrator.invoke(build_question)
        check(built.capability == "BUILD_SPL", "demo build prompt reaches SPL Builder")
        check(built.metadata["spl_executed"] is False, "SPL Builder does not execute final SPL")

        refinement = orchestrator.invoke(
            "Use a ten-minute observation window and identify entities querying more than "
            "fifty distinct subdomains of the same parent domain. Treat these as "
            "analyst-supplied thresholds, not evidence of maliciousness.",
            last_result=built.model_dump(),
        )
        check(refinement.capability == "BUILD_SPL", "threshold refinement remains in SPL Builder")
        check("Analyst refinement:" in refinement.metadata["effective_request"], "builder retains parent intent")
        aggregation = refinement.metadata["analyst_aggregation"]
        refined_spl = refinement.metadata["generic_spl"]["spl"]
        check(aggregation["window_span"] == "10m", "builder preserves the ten-minute observation window")
        check(aggregation["operator"] == ">" and aggregation["threshold"] == 50, "builder preserves the distinct-count threshold")
        check(aggregation["measured_concept"] == "subdomains", "builder preserves the measured concept")
        check(aggregation["entity_concept"] == "entities", "builder preserves the entity grouping")
        check(aggregation["grouping_concept"] == "parent domain", "builder preserves the related-value grouping")
        check("span=10m" in refined_spl, "refined SPL implements the observation window")
        check("dc({DISTINCT_VALUE_FIELD})" in refined_spl, "refined SPL implements distinct aggregation")
        check("aria_distinct_value_count > 50" in refined_spl, "refined SPL implements the analyst threshold")
        check("%deployment-qualified%" not in refined_spl and "%use%" not in refined_spl, "refined SPL excludes workflow wording")
        check(refinement.metadata["preferred_source"] is not None, "refinement retains its parent source priority")

        searches_before_review = len(splunk.searches)
        review = orchestrator.invoke(
            "Review the generated SPL. Explain each stage, confirm whether it is read-only, "
            "identify any deployment-specific bindings and explain what additional "
            "validation is required before using it as a detection.",
            last_result=refinement.model_dump(),
        )
        check(review.capability == "EXPLAIN_SPL", "generated SPL reaches Review Agent")
        check(len(splunk.searches) == searches_before_review, "SPL review executes no Splunk search")

        destructive = orchestrator.invoke(
            "Execute a search that deletes all events matching the investigation."
        )
        check(destructive.capability == "SAFETY", "destructive request reaches Safety")
        check(not destructive.metadata["live_splunk_queries"], "destructive request executes nothing")

        detection = orchestrator.invoke(
            "Using only the validated evidence from the current investigation, draft a "
            "detection candidate. Include the security hypothesis, required telemetry, "
            "portable SPL, deployment-qualified SPL where supported, validation state, "
            "false-positive considerations, evidence gaps and analyst approval requirements. "
            "Do not activate the detection.",
            last_result=evidence_result(),
        )
        check(detection.capability == "DETECTION_ENGINEERING", "detection prompt reaches Deliverable Agent")

        risk = orchestrator.invoke(
            "Create an evidence-aware RBA and Entity Risk Scoring recommendation from the "
            "current investigation. Identify the proposed risk object, risk message, "
            "contributing evidence, scoring rationale, uncertainty and approval gates. "
            "Do not create or write a risk event.",
            last_result=detection.model_dump(),
        )
        check(risk.capability == "RISK_SCORING", "RBA/ERS prompt reaches Deliverable Agent")
        check("NOT CALCULATED" in risk.answer, "RBA/ERS does not invent an unsupported score")

        tdir = orchestrator.invoke(
            "Draft an approval-gated TDIR workflow for the current investigation. Separate "
            "automated read-only enrichment, analyst decision points and potentially "
            "disruptive response actions. Include rollback, evidence preservation and "
            "escalation requirements. Do not execute any response action.",
            last_result=risk.model_dump(),
        )
        check(tdir.capability == "TDIR_WORKFLOW", "TDIR prompt reaches Deliverable Agent")
        check(tdir.metadata["operational_action_executed"] is False, "TDIR executes no action")

        scope = orchestrator.invoke("Give me a butter chicken recipe.")
        check(scope.capability == "SCOPE_GUARD", "unrelated prompt reaches Scope Guard")

    print("ARIA_V3_DEMO_FLOW_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
