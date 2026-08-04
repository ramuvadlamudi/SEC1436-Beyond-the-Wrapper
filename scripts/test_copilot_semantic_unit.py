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

from aria.copilot.engine import EvidenceFirstCopilotEngine  # noqa: E402
from aria.models import CatalogItem, FieldEvidence, SourceProfile  # noqa: E402


class NoGenerativeDependency:
    def structured_chat(self, **kwargs):
        raise RuntimeError("generative model unavailable")

    def chat(self, **kwargs):
        raise RuntimeError("generative model unavailable")

    def embed_texts(self, texts, timeout=None):
        raise RuntimeError("embedding unavailable to exercise lexical fallback")


class GenericLiveSplunk:
    def discover_catalog(self):
        return [
            CatalogItem(
                index="dynamic_index_from_live_catalog",
                sourcetype="protocol:query_activity",
                event_count=50,
                first_seen="1",
                last_seen="2",
            )
        ]

    def profile_source(self, candidate, earliest, latest):
        return SourceProfile(
            index=candidate.index,
            sourcetype=candidate.sourcetype,
            rationale="live",
            fields=[
                FieldEvidence(
                    name="activity_key",
                    count=40,
                    distinct_count=4,
                    sample_values='["protocol query", "protocol response"]',
                ),
                FieldEvidence(
                    name="actor_key",
                    count=40,
                    distinct_count=4,
                    sample_values='["alpha", "beta"]',
                ),
            ],
        )

    def source_event_count(self, candidate, earliest, latest):
        return 40

    def search(self, spl):
        lowered = spl.lower()
        if "| tstats" in lowered:
            return [
                {
                    "index": "dynamic_index_from_live_catalog",
                    "sourcetype": "protocol:query_activity",
                    "event_count": "50",
                    "first_seen": "1",
                    "last_seen": "2",
                }
            ]
        if "fully_bound_events" in lowered:
            return [
                {
                    "sampled_events": "40",
                    "fully_bound_events": "35",
                    "aria_field_1_present": "40",
                }
            ]
        if "aria_required_all_present" in lowered:
            return [
                {
                    "event_count": "40",
                    "aria_activity_key_distinct": "4",
                    "aria_activity_key_values": ["protocol query", "protocol response"],
                    "aria_required_1_present": "40",
                    "aria_required_all_present": "40",
                }
            ]
        return [{"activity_key": "protocol query", "event_count": "4"}]


def main() -> int:
    engine = EvidenceFirstCopilotEngine(
        ollama=NoGenerativeDependency(),
        splunk=GenericLiveSplunk(),
    )
    result = engine.invoke(
        "Investigate protocol query activity using live Splunk evidence across all available time"
    )

    failures: list[str] = []
    if result.capability != "INVESTIGATION":
        failures.append("wrong capability")
    if not result.source_evidence or not result.source_evidence[0].accepted:
        failures.append(
            "live source was not accepted: "
            + str([item.rejection_reasons for item in result.source_evidence])
        )
    if not result.searches or not result.searches[0].safe:
        failures.append("safe SPL was not compiled")
    elif "dynamic_index_from_live_catalog" not in result.searches[0].spl:
        failures.append("SPL did not use the live catalog source")
    elif "activity_key" not in result.searches[0].spl:
        failures.append("SPL did not use a validated observed field")
    if result.finding is None or result.finding.verdict != "EVIDENCE_FOUND":
        failures.append("finding did not preserve returned evidence")
    if result.confidence is None or result.confidence.score <= 0:
        failures.append("confidence was not calculated")

    print("ARIA Evidence-First Copilot Semantic Unit Test")
    print("==============================================")
    if failures:
        for failure in failures:
            print(f"FAIL   {failure}")
        print("ARIA_COPILOT_SEMANTIC_UNIT=FAIL")
        return 1

    print("PASS   live catalog source used")
    print("PASS   live observed fields validated")
    print("PASS   required-field co-occurrence enforced")
    print("PASS   read-only SPL compiled without a generative dependency")
    print("PASS   returned rows preserved as evidence")
    print("PASS   deterministic confidence calculated")
    print("ARIA_COPILOT_SEMANTIC_UNIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
