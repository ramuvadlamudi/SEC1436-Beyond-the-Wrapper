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

from aria.copilot.catalog_ranker import deterministic_catalog_selection  # noqa: E402
from aria.copilot.contracts import EvidenceRequirement, InvestigationPlan  # noqa: E402
from aria.copilot.planner import CopilotPlanner  # noqa: E402


class NoCandidateModel:
    def structured_chat(self, **kwargs):
        raise AssertionError("an exact live-catalog match must not invoke generative candidate ranking")


def plan() -> InvestigationPlan:
    return InvestigationPlan(
        capability="QUERY_SPLUNK",
        goal="Investigate DNS tunneling using live Splunk evidence across all available time.",
        earliest="0",
        latest="now",
        time_range_explicit=True,
        requirements=[
            EvidenceRequirement(
                requirement_id="req1",
                concept="DNS queries",
                role="activity",
                required=True,
                reason="Observe query activity",
            ),
            EvidenceRequirement(
                requirement_id="req2",
                concept="Destination IP addresses",
                role="entity",
                required=True,
                reason="Observe destinations",
            ),
            EvidenceRequirement(
                requirement_id="req3",
                concept="DNS query timestamps",
                role="activity",
                required=True,
                reason="Observe timing",
            ),
            EvidenceRequirement(
                requirement_id="req4",
                concept="Source IP addresses",
                role="entity",
                required=True,
                reason="Observe origins",
            ),
        ],
    )


def catalog() -> list[dict[str, object]]:
    return [
        {"candidate_id": "C1", "index": "botsv3", "sourcetype": "syslog", "event_count": 283976},
        {"candidate_id": "C2", "index": "botsv3", "sourcetype": "stream:ip", "event_count": 227872},
        {"candidate_id": "C3", "index": "botsv3", "sourcetype": "osquery:results", "event_count": 219997},
        {"candidate_id": "C4", "index": "botsv3", "sourcetype": "stream:dns", "event_count": 218456},
    ]


def main() -> int:
    failures: list[str] = []
    question = """Investigate DNS tunneling using live Splunk evidence across all available time.

Discover candidate telemetry from the connected Splunk catalog.

Validate observed fields and values, verify required-field co-occurrence, execute only evidence-qualified read-only SPL, and report any raw-event access gaps."""

    selection = deterministic_catalog_selection(
        question=question,
        plan=plan(),
        catalog_rows=catalog(),
        limit=1,
        positive_only=True,
    )
    ids = [item.candidate_id for item in selection.candidates]
    if ids != ["C4"]:
        failures.append(
            f"exact catalog token did not outrank substring-only fuzzy hit; selected={ids}"
        )

    planner = CopilotPlanner(NoCandidateModel())
    runtime_selection = planner.select_candidates(
        question=question,
        plan=plan(),
        catalog_rows=catalog(),
        limit=2,
    )
    runtime_ids = [item.candidate_id for item in runtime_selection.candidates]
    if not runtime_ids or runtime_ids[0] != "C4":
        failures.append(
            f"runtime planner did not put the exact live-catalog match first; selected={runtime_ids}"
        )

    print("ARIA Exact Catalog Match Precedence Test")
    print("========================================")
    if failures:
        for failure in failures:
            print(f"FAIL   {failure}")
        print(f"ARIA_EXACT_CATALOG_PRECEDENCE_TEST=FAIL failures={len(failures)}")
        return 1

    print("PASS   exact live-catalog token match outranks substring-only fuzzy overlap")
    print("PASS   runtime candidate selection uses the exact-match fast path without an LLM call")
    print("ARIA_EXACT_CATALOG_PRECEDENCE_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
