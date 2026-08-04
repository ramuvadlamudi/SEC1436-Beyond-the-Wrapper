from __future__ import annotations

import os

os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("OLLAMA_FAST_MODEL", "test-fast")
os.environ.setdefault("OLLAMA_REASONING_MODEL", "test-reasoning")
os.environ.setdefault("OLLAMA_EMBEDDING_MODEL", "test-embed")
os.environ.setdefault("SPLUNK_URL", "https://127.0.0.1:8089")
os.environ.setdefault("SPLUNK_USERNAME", "test")
os.environ.setdefault("SPLUNK_PASSWORD", "test")
os.environ.setdefault("SPLUNK_VERIFY_SSL", "false")

from aria.spl_validator import StaticSPLValidator
from aria.v3.contracts import TriageDecision
from aria.v3.triage_agent import TriageAgent


class FakeOllama:
    def structured_chat(self, **kwargs):
        return TriageDecision(
            verdict="SUSPICIOUS",
            confidence=62,
            reasoning="Returned rows show activity requiring analyst review, but corroboration and expected-use context are incomplete.",
            supporting_evidence=["ROW-1"],
            evidence_gaps=["No corroborating source"],
            next_action="Query adjacent activity for the affected entity and time window.",
        )


class FakeSplunk:
    def __init__(self):
        self.searches = []

    def search(self, spl):
        self.searches.append(spl)
        return [{"_time": "2026-01-01T00:00:00", "index": "alerts", "sourcetype": "finding", "_raw": "bounded finding evidence"}]


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 Triage Agent Test")
    print("=========================")
    splunk = FakeSplunk()
    agent = TriageAgent(FakeOllama(), splunk, StaticSPLValidator())
    result = agent.triage("Triage finding ID ABC-123 across all available time")
    check(result.capability == "TRIAGE", "triage capability")
    check(result.metadata["triage_verdict"] == "SUSPICIOUS", "evidence-bound verdict")
    check(result.metadata["triage_confidence"] == 62, "bounded confidence")
    check(len(result.searches) == 1 and result.searches[0].safe, "read-only locator search executed")
    check("outputlookup" not in result.searches[0].spl.lower(), "no write command")
    check("ROW-1" in result.answer, "verdict references returned evidence")

    empty_prior = {"capability": "INVESTIGATION", "searches": []}
    no_rows = agent.triage("Triage the current investigation results.", last_result=empty_prior)
    check(no_rows.metadata["triage_verdict"] == "INSUFFICIENT_EVIDENCE", "zero-row investigation produces a bounded triage verdict")
    check(no_rows.metadata["prior_investigation_available"] is True, "prior investigation context is retained")

    evidence_prior = {
        "capability": "INVESTIGATION",
        "searches": [{"rows": [{"event_count": "25", "aria_signal_distinct": "3"}]}],
    }
    with_rows = agent.triage(
        "Triage the current investigation results.",
        last_result=evidence_prior,
    )
    check(with_rows.metadata["triage_confidence"] > 0, "returned evidence cannot produce zero-confidence triage")
    check(with_rows.metadata["supporting_evidence"] == ["ROW-1"], "triage preserves returned-row evidence identifiers")
    check(
        with_rows.metadata["evidence_context"]["searches"][0]["rows"],
        "triage carries structured investigation evidence for downstream deliverables",
    )
    check(with_rows.metadata["triage_verdict"] == "INSUFFICIENT_EVIDENCE", "aggregate volume alone cannot produce a suspicious verdict")
    check("Event volume alone" in with_rows.answer, "triage removes unsupported unusual-volume reasoning")

    inconsistent_prior = {
        "capability": "INVESTIGATION",
        "searches": [
            {
                "safe": True,
                "qualification_consistent": False,
                "execution_error": "QUALIFICATION_EXECUTION_INCONSISTENCY",
                "rows": [{"event_count": "500", "aria_required_signal_distinct": "0"}],
            }
        ],
    }
    inconsistent = agent.triage(
        "Triage the current investigation results.",
        last_result=inconsistent_prior,
    )
    check(inconsistent.metadata["triage_confidence"] == 0, "inconsistent execution rows are excluded from Triage")
    print("ARIA_V3_TRIAGE_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
