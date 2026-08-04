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

from aria.copilot.contracts import EvidenceRequirement, InvestigationPlan
from aria.v3.investigation_agent import InvestigationAgent


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 Investigation Contract Test")
    print("===================================")
    cleaned = InvestigationAgent._clean_control_language(
        "Build and execute SPL using live Splunk evidence to investigate encoded command activity. Discover the source and fields rather than assuming them."
    )
    check(cleaned.lower().startswith("investigate encoded command activity"), "workflow control language removed from threat intent")
    agent = object.__new__(InvestigationAgent)
    plan = InvestigationPlan(
        capability="QUERY_SPLUNK",
        goal=cleaned,
        requirements=[EvidenceRequirement(requirement_id="R1", concept="Build and", role="activity", required=True, reason="bad planner output")],
    )
    repaired = agent._repair_plan(cleaned, plan)
    check(all(item.concept.lower() != "build and" for item in repaired.requirements), "workflow directive cannot remain required evidence")
    check(any(item.required and "encoded" in item.concept.lower() for item in repaired.requirements), "security behaviour becomes required evidence")
    check(repaired.execute_read_only_search is True, "investigation contract executes read-only evidence search")
    print("ARIA_V3_INVESTIGATION_CONTRACT_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
