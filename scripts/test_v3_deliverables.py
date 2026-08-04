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

from aria.v3.deliverable_agent import EvidenceDeliverableAgent
from aria.v3.orchestrator import ARIAV3Orchestrator


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def investigation_context() -> dict:
    return {
        "origin_capability": "INVESTIGATION",
        "goal": "Investigate analyst-requested network behaviour using live evidence.",
        "plan": {
            "capability": "QUERY_SPLUNK",
            "goal": "Investigate analyst-requested network behaviour using live evidence.",
            "explicit_entities": [],
        },
        "source_evidence": [
            {
                "evidence_id": "SRC-1",
                "candidate_id": "C1",
                "index": "live_index",
                "sourcetype": "security:telemetry",
                "score": 88.0,
                "accepted": True,
                "requirement_bindings": [
                    {
                        "requirement_id": "R1",
                        "status": "SUPPORTED",
                        "fields": ["observed_signal"],
                    }
                ],
            }
        ],
        "searches": [
            {
                "evidence_id": "QRY-1",
                "safe": True,
                "spl": (
                    'search index="live_index" sourcetype="security:telemetry" '
                    "earliest=-24h latest=now\n| head 100"
                ),
                "rows": [{"event_count": "12", "aria_observed_signal_distinct": "2"}],
                "qualification_consistent": True,
            }
        ],
        "finding": {
            "verdict": "INSUFFICIENT_EVIDENCE",
            "summary": "Live activity was returned but maliciousness was not established.",
            "missing_evidence": [
                "Validated entity attribution",
                "Corroborating behaviour-specific evidence",
            ],
        },
        "confidence": {"score": 53, "factors": []},
        "risk": None,
        "spl_variants": {"generic": None, "deployment": None},
    }


def main() -> int:
    print("ARIA v3 Evidence Deliverable Agent Test")
    print("=======================================")
    agent = EvidenceDeliverableAgent()
    triage = {
        "capability": "TRIAGE",
        "goal": "Triage the current investigation.",
        "finding": {
            "verdict": "INSUFFICIENT_EVIDENCE",
            "summary": "Evidence does not support a definitive verdict.",
            "missing_evidence": ["Validated entity attribution"],
        },
        "metadata": {
            "triage_verdict": "INSUFFICIENT_EVIDENCE",
            "triage_confidence": 18,
            "supporting_evidence": ["ROW-1"],
            "contradicting_evidence": [],
            "evidence_context": investigation_context(),
        },
    }

    detection = agent.create(
        "Draft a detection candidate from the current investigation.",
        "DETECTION_ENGINEERING",
        last_result=triage,
    )
    check(detection.capability == "DETECTION_ENGINEERING", "detection deliverable capability")
    check(detection.metadata["live_splunk_queries"] is False, "detection deliverable runs no Splunk query")
    check(detection.metadata["operational_action_executed"] is False, "detection deliverable activates nothing")
    check("`QRY-1`" in detection.answer, "detection cites carried evidence")
    check("NOT_AVAILABLE_FROM_CURRENT_EVIDENCE" in detection.answer, "missing portable SPL remains explicit")
    check("EVIDENCE_BOUND_DRAFT" in detection.answer, "detection readiness is bounded")

    risk = agent.create(
        "Create an evidence-aware RBA and ERS recommendation.",
        "RISK_SCORING",
        last_result=detection.model_dump(),
    )
    check(risk.capability == "RISK_SCORING", "risk deliverable capability")
    check(
        {"SRC-1", "QRY-1", "ROW-1"}.issubset(set(risk.metadata["evidence_ids"])),
        "risk reuses original and triage evidence IDs",
    )
    check("NOT_ELIGIBLE" in risk.answer, "missing risk object blocks scoring")
    check("NOT CALCULATED" in risk.answer, "unsupported risk score is not invented")

    tdir = agent.create(
        "Draft an approval-gated TDIR workflow.",
        "TDIR_WORKFLOW",
        last_result=risk.model_dump(),
    )
    check(tdir.capability == "TDIR_WORKFLOW", "TDIR deliverable capability")
    check("Analyst decision points" in tdir.answer, "TDIR includes decision points")
    check("Recovery and rollback" in tdir.answer, "TDIR includes rollback")
    check("Operational action executed:** `NO`" in tdir.answer, "TDIR executes no response")
    check(
        {"SRC-1", "QRY-1", "ROW-1"}.issubset(set(tdir.metadata["evidence_ids"])),
        "TDIR preserves evidence through chained deliverables",
    )

    generated = {
        "capability": "BUILD_SPL",
        "metadata": {
            "generic_spl": {
                "spl": "search index={INDEX} sourcetype={SOURCETYPE} earliest={EARLIEST} latest={LATEST}\n| head 100"
            },
            "deployment_spl": {
                "spl": 'search index="live_index" sourcetype="security:telemetry" earliest=-24h latest=now\n| head 100'
            },
        },
    }
    resolved = ARIAV3Orchestrator._extract_spl(
        "Review the generated SPL and explain every stage.",
        last_result=generated,
    )
    check('index="live_index"' in resolved, "generated SPL review resolves the deployment-qualified variant")

    print("ARIA_V3_DELIVERABLE_AGENT_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
