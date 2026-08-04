from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("OLLAMA_FAST_MODEL", "test-fast")
os.environ.setdefault("OLLAMA_REASONING_MODEL", "test-reasoning")
os.environ.setdefault("OLLAMA_EMBEDDING_MODEL", "test-embed")
os.environ.setdefault("SPLUNK_URL", "https://127.0.0.1:8089")
os.environ.setdefault("SPLUNK_USERNAME", "test")
os.environ.setdefault("SPLUNK_PASSWORD", "test")
os.environ.setdefault("SPLUNK_VERIFY_SSL", "false")

from scripts.live_v3_acceptance import (  # noqa: E402
    validate_conversation_result,
    validate_investigation_result,
    validate_triage_handoff,
)


def search(
    *,
    rows,
    observed_event_count,
    qualification_consistent,
    required_field_presence=None,
    fully_bound_event_count=None,
    execution_error=None,
):
    return SimpleNamespace(
        evidence_id="QRY-1",
        spl='search index="live" sourcetype="observed" | head 500 | stats count as event_count',
        safe=True,
        rows=rows,
        observed_event_count=observed_event_count,
        required_field_presence=required_field_presence or {},
        fully_bound_event_count=fully_bound_event_count,
        qualification_consistent=qualification_consistent,
        execution_error=execution_error,
    )


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 Live Evidence Continuity Test")
    print("=====================================")

    positive = SimpleNamespace(
        searches=[
            search(
                rows=[{"event_count": "25"}],
                observed_event_count=25,
                required_field_presence={"required_signal": 25},
                fully_bound_event_count=25,
                qualification_consistent=True,
            )
        ]
    )
    check(
        validate_investigation_result(positive) == [],
        "positive bounded evidence passes the connected contract",
    )

    no_rows = SimpleNamespace(
        searches=[
            search(
                rows=[],
                observed_event_count=None,
                qualification_consistent=False,
            )
        ]
    )
    no_row_failures = validate_investigation_result(no_rows)
    check(
        any("no evidence rows" in item for item in no_row_failures),
        "safe execution without rows fails acceptance",
    )
    check(
        any("contradicted" in item for item in no_row_failures),
        "qualification/execution contradiction fails acceptance",
    )

    zero_events = SimpleNamespace(
        searches=[
            search(
                rows=[{"event_count": "0"}],
                observed_event_count=0,
                qualification_consistent=False,
            )
        ]
    )
    check(
        any(
            "represented no live events" in item
            for item in validate_investigation_result(zero_events)
        ),
        "synthetic zero-count rows cannot satisfy live acceptance",
    )

    missing_required_field = SimpleNamespace(
        searches=[
            search(
                rows=[
                    {
                        "event_count": "500",
                        "aria_required_signal_distinct": "0",
                        "aria_required_1_present": "0",
                        "aria_required_all_present": "0",
                    }
                ],
                observed_event_count=500,
                required_field_presence={"required_signal": 0},
                fully_bound_event_count=0,
                qualification_consistent=False,
            )
        ]
    )
    missing_field_failures = validate_investigation_result(missing_required_field)
    check(
        any("unpopulated required field" in item for item in missing_field_failures),
        "positive event count with an empty required field fails acceptance",
    )
    check(
        any("no fully-bound execution event" in item for item in missing_field_failures),
        "missing fully-bound execution evidence fails acceptance",
    )

    triage_ok = SimpleNamespace(
        metadata={
            "prior_investigation_available": True,
            "triage_confidence": 35,
            "supporting_evidence": ["ROW-1"],
        }
    )
    check(
        validate_triage_handoff(triage_ok, 1) == [],
        "returned investigation evidence survives into Triage",
    )

    triage_lost = SimpleNamespace(
        metadata={
            "prior_investigation_available": True,
            "triage_confidence": 0,
            "supporting_evidence": [],
        }
    )
    triage_failures = validate_triage_handoff(triage_lost, 1)
    check(
        any("zero confidence" in item for item in triage_failures),
        "zero-confidence evidence handoff fails acceptance",
    )
    check(
        any("preserve evidence identifiers" in item for item in triage_failures),
        "lost evidence identifiers fail acceptance",
    )

    detailed_paragraph = (
        " Analysts connect the framework to relevant assets, trust boundaries, "
        "telemetry categories, analytic hypotheses, validation evidence, response "
        "decisions and documented limitations. They confirm source availability, "
        "field population, time coverage, relationships and representative tests "
        "before claiming that a behaviour is observable or controlled."
    )
    deep_answer = "\n\n".join([
        "## ARIA v3 SOC Conversation Agent\n\n**Splunk execution:** `NO`",
        "### Exact definition\n\nMITRE ATLAS is the exact named framework requested by the analyst." + detailed_paragraph,
        "### Scope and structure\n\nThe structure organises threat knowledge for practical analysis." + detailed_paragraph,
        "### Relationship to adjacent concepts\n\nAdjacent frameworks are related but are not substitutes." + detailed_paragraph,
        "### SOC operational use\n\nSOC roles use the framework for threat modelling and validation." + detailed_paragraph,
        "### Splunk application\n\nSplunk supplies deployment evidence rather than framework truth." + detailed_paragraph,
        "### Limitations and validation\n\nThe framework does not prove that any local event is malicious." + detailed_paragraph,
    ])
    conversation_ok = SimpleNamespace(
        capability="SOC_CONVERSATION",
        answer=deep_answer,
        searches=[],
        metadata={
            "live_splunk_queries": False,
            "splunk_executed": False,
            "model_status": "LOCAL_MODEL",
            "response_contract_validated": True,
            "subject_fidelity_validated": True,
            "response_depth": "DEEP_FRAMEWORK",
            "response_word_count": len(deep_answer.split()),
            "conversation_context_mode": "ISOLATED_STANDALONE",
        },
    )
    check(
        validate_conversation_result(conversation_ok, "What is MITRE ATLAS?") == [],
        "deep exact-subject conversation passes connected acceptance",
    )

    substituted_answer = deep_answer.replace(
        "MITRE ATLAS is the exact named framework requested by the analyst.",
        "MITRE ATT&CK is the framework being defined. MITRE ATLAS is only adjacent.",
        1,
    )
    substituted = SimpleNamespace(
        **{
            **conversation_ok.__dict__,
            "answer": substituted_answer,
        }
    )
    check(
        any(
            "named subject anchor" in item
            for item in validate_conversation_result(
                substituted,
                "What is MITRE ATLAS?",
            )
        ),
        "adjacent-framework substitution fails connected acceptance",
    )

    shallow = SimpleNamespace(
        **{
            **conversation_ok.__dict__,
            "answer": "### Exact definition\n\nMITRE ATLAS is a framework.",
            "metadata": {
                **conversation_ok.metadata,
                "response_word_count": 7,
            },
        }
    )
    shallow_failures = validate_conversation_result(
        shallow,
        "What is MITRE ATLAS?",
    )
    check(
        any("minimum of 260 words" in item for item in shallow_failures),
        "shallow framework answer fails connected acceptance",
    )
    check(
        any("omitted deep section" in item for item in shallow_failures),
        "incomplete framework structure fails connected acceptance",
    )

    print("ARIA_V3_LIVE_EVIDENCE_CONTINUITY_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
