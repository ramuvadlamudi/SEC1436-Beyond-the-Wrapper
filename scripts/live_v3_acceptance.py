from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aria.copilot.engine import copilot_engine
from aria.v3.reference_knowledge import LocalReferenceStore, ReferenceMatch


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "data" / "test_results" / "live_v3_acceptance.json"
BLOCKED_TERMS = ("| delete", "| collect", "| mcollect", "| outputlookup", "| sendalert", "| notable")
CONVERSATION_LEAKAGE_PATTERNS = (
    r"\baria\s+v3\s+investigation\s+agent\b",
    r"\bcapability\b.{0,16}\bquery_splunk\b",
    r"\blive_splunk_read_only\b",
    r"\bverdict\b.{0,6}:",
    r"\bevidence\s+confidence\b.{0,6}:",
)
CONVERSATION_QUESTION_STOPWORDS = {
    "about", "and", "are", "can", "concept", "describe", "explain", "for",
    "from", "how", "in", "is", "me", "of", "please", "security", "splunk",
    "the", "to", "what", "why", "with",
}
CONVERSATION_DEEP_SECTIONS = (
    "Exact definition",
    "Scope and structure",
    "Relationship to adjacent concepts",
    "SOC operational use",
    "Splunk application",
    "Limitations and validation",
)


def positive_event_count(search: Any) -> int:
    explicit = getattr(search, "observed_event_count", None)
    if explicit is not None:
        try:
            return max(0, int(explicit))
        except (TypeError, ValueError):
            return 0
    total = 0
    for row in getattr(search, "rows", []) or []:
        for key in ("event_count", "sampled_events", "source_event_count"):
            if key not in row:
                continue
            try:
                total += max(0, int(float(row.get(key) or 0)))
            except (TypeError, ValueError):
                continue
            break
    return total


def validate_investigation_result(investigation: Any) -> list[str]:
    failures: list[str] = []
    searches = list(getattr(investigation, "searches", []) or [])
    if not searches:
        return ["investigation executed no read-only search"]

    positive_events = 0
    returned_rows = 0
    for search in searches:
        lower = str(search.spl or "").lower()
        if not search.safe:
            failures.append(
                f"investigation search {search.evidence_id} failed safety validation"
            )
        if any(term in lower for term in BLOCKED_TERMS):
            failures.append(
                f"investigation search {search.evidence_id} contains a write/action command"
            )
        if search.execution_error:
            failures.append(
                f"investigation search {search.evidence_id} failed execution: "
                f"{search.execution_error}"
            )
        if search.qualification_consistent is False:
            failures.append(
                f"investigation search {search.evidence_id} contradicted its "
                "source-qualification probe"
            )
        required_presence = dict(
            getattr(search, "required_field_presence", {}) or {}
        )
        if not required_presence:
            failures.append(
                f"investigation search {search.evidence_id} did not report "
                "required-field execution presence"
            )
        elif any(int(count or 0) <= 0 for count in required_presence.values()):
            failures.append(
                f"investigation search {search.evidence_id} returned an "
                "unpopulated required field"
            )
        fully_bound = getattr(search, "fully_bound_event_count", None)
        if required_presence and int(fully_bound or 0) <= 0:
            failures.append(
                f"investigation search {search.evidence_id} returned no "
                "fully-bound execution event"
            )
        returned_rows += len(search.rows)
        positive_events += positive_event_count(search)

    if returned_rows < 1:
        failures.append(
            "investigation returned no evidence rows; safe execution alone is not acceptance"
        )
    if positive_events < 1:
        failures.append("investigation evidence rows represented no live events")
    return failures


def validate_triage_handoff(triage: Any, investigation_rows: int) -> list[str]:
    if investigation_rows < 1:
        return []
    failures: list[str] = []
    if not triage.metadata.get("prior_investigation_available"):
        failures.append("triage did not retain the current investigation context")
    if int(triage.metadata.get("triage_confidence") or 0) <= 0:
        failures.append("triage assigned zero confidence despite returned investigation evidence")
    if not triage.metadata.get("supporting_evidence"):
        failures.append("triage did not preserve evidence identifiers from returned rows")
    return failures


def validate_deliverable_result(
    result: Any,
    expected_capability: str,
    *,
    require_evidence: bool = True,
) -> list[str]:
    failures: list[str] = []
    metadata = dict(getattr(result, "metadata", {}) or {})
    if getattr(result, "capability", "") != expected_capability:
        failures.append(
            f"deliverable routed to {getattr(result, 'capability', '')}, "
            f"expected {expected_capability}"
        )
    if metadata.get("live_splunk_queries"):
        failures.append(f"{expected_capability} executed a new Splunk query")
    if metadata.get("operational_action_executed"):
        failures.append(f"{expected_capability} executed an operational action")
    if getattr(result, "searches", None):
        failures.append(f"{expected_capability} returned newly executed search records")
    if require_evidence and not metadata.get("evidence_ids"):
        failures.append(f"{expected_capability} lost the structured evidence handoff")
    if not metadata.get("evidence_context"):
        failures.append(f"{expected_capability} did not preserve evidence context")
    return failures


def validate_conversation_result(
    conversation: Any,
    question: str,
    *,
    expected_reference: ReferenceMatch | None = None,
) -> list[str]:
    failures: list[str] = []
    metadata = dict(getattr(conversation, "metadata", {}) or {})
    answer = str(getattr(conversation, "answer", "") or "").strip()
    if conversation.capability != "SOC_CONVERSATION":
        failures.append(f"conversation question routed to {conversation.capability}")
    if not answer:
        failures.append("conversation returned an empty answer")
    if metadata.get("live_splunk_queries") is not False or metadata.get("splunk_executed") is not False:
        failures.append("conversation did not explicitly preserve zero Splunk execution")
    if list(getattr(conversation, "searches", []) or []):
        failures.append("conversation returned Splunk search records")
    if metadata.get("model_status") not in {
        "LOCAL_MODEL",
        "LOCAL_MODEL_REPAIRED",
        "LOCAL_REFERENCE_FALLBACK",
    }:
        failures.append(f"conversation local model status is {metadata.get('model_status')}")
    if metadata.get("response_contract_validated") is not True:
        failures.append("conversation response did not pass the deterministic response contract")
    if metadata.get("subject_fidelity_validated") is not True:
        failures.append("conversation did not preserve exact named-subject fidelity")
    if metadata.get("response_depth") != "DEEP_FRAMEWORK":
        failures.append(
            f"conversation did not use the deep framework contract: "
            f"{metadata.get('response_depth')}"
        )
    actual_word_count = len(re.findall(r"\b[\w&'-]+\b", answer))
    if (
        int(metadata.get("response_word_count") or 0) < 260
        or actual_word_count < 260
    ):
        failures.append(
            "conversation answer did not meet the release minimum of 260 words"
        )
    missing_sections = [
        section
        for section in CONVERSATION_DEEP_SECTIONS
        if not re.search(rf"(?im)^###\s+{re.escape(section)}\s*$", answer)
    ]
    if missing_sections:
        failures.append(
            "conversation answer omitted deep section(s): "
            + ", ".join(missing_sections)
        )
    if metadata.get("conversation_context_mode") != "ISOLATED_STANDALONE":
        if not expected_reference or metadata.get("conversation_context_mode") != "SAME_AGENT_FOLLOWUP":
            failures.append(
                "conversation context mode did not preserve the expected isolation boundary"
            )
    for pattern in CONVERSATION_LEAKAGE_PATTERNS:
        if re.search(pattern, answer, re.IGNORECASE):
            failures.append(f"conversation leaked operational investigation output: {pattern}")
            break

    topic_terms = [
        token.lower()
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:/&-]*", question)
        if len(token) >= 4 and token.lower() not in CONVERSATION_QUESTION_STOPWORDS
    ]
    if topic_terms and not any(term in answer.lower() for term in topic_terms[:6]):
        failures.append("conversation answer did not address the current analyst topic")

    subject_anchors = [
        str(token).lower()
        for token in metadata.get("subject_anchors") or []
    ]
    if not subject_anchors:
        subject_anchors = [
            token.lower()
            for token in re.findall(r"\b[A-Z][A-Z0-9&.-]{2,}\b", question)
        ]
    definition = re.search(
        r"(?ims)^###\s+Exact definition\s*$\s*(.+?)(?=^###\s+|\Z)",
        answer,
    )
    first_sentence = ""
    if definition:
        first_sentence = re.split(
            r"(?<=[.!?])\s+",
            " ".join(definition.group(1).strip().split()),
            maxsplit=1,
        )[0].lower()
    if subject_anchors and not all(anchor in first_sentence for anchor in subject_anchors):
        failures.append(
            "conversation exact definition did not preserve every named subject anchor"
        )
    if expected_reference:
        if metadata.get("grounding_status") != "LOCAL_REFERENCE":
            failures.append("conversation did not use authoritative local reference grounding")
        if list(metadata.get("reference_card_ids") or []) != expected_reference.card_ids:
            failures.append("conversation selected an unexpected local reference card")
        grounded_valid, grounded_reason = LocalReferenceStore.validate_answer(
            answer,
            expected_reference,
        )
        if not grounded_valid:
            failures.append(f"conversation grounding validation failed: {grounded_reason}")
    return failures


def record_result(name: str, result: Any, elapsed: float) -> dict[str, Any]:
    payload = result.model_dump()
    return {
        "name": name,
        "capability": result.capability,
        "elapsed_seconds": round(elapsed, 2),
        "metadata": payload.get("metadata") or {},
        "searches": payload.get("searches") or [],
        "finding": payload.get("finding"),
        "confidence": payload.get("confidence"),
        "answer_preview": str(result.answer or "")[:1200],
    }


def run(
    question: str,
    *,
    last_result: dict[str, Any] | None = None,
    history: list[dict[str, Any]] | None = None,
) -> tuple[Any, float]:
    started = time.monotonic()
    result = copilot_engine.invoke(
        question,
        last_result=last_result,
        history=history or [],
    )
    return result, time.monotonic() - started


def main() -> int:
    parser = argparse.ArgumentParser(description="Blocking connected acceptance for all four ARIA v3 agents.")
    parser.add_argument(
        "--build-question",
        required=True,
        help="A BUILD_SPL request with an explicit time range. It may include analyst-supplied source constraints.",
    )
    parser.add_argument(
        "--investigation-question",
        required=True,
        help="An evidence-first live Splunk investigation request with an explicit time range.",
    )
    parser.add_argument(
        "--triage-value",
        default="",
        help="Optional finding, notable, incident or entity value used when the investigation returns no rows.",
    )
    parser.add_argument(
        "--conversation-question",
        default="What is MITRE ATLAS?",
        help="A standalone named-framework question used after Investigation and Triage to prove context isolation, subject fidelity and useful depth.",
    )
    parser.add_argument(
        "--conversation-followup-question",
        default="How can a SOC use that framework to monitor AI-enabled systems with Splunk?",
        help="A referential SOC follow-up used to prove that the grounded framework survives conversation continuity.",
    )
    parser.add_argument("--max-build-seconds", type=int, default=120)
    parser.add_argument("--max-investigation-seconds", type=int, default=300)
    parser.add_argument("--max-conversation-seconds", type=int, default=180)
    parser.add_argument("--max-triage-seconds", type=int, default=120)
    args = parser.parse_args()

    failures: list[str] = []
    results: list[dict[str, Any]] = []

    inventory, elapsed = run("Give me telemetry from the connected Splunk instance")
    results.append(record_result("inventory", inventory, elapsed))
    if inventory.capability != "INVENTORY":
        failures.append(f"inventory routed to {inventory.capability}")
    if int(inventory.metadata.get("catalog_rows") or 0) < 1:
        failures.append("inventory returned no catalogue rows")
    if elapsed > 15:
        failures.append(f"inventory exceeded 15 seconds: {elapsed:.1f}")

    build, elapsed = run(args.build_question)
    results.append(record_result("build_spl", build, elapsed))
    if build.capability != "BUILD_SPL":
        failures.append(f"build question routed to {build.capability}")
    deployment = build.metadata.get("deployment_spl") or {}
    if deployment.get("status") not in {"SCHEMA_QUALIFIED", "DATA_VALIDATED", "RESULT_VALIDATED"}:
        failures.append(f"deployment SPL was not qualified: {deployment.get('status')}")
    if not deployment.get("safe"):
        failures.append("deployment SPL did not pass safety validation")
    if deployment.get("executed"):
        failures.append("BUILD_SPL executed the final generated search")
    if not str(deployment.get("spl") or "").strip():
        failures.append("deployment SPL is empty")
    if elapsed > args.max_build_seconds:
        failures.append(f"BUILD_SPL exceeded {args.max_build_seconds} seconds: {elapsed:.1f}")

    investigation, elapsed = run(args.investigation_question)
    results.append(record_result("investigation", investigation, elapsed))
    if investigation.capability == "COPILOT_ERROR":
        failures.append("investigation returned COPILOT_ERROR")
    if investigation.capability != "INVESTIGATION":
        failures.append(f"investigation routed to {investigation.capability}")
    failures.extend(validate_investigation_result(investigation))
    if elapsed > args.max_investigation_seconds:
        failures.append(f"investigation exceeded {args.max_investigation_seconds} seconds: {elapsed:.1f}")

    investigation_payload = investigation.model_dump()
    investigation_rows = sum(len(item.get("rows") or []) for item in investigation_payload.get("searches") or [])

    if investigation_rows:
        triage_question = "Triage the current investigation results and return a verdict, confidence, evidence gaps and next action."
    elif args.triage_value:
        triage_question = f'Triage finding ID "{args.triage_value}" across all available time and return a verdict, confidence, evidence gaps and next action.'
    else:
        triage_question = "Triage the current investigation results and explain the evidence gap."
    triage, elapsed = run(triage_question, last_result=investigation_payload)
    results.append(record_result("triage", triage, elapsed))
    if triage.capability != "TRIAGE":
        failures.append(f"triage routed to {triage.capability}")
    if triage.metadata.get("triage_verdict") not in {
        "TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS", "BENIGN_OR_EXPECTED", "INSUFFICIENT_EVIDENCE",
    }:
        failures.append("triage returned no valid verdict")
    confidence = triage.metadata.get("triage_confidence")
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        failures.append("triage confidence is missing or out of range")
    failures.extend(validate_triage_handoff(triage, investigation_rows))
    if elapsed > args.max_triage_seconds:
        failures.append(f"triage exceeded {args.max_triage_seconds} seconds: {elapsed:.1f}")

    triage_payload = triage.model_dump()
    deliverable_failures: list[str] = []
    detection_question = (
        "Using only the validated evidence from the current investigation, draft a "
        "detection candidate. Include the security hypothesis, required telemetry, "
        "portable SPL, deployment-qualified SPL where supported, validation state, "
        "false-positive considerations, evidence gaps and analyst approval requirements. "
        "Do not activate the detection."
    )
    detection, elapsed = run(detection_question, last_result=triage_payload)
    results.append(record_result("detection_candidate", detection, elapsed))
    current = validate_deliverable_result(
        detection,
        "DETECTION_ENGINEERING",
        require_evidence=investigation_rows > 0,
    )
    deliverable_failures.extend(current)
    failures.extend(current)

    risk_question = (
        "Create an evidence-aware RBA and Entity Risk Scoring recommendation from the "
        "current investigation. Identify the proposed risk object, risk message, "
        "contributing evidence, scoring rationale, uncertainty and approval gates. "
        "Do not create or write a risk event."
    )
    risk, elapsed = run(risk_question, last_result=detection.model_dump())
    results.append(record_result("risk_recommendation", risk, elapsed))
    current = validate_deliverable_result(
        risk,
        "RISK_SCORING",
        require_evidence=investigation_rows > 0,
    )
    deliverable_failures.extend(current)
    failures.extend(current)

    tdir_question = (
        "Draft an approval-gated TDIR workflow for the current investigation. Separate "
        "automated read-only enrichment, analyst decision points and potentially "
        "disruptive response actions. Include rollback, evidence preservation and "
        "escalation requirements. Do not execute any response action."
    )
    tdir, elapsed = run(tdir_question, last_result=risk.model_dump())
    results.append(record_result("tdir_workflow", tdir, elapsed))
    current = validate_deliverable_result(
        tdir,
        "TDIR_WORKFLOW",
        require_evidence=investigation_rows > 0,
    )
    deliverable_failures.extend(current)
    failures.extend(current)

    conversation_history = [
        {"role": "user", "content": args.investigation_question},
        {
            "role": "assistant",
            "capability": investigation.capability,
            "content": investigation.answer,
        },
        {"role": "user", "content": triage_question},
        {
            "role": "assistant",
            "capability": triage.capability,
            "content": triage.answer,
        },
    ]
    reference_store = LocalReferenceStore()
    expected_reference = reference_store.match(args.conversation_question)
    if expected_reference is None:
        failures.append("connected conversation question has no authoritative local reference card")

    conversation, elapsed = run(
        args.conversation_question,
        last_result=triage_payload,
        history=conversation_history,
    )
    results.append(record_result("soc_conversation", conversation, elapsed))
    conversation_failures = validate_conversation_result(
        conversation,
        args.conversation_question,
        expected_reference=expected_reference,
    )
    failures.extend(conversation_failures)
    if elapsed > args.max_conversation_seconds:
        failures.append(
            f"SOC conversation exceeded {args.max_conversation_seconds} seconds: "
            f"{elapsed:.1f}"
        )

    conversation_payload = conversation.model_dump()
    followup_history = [
        *conversation_history,
        {"role": "user", "content": args.conversation_question},
        {
            "role": "assistant",
            "capability": conversation.capability,
            "content": conversation.answer,
        },
    ]
    followup, elapsed = run(
        args.conversation_followup_question,
        last_result=conversation_payload,
        history=followup_history,
    )
    results.append(record_result("soc_followup", followup, elapsed))
    followup_failures = validate_conversation_result(
        followup,
        args.conversation_followup_question,
        expected_reference=expected_reference,
    )
    conversation_failures.extend(followup_failures)
    failures.extend(followup_failures)
    if elapsed > args.max_conversation_seconds:
        failures.append(
            f"SOC follow-up exceeded {args.max_conversation_seconds} seconds: "
            f"{elapsed:.1f}"
        )

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": (ROOT / "product" / "VERSION").read_text(encoding="utf-8").strip(),
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "results": results,
        "questions": {
            "build": args.build_question,
            "investigation": args.investigation_question,
            "conversation": args.conversation_question,
            "conversation_followup": args.conversation_followup_question,
            "triage": triage_question,
            "detection_candidate": detection_question,
            "risk_recommendation": risk_question,
            "tdir_workflow": tdir_question,
        },
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("ARIA v3 Connected Live Acceptance")
    print("=================================")
    for item in results:
        print(f"{'PASS' if item['capability'] != 'COPILOT_ERROR' else 'FAIL':<6} {item['name']:<15} capability={item['capability']} elapsed={item['elapsed_seconds']}s")
    if failures:
        for failure in failures:
            print(f"FAIL   {failure}")
    print(f"REPORT {REPORT}")
    print(
        "ARIA_V3_CONVERSATION_LIVE_ACCEPTANCE="
        f"{'PASS' if not conversation_failures else 'FAIL'}"
    )
    print(
        "ARIA_V3_DELIVERABLE_LIVE_ACCEPTANCE="
        f"{'PASS' if not deliverable_failures else 'FAIL'}"
    )
    print(f"ARIA_V3_LIVE_ACCEPTANCE={'PASS' if not failures else 'FAIL'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
