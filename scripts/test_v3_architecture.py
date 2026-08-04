from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 Multi-Agent Architecture Test")
    print("=====================================")
    required = [
        "aria/v3/router.py",
        "aria/v3/orchestrator.py",
        "aria/v3/telemetry_intelligence.py",
        "aria/v3/conversation_agent.py",
        "aria/v3/deliverable_agent.py",
        "aria/v3/reference_knowledge.py",
        "aria/v3/spl_builder_agent.py",
        "aria/v3/investigation_agent.py",
        "aria/v3/triage_agent.py",
        "aria/v3/contracts.py",
    ]
    for relative in required:
        path = ROOT / relative
        check(path.exists() and path.stat().st_size > 0, f"{relative} present")
        ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    engine = (ROOT / "aria/copilot/engine.py").read_text(encoding="utf-8")
    check("ARIAV3Orchestrator" in engine, "compatibility engine delegates to v3 orchestrator")
    orchestrator = (ROOT / "aria/v3/orchestrator.py").read_text(encoding="utf-8")
    check("V3Router" in orchestrator, "deterministic control-plane router wired")
    check("TelemetryIntelligenceService" in orchestrator, "shared telemetry intelligence wired")
    check("SPLBuilderAgent" in orchestrator and "InvestigationAgent" in orchestrator and "TriageAgent" in orchestrator, "isolated product agents wired")
    check("EvidenceDeliverableAgent" in orchestrator, "evidence-bound post-investigation deliverables wired")
    conversation = (ROOT / "aria/v3/conversation_agent.py").read_text(encoding="utf-8")
    check("ISOLATED_STANDALONE" in conversation and "SAME_AGENT_FOLLOWUP" in conversation, "conversation context is isolated by agent and intent")
    check("_validate_conversation_answer" in conversation, "conversation output has a deterministic leakage contract")
    check("_subject_fidelity_valid" in conversation and "DEEP_FRAMEWORK" in conversation, "conversation enforces named-subject fidelity and useful depth")
    check("ARIA_V3_CONVERSATION_DEEP_MODEL_ROLE" in conversation, "deep explanations use a configurable local reasoning role")
    check("LocalReferenceStore" in conversation and "LOCAL_REFERENCE_FALLBACK" in conversation, "conversation supports cited offline grounding and deterministic fallback")
    references = (ROOT / "aria/v3/reference_knowledge.py").read_text(encoding="utf-8")
    check("ReferenceMatch" in references and "Authoritative local references" in references, "reference grounding is generic and source-attributed")
    router = (ROOT / "aria/v3/router.py").read_text(encoding="utf-8")
    check("structured_chat" not in router and ".chat(" not in router, "routing has no generative dependency")
    builder = (ROOT / "aria/v3/spl_builder_agent.py").read_text(encoding="utf-8")
    check("SEMANTIC_PLAN_THEN_DETERMINISTIC_COMPILE" in builder, "SPL builder separates semantic planning from compilation")
    check("SCHEMA_QUALIFIED" in builder and "RESULT_VALIDATED" in (ROOT / "aria/v3/contracts.py").read_text(encoding="utf-8"), "SPL validation states are explicit")
    triage = (ROOT / "aria/v3/triage_agent.py").read_text(encoding="utf-8")
    check("supporting_evidence" in triage and "ROW-" in triage, "triage verdicts require evidence references")
    print("ARIA_V3_ARCHITECTURE_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
