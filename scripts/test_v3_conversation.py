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
from aria.v3.conversation_agent import ConversationAgent
from aria.v3.orchestrator import ARIAV3Orchestrator


CONCEPT_QUESTION = "What is a threat-informed security framework?"
SAFE_ANSWER = """### Exact definition

A threat-informed security framework organises defensive decisions around documented adversary behaviours, relevant assets and validated defensive evidence.

### Scope and structure

The framework connects a threat model to defensive objectives, observable behaviours, telemetry requirements, analytic coverage and response decisions. It should distinguish what is known about adversary behaviour from what the organisation can actually observe. A mature implementation also records assumptions, evidence gaps, ownership and validation status so that a framework map is not mistaken for proven protection.

### Relationship to adjacent concepts

Threat-informed defence is related to risk management, control frameworks and compliance, but it is not interchangeable with them. Compliance shows whether prescribed requirements are addressed. Risk management prioritises exposure and business impact. A threat-informed framework focuses on how relevant adversaries operate and whether people, process and technology can prevent, observe or respond to those behaviours.

### SOC operational use

Analysts use the framework to structure investigations and communicate behaviour consistently. Detection engineers use it to identify telemetry and analytic gaps. Threat hunters use it to form testable hypotheses. Incident responders use it to connect observed actions into an attack narrative while preserving uncertainty. Leaders can use the same mapping to prioritise improvements without treating technique coverage as a simple maturity score.

### Splunk application

In Splunk, implementation starts by identifying the telemetry categories needed for each behaviour, confirming that the sources are available, validating field population and time coverage, and testing analytics against returned events. Dashboards can show coverage, data health and validation state. Live validation matters because a conceptual mapping does not prove that a deployment has the necessary logs, fields, extraction quality or event relationships.

### Limitations and validation

The framework does not prove that an attack occurred, that a detection is effective or that every mapped control works. Coverage counts can hide weak telemetry or untested analytics. Teams should validate framework content against authoritative references, document local assumptions, test representative behaviours and retain evidence for every operational claim."""

ATLAS_QUESTION = "What is MITRE ATLAS?"
ATLAS_SAFE_ANSWER = """### Exact definition

MITRE ATLAS, the Adversarial Threat Landscape for Artificial-Intelligence Systems, is a living knowledge base of adversary tactics and techniques against AI-enabled systems, grounded in real-world observations, demonstrations and security research.

### Scope and structure

ATLAS describes how adversaries can target machine-learning and AI systems across their lifecycle. It uses a tactic-and-technique taxonomy and links that knowledge to case studies and mitigations. Its scope includes attacks on AI data, models, interfaces, supply chains and dependent applications. The structure lets defenders move from an adversary objective to specific behaviours and then to the evidence and safeguards needed to investigate or reduce that exposure.

### Relationship to adjacent concepts

MITRE ATLAS is related to, but distinct from, MITRE ATT&CK. ATT&CK is the broader knowledge base of cyber-adversary behaviour across enterprise, cloud, mobile, industrial and related environments. ATLAS applies a similar threat-informed vocabulary to adversarial behaviour involving AI-enabled systems. They can overlap when an intrusion uses conventional infrastructure to reach an AI target, but an ATLAS mapping must not be replaced by an ATT&CK mapping.

### SOC operational use

SOC teams use ATLAS to threat-model AI services, structure hunts, design adversarial-AI detections, guide red-team scenarios and connect AI-specific observations to incident response. Relevant behaviours can include abuse of model interfaces, manipulation of data or model behaviour, discovery of AI assets, evasion, model theft and misuse of connected tools. The framework helps teams ask what evidence would support or contradict each hypothesis.

### Splunk application

Splunk can support ATLAS-aligned monitoring by bringing together AI gateway and application logs, prompt and response security metadata, model-serving telemetry, identity and access events, tool-call records, endpoint activity, network flows, data-pipeline events and change records. Analysts should map a selected ATLAS behaviour to the telemetry actually available, validate populated fields and relationships, and then test bounded analytics. The framework supplies threat context; Splunk supplies deployment facts.

### Limitations and validation

ATLAS is not proof that an event is malicious, a complete detection pack or a substitute for AI risk assessment and secure engineering. Its content evolves, and not every technique is relevant to every AI architecture. Teams should verify names, identifiers and current framework structure against an authoritative local copy, document applicable AI assets and trust boundaries, and require returned evidence before assigning a security verdict."""

WRONG_ATLAS_ANSWER = ATLAS_SAFE_ANSWER.replace(
    "MITRE ATLAS, the Adversarial Threat Landscape for Artificial-Intelligence Systems, is a living knowledge base of adversary tactics and techniques against AI-enabled systems, grounded in real-world observations, demonstrations and security research.",
    "MITRE ATT&CK is a knowledge base of conventional cyber-adversary tactics and techniques. MITRE ATLAS is mentioned only as an adjacent topic.",
    1,
)


class FakeOllama:
    def __init__(self, answers: list[str] | None = None) -> None:
        self.answers = list(answers or [SAFE_ANSWER])
        self.calls: list[dict] = []

    def chat(self, **kwargs):
        self.calls.append(kwargs)
        return self.answers.pop(0)


class NoSplunk:
    def __getattr__(self, name):
        raise AssertionError(f"SOC Conversation Agent attempted Splunk access through {name}")


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def investigation_history() -> list[dict[str, str]]:
    return [
        {
            "role": "user",
            "content": "Investigate an analyst-supplied behaviour using live Splunk evidence.",
        },
        {
            "role": "assistant",
            "capability": "INVESTIGATION",
            "content": (
                "## ARIA v3 Investigation Agent\n\n"
                "**Capability:** `QUERY_SPLUNK`\n\n"
                "**Execution:** `LIVE_SPLUNK_READ_ONLY`\n\n"
                "**Verdict:** `EVIDENCE_FOUND`"
            ),
        },
    ]


def main() -> int:
    print("ARIA v3 SOC Conversation Agent Test")
    print("===================================")

    ollama = FakeOllama()
    orchestrator = ARIAV3Orchestrator(
        ollama=ollama,
        splunk=NoSplunk(),
        validator=StaticSPLValidator(),
    )
    result = orchestrator.invoke(CONCEPT_QUESTION, history=investigation_history())
    check(result.capability == "SOC_CONVERSATION", "concept question routes to SOC Conversation Agent")
    check(result.metadata["live_splunk_queries"] is False, "conversation grants no Splunk query authority")
    check(result.metadata["splunk_executed"] is False, "conversation records no Splunk execution")
    check(result.metadata["conversation_context_mode"] == "ISOLATED_STANDALONE", "standalone question is isolated from investigation history")
    check(result.metadata["response_depth"] == "DEEP_FRAMEWORK", "framework question receives the deep response contract")
    check(result.metadata["response_word_count"] >= 260, "deep response meets the minimum useful depth")
    check(result.metadata["subject_fidelity_validated"] is True, "exact subject fidelity is validated")
    check(result.metadata["response_contract_validated"] is True, "conversation answer passes deterministic response contract")
    check("Investigation Agent" not in result.answer, "investigation output cannot leak into conversation")
    check("threat-informed" in result.answer.lower(), "answer addresses the current analyst topic")
    first_prompt = ollama.calls[0]["user_prompt"]
    check("ARIA v3 Investigation Agent" not in first_prompt, "operational history is absent from standalone model prompt")
    check(first_prompt.rstrip().endswith(CONCEPT_QUESTION), "current analyst question is the final prompt instruction")

    atlas_ollama = FakeOllama([WRONG_ATLAS_ANSWER, ATLAS_SAFE_ANSWER])
    atlas = ConversationAgent(atlas_ollama, StaticSPLValidator()).conversation(ATLAS_QUESTION)
    check(atlas.metadata["model_status"] == "LOCAL_REFERENCE_FALLBACK", "invalid grounded draft uses deterministic cited fallback")
    check(atlas.metadata["grounding_status"] == "LOCAL_REFERENCE", "named framework uses the local reference layer")
    check(atlas.metadata["reference_card_ids"] == ["mitre-atlas"], "exact framework reference card selected")
    check(atlas.metadata["reference_fallback_used"] is True, "grounded fallback use is explicit")
    check(atlas.metadata["subject_anchors"] == ["mitre", "atlas"], "all named subject anchors are retained")
    check(atlas.metadata["subject_fidelity_validated"] is True, "grounded named-framework answer preserves the exact subject")
    check(atlas.metadata["response_depth"] == "DEEP_FRAMEWORK", "named framework receives deep treatment")
    check(atlas.metadata["response_word_count"] >= 260, "named-framework answer has release-grade depth")
    check("Adversarial Threat Landscape" in atlas.answer, "answer defines the requested framework")
    check("distinct from" in atlas.answer, "answer distinguishes the adjacent framework")
    check("MITRE ATT&CK is a knowledge base" not in atlas.answer, "substituted first definition is suppressed")
    check("https://atlas.mitre.org/" in atlas.answer, "grounded answer cites the authoritative source")
    check(atlas_ollama.calls[0]["model_role"] == "fast", "grounded depth uses the fast local model before fallback")
    check(atlas_ollama.calls[0]["user_prompt"].rstrip().endswith(ATLAS_QUESTION), "grounded prompt keeps the current named subject as the final instruction")
    check(len(atlas_ollama.calls) == 1, "grounded failure does not spend a second model call")

    atlas_followup_history = [
        {"role": "user", "content": ATLAS_QUESTION},
        {"role": "assistant", "capability": "SOC_CONVERSATION", "content": atlas.answer},
    ]
    atlas_followup_ollama = FakeOllama([
        "NIST CSF and MITRE ATT&CK can be used to monitor enterprise systems."
    ])
    atlas_followup = ConversationAgent(
        atlas_followup_ollama,
        StaticSPLValidator(),
    ).conversation(
        "How can a SOC use that framework to monitor AI-enabled systems with Splunk?",
        history=atlas_followup_history,
    )
    check(atlas_followup.metadata["grounding_status"] == "LOCAL_REFERENCE", "referential framework follow-up retains local grounding")
    check(atlas_followup.metadata["subject_label"] == "MITRE ATLAS", "follow-up retains the referenced framework subject")
    check(atlas_followup.metadata["reference_fallback_used"] is True, "drifting follow-up uses grounded fallback")
    check("Adversarial Threat Landscape" in atlas_followup.answer, "follow-up cannot drift to a different framework")
    check("https://atlas.mitre.org/" in atlas_followup.answer, "follow-up preserves authoritative citation")

    contaminated = FakeOllama([
        (
            "ARIA v3 Investigation Agent\n"
            "Capability: QUERY_SPLUNK\n"
            "Execution: LIVE_SPLUNK_READ_ONLY\n"
            "Verdict: EVIDENCE_FOUND"
        ),
        SAFE_ANSWER,
    ])
    repaired = ConversationAgent(contaminated, StaticSPLValidator()).conversation(CONCEPT_QUESTION)
    check(repaired.metadata["model_status"] == "LOCAL_MODEL_REPAIRED", "operational model leakage triggers one bounded repair")
    check(repaired.metadata["response_contract_validated"] is True, "repaired response passes the contract")
    check(len(repaired.metadata["response_contract_rejections"]) == 1, "rejected draft is recorded")
    check("EVIDENCE_FOUND" not in repaired.answer, "rejected operational draft is never returned")

    unavailable = FakeOllama([
        "ARIA has identified suspicious activity. Verdict: EVIDENCE_FOUND",
        "index=customer_index | stats count",
    ])
    abstained = ConversationAgent(unavailable, StaticSPLValidator()).conversation(CONCEPT_QUESTION)
    check(abstained.metadata["model_status"] == "LOCAL_MODEL_UNAVAILABLE", "two invalid drafts fail closed")
    check(abstained.metadata["response_contract_validated"] is False, "failed response contract is explicit")
    check("EVIDENCE_FOUND" not in abstained.answer and "customer_index" not in abstained.answer, "invalid drafts are suppressed")

    followup_history = [
        {"role": "user", "content": CONCEPT_QUESTION},
        {"role": "assistant", "capability": "SOC_CONVERSATION", "content": SAFE_ANSWER},
    ]
    followup_ollama = FakeOllama([
        "That framework can be mapped to control coverage by linking each documented behaviour to telemetry, analytic logic and validation status."
    ])
    followup = ConversationAgent(followup_ollama, StaticSPLValidator()).conversation(
        "How is that mapped to control coverage?",
        history=followup_history,
    )
    check(followup.metadata["conversation_context_mode"] == "SAME_AGENT_FOLLOWUP", "referential follow-up receives same-agent context")
    check("Prior same-agent conversational context" in followup_ollama.calls[0]["user_prompt"], "follow-up context is explicitly labelled")
    check(followup_ollama.calls[0]["user_prompt"].rstrip().endswith("How is that mapped to control coverage?"), "follow-up question remains the final prompt instruction")

    print("ARIA_V3_CONVERSATION_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
