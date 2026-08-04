from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")
os.environ.setdefault("OLLAMA_FAST_MODEL", "test-fast")
os.environ.setdefault("OLLAMA_REASONING_MODEL", "test-reasoning")
os.environ.setdefault("OLLAMA_EMBEDDING_MODEL", "test-embed")
os.environ.setdefault("SPLUNK_URL", "https://127.0.0.1:8089")
os.environ.setdefault("SPLUNK_USERNAME", "test")
os.environ.setdefault("SPLUNK_PASSWORD", "test")
os.environ.setdefault("SPLUNK_VERIFY_SSL", "false")

from aria.v3.reference_knowledge import LocalReferenceStore


ROOT = Path(__file__).resolve().parents[1]


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 Local Reference Knowledge Test")
    print("======================================")

    path = ROOT / "product" / "knowledge" / "reference_cards.json"
    store = LocalReferenceStore(path)

    atlas = store.match("What is MITRE ATLAS?")
    check(atlas is not None, "exact named framework resolves locally")
    check(atlas.card_ids == ["mitre-atlas"], "exact alias selects the correct card")
    check(
        atlas.primary["canonical_name"] == "MITRE ATLAS",
        "canonical subject is retained",
    )

    rendered = store.render(atlas)
    valid, reason = store.validate_answer(rendered, atlas)
    check(valid, f"deterministic reference rendering validates: {reason}")
    check(
        "Adversarial Threat Landscape for Artificial-Intelligence Systems"
        in rendered,
        "official framework expansion is preserved",
    )
    check(
        "https://atlas.mitre.org/" in rendered,
        "authoritative source URL is preserved",
    )

    followup = store.match(
        "How can a SOC use that framework with Splunk?",
        "assistant: MITRE ATLAS is a living adversarial-AI knowledge base.",
    )
    check(followup is not None, "referential follow-up resolves from same-agent context")
    check(followup.card_ids == ["mitre-atlas"], "follow-up retains the original framework")

    unrelated = store.match("How does risk scoring work?", "")
    check(unrelated is None, "unmatched topics remain model-only")

    wrong = rendered.replace(
        "Adversarial Threat Landscape for Artificial-Intelligence Systems",
        "Adversary Tactics and Learning Actions",
        1,
    )
    valid, reason = store.validate_answer(wrong, atlas)
    check(not valid and "required reference phrase" in reason, "incorrect expansion fails grounding validation")

    no_source = rendered.replace("https://atlas.mitre.org/", "")
    no_source = no_source.replace(
        "https://atlas.mitre.org/pdf-files/SAFEAI_Full_Report.pdf",
        "",
    )
    valid, reason = store.validate_answer(no_source, atlas)
    check(not valid and "source URL" in reason, "uncited grounded answer fails validation")

    print("ARIA_V3_REFERENCE_KNOWLEDGE_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
