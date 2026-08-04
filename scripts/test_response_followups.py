from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, label: str, failures: list[str]) -> None:
    if condition:
        print(f"PASS   {label}")
    else:
        print(f"FAIL   {label}")
        failures.append(label)


def main() -> int:
    print("ARIA In-Conversation Follow-Up Prompt Test")
    print("==========================================")
    failures: list[str] = []

    web = (ROOT / "web_ui.py").read_text(encoding="utf-8")
    orchestrator = (ROOT / "aria" / "v3" / "orchestrator.py").read_text(encoding="utf-8")
    router = (ROOT / "aria" / "v3" / "router.py").read_text(encoding="utf-8")

    require('"followups": list(followups or [])' in web, "follow-ups persisted per message", failures)
    require('"followups": list(decision.context_actions or [])' in web, "completed response stores aligned follow-ups", failures)
    require('class="followup-chip"' in web, "follow-up prompt chips rendered in conversation", failures)
    require('data-followup' in web and 'document.getElementById("prompt")' in web, "follow-up chip populates composer", failures)
    require("prepared aligned follow-up prompts" in web, "follow-up completion visible in progress", failures)
    require("context_actions=[" in orchestrator, "agent outcome supplies aligned follow-ups", failures)
    require("DETERMINISTIC_ROUTING" in web and "ARIA_V3_ROUTER" in web, "queued UI identifies deterministic routing", failures)
    require("Understanding your request" in web, "queued UI describes routing rather than forced evidence", failures)

    if failures:
        print(f"\nARIA_RESPONSE_FOLLOWUPS_TEST=FAIL failures={len(failures)}")
        return 1
    print("\nARIA_RESPONSE_FOLLOWUPS_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
