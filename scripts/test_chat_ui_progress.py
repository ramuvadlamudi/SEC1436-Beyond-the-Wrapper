from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(text: str, needle: str, label: str, failures: list[str]) -> None:
    if needle in text:
        print(f"PASS   {label}")
    else:
        print(f"FAIL   {label}")
        failures.append(label)


def main() -> int:
    print("ARIA Conversational UI and Progress Test")
    print("========================================")
    failures: list[str] = []

    web = (ROOT / "web_ui.py").read_text(encoding="utf-8")
    engine = (ROOT / "aria" / "copilot" / "engine.py").read_text(encoding="utf-8")
    v3 = (ROOT / "aria" / "v3" / "orchestrator.py").read_text(encoding="utf-8")
    builder = (ROOT / "aria" / "v3" / "spl_builder_agent.py").read_text(encoding="utf-8")
    triage = (ROOT / "aria" / "v3" / "triage_agent.py").read_text(encoding="utf-8")
    investigation = (ROOT / "aria" / "copilot" / "legacy_engine.py").read_text(encoding="utf-8")
    orchestrator = (ROOT / "aria" / "conversation_orchestrator.py").read_text(encoding="utf-8")

    require(web, 'path == "/api/chat/start"', "asynchronous chat start endpoint", failures)
    require(web, 'path.startswith("/api/jobs/")', "job polling endpoint", failures)
    require(web, 'status="thinking"', "persisted thinking message", failures)
    require(web, 'ARIA is working', "visible working state", failures)
    require(web, 'route="ARIA_V3_ROUTER"', "UI reports deterministic v3 routing", failures)
    require(web, 'deterministic control plane', "UI explains deterministic control plane", failures)
    require(web, 'id="active-job-bar"', "persistent active-job status", failures)
    require(web, 'id="workspace-evidence"', "on-demand evidence workspace", failures)
    require(web, 'function nearBottom()', "scroll position preservation", failures)
    require(web, 'followLatest: true', "automatic latest-message follow mode", failures)
    require(web, 'jump-latest', "jump-to-latest control", failures)
    require(web, 'const state = {', "single conversational client state", failures)
    require(engine, 'progress: ProgressCallback | None = None', "engine progress callback", failures)
    require(builder, '"v3_build_catalog"', "deployment-catalog progress stage", failures)
    require(builder, '"v3_build_profile"', "source-profiling progress stage", failures)
    require(investigation, '"spl_execution"', "live Splunk execution progress stage", failures)
    require(investigation, '"evidence_reasoning"', "bounded evidence reasoning progress stage", failures)
    require(triage, '"v3_triage_locator"', "triage evidence-location progress stage", failures)
    require(v3, '"v3_route"', "v3 agent-routing progress stage", failures)
    require(orchestrator, 'progress: Callable[[str, str, str], None] | None = None', "orchestrator progress propagation", failures)

    if failures:
        print(f"\nARIA_CHAT_UI_PROGRESS_TEST=FAIL failures={len(failures)}")
        return 1
    print("\nARIA_CHAT_UI_PROGRESS_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
