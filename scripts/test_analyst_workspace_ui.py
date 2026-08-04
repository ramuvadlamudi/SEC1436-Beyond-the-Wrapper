from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "web_ui.py"


def main() -> int:
    print("ARIA Analyst Workspace UI Test")
    print("==============================")

    text = SOURCE.read_text(encoding="utf-8")
    checks = [
        ("three-pane analyst workspace", "grid-template-columns: var(--left-width) minmax(0, 1fr) var(--right-width)" in text),
        ("left investigations pane", 'id="left-panel"' in text and 'id="chat-list"' in text),
        ("right analyst workspace", 'id="right-panel"' in text and 'data-workspace-tab="overview"' in text),
        ("evidence workspace tab", 'data-workspace-tab="evidence"' in text),
        ("analyst actions workspace tab", 'data-workspace-tab="actions"' in text),
        ("per-investigation options menu", 'class="chat-menu-button"' in text and 'data-chat-action="delete"' in text),
        ("rename investigation API", 'def rename_chat(' in text and '/rename"' in text),
        ("pin investigation API", 'def set_chat_pinned(' in text and '/pin"' in text),
        ("delete confirmation modal", 'id="modal-backdrop"' in text and 'Delete investigation?' in text),
        ("persistent active-job bar", 'id="active-job-bar"' in text and 'id="view-progress"' in text),
        ("automatic latest-message follow mode", 'followLatest: true' in text and 'renderChat(state.followLatest)' in text),
        ("independent conversation scrolling", '.messages {' in text and 'overflow-y: auto;' in text),
        ("fixed application shell", 'overflow: hidden;' in text and 'grid-template-rows: auto minmax(0, 1fr) auto;' in text),
        ("investigation search", 'id="chat-search"' in text),
        ("legacy global clear/delete controls removed", 'id="clear-chat"' not in text and 'id="delete-chat"' not in text),
    ]

    failures = 0
    for name, passed in checks:
        if passed:
            print(f"PASS   {name}")
        else:
            print(f"FAIL   {name}")
            failures += 1

    if failures:
        print(f"\nARIA_ANALYST_WORKSPACE_UI_TEST=FAIL failures={failures}")
        return 1
    print("\nARIA_ANALYST_WORKSPACE_UI_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
