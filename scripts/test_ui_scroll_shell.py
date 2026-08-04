from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB_UI = ROOT / "web_ui.py"


def require(label: str, condition: bool) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    text = WEB_UI.read_text(encoding="utf-8")

    print("ARIA Fixed Conversation Scroll Shell Test")
    print("=========================================")

    require("viewport height is synchronized", "function syncViewportHeight()" in text)
    require("dynamic visual viewport is supported", "window.visualViewport" in text)
    require("application shell clips outer overflow", ".app {" in text and "overflow: hidden;" in text)
    require("center grid has bounded rows", ".center-panel {" in text and "grid-template-rows: auto minmax(0, 1fr) auto;" in text)
    require("conversation pane owns vertical scrolling", ".messages {" in text and "overflow-y: auto;" in text)
    require("conversation pane supports Safari momentum scrolling", "-webkit-overflow-scrolling: touch" in text)
    require("conversation preserves reading position", "const previousTop = container.scrollTop" in text and "container.scrollTop = Math.min(previousTop, maximum)" in text)
    require("automatic follow-to-latest is available", "followLatest: true" in text and "renderChat(state.followLatest)" in text)
    require("top navigation remains in fixed grid row", "<header class=\"topbar\">" in text)
    require("composer remains in fixed bottom grid row", "<footer class=\"composer\">" in text)
    require("left menu control is always available", 'id="toggle-left"' in text and "function toggleLeft()" in text)
    require("right workspace control is always available", 'id="toggle-right"' in text and "function toggleRight()" in text)
    require("desktop panes collapse independently", "left-collapsed" in text and "right-collapsed" in text)
    require("outer document scrolling remains disabled", re.search(r"body\s*\{[^}]*overflow:\s*hidden", text, re.S) is not None)

    print("ARIA_UI_SCROLL_SHELL_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
