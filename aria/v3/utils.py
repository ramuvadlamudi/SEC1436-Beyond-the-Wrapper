from __future__ import annotations

import re
from typing import Any

from aria.copilot.utils import compact_text, markdown_table, safe_field, safe_time, spl_field, spl_quote


_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*")
_TIME_RE = re.compile(r"\bearliest\s*=\s*([^\s|]+).*?\blatest\s*=\s*([^\s|]+)", re.IGNORECASE | re.DOTALL)

_GENERIC_STOPWORDS = {
    "a", "an", "and", "all", "analyse", "analyze", "analysis", "available",
    "build", "create", "detect", "detection", "discover", "environment", "event",
    "events", "execute", "find", "for", "from", "give", "hunt", "in", "investigate",
    "investigation", "live", "me", "of", "on", "or", "please", "query", "search",
    "spl", "splunk", "the", "this", "time", "to", "using", "validate", "with",
    "across", "data", "telemetry", "activity", "behaviour", "behavior", "specific",
    "logs", "log", "show", "look", "looking", "review", "return", "first", "last",
    "index", "sourcetype", "source", "earliest", "latest", "now", "hour", "hours",
    "day", "days", "week", "weeks", "minute", "minutes", "qualified", "deployment",
    "final", "generated", "portable", "schema", "fields", "field",
    "detecting", "possible", "use", "qualify", "suitable", "observed",
    "selected", "explain", "evidence", "gaps", "assume", "analyst", "supplied",
    "threshold", "thresholds", "refinement", "window", "validation",
}


def normalise(text: str) -> str:
    return " ".join(str(text or "").strip().lower().split())


def tokens(text: str) -> list[str]:
    return [item.lower() for item in _WORD_RE.findall(str(text or ""))]


def salient_terms(text: str, *, limit: int = 8) -> list[str]:
    output: list[str] = []
    for token in tokens(text):
        clean = token.strip(".,;:()[]{}\"'")
        if len(clean) < 3 or clean in _GENERIC_STOPWORDS:
            continue
        if clean not in output:
            output.append(clean)
        if len(output) >= limit:
            break
    return output


def term_variants(term: str) -> list[str]:
    value = str(term or "").strip().lower()
    spaced = re.sub(r"[-_./:]+", " ", value)
    compact = re.sub(r"[-_./:\s]+", "", value)
    return list(dict.fromkeys(item for item in (value, spaced, compact) if len(item) >= 2))


def parse_time_range(text: str) -> tuple[str | None, str | None, bool]:
    raw = str(text or "")
    match = _TIME_RE.search(raw)
    if match:
        return safe_time(match.group(1), "-24h"), safe_time(match.group(2), "now"), True
    lowered = normalise(raw)
    if any(phrase in lowered for phrase in ("all available time", "across all time", "earliest available", "all time")):
        return "0", "now", True
    patterns = [
        (r"\blast\s+(\d+)\s+minutes?\b", "m"),
        (r"\blast\s+(\d+)\s+hours?\b", "h"),
        (r"\blast\s+(\d+)\s+days?\b", "d"),
        (r"\blast\s+(\d+)\s+weeks?\b", "w"),
    ]
    for pattern, suffix in patterns:
        found = re.search(pattern, lowered)
        if found:
            return f"-{found.group(1)}{suffix}", "now", True
    return None, None, False


def extract_explicit_constraints(text: str) -> dict[str, Any]:
    raw = str(text or "")
    index_match = re.search(r"\bindex\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|]+))", raw, re.IGNORECASE)
    st_match = re.search(r"\bsourcetype\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|]+))", raw, re.IGNORECASE)
    earliest, latest, explicit_time = parse_time_range(raw)
    literal = None
    literal_match = re.search(
        r"(?:literal\s+conditions?|use\s+the\s+literal\s+conditions?)\s*:\s*(.+?)(?:\n\s*\n|\n\s*(?:return|use\s+live|do\s+not)|$)",
        raw,
        re.IGNORECASE | re.DOTALL,
    )
    if literal_match:
        literal = " ".join(literal_match.group(1).strip().split())
    limit = 100
    head_match = re.search(r"\b(?:first|head|limit(?:ed)?\s+to)\s+(\d+)\b", raw, re.IGNORECASE)
    if head_match:
        limit = max(1, min(int(head_match.group(1)), 500))
    return {
        "index": next((g for g in index_match.groups() if g), None) if index_match else None,
        "sourcetype": next((g for g in st_match.groups() if g), None) if st_match else None,
        "earliest": earliest,
        "latest": latest,
        "time_explicit": explicit_time,
        "literal_condition": literal,
        "limit": limit,
    }


def quote_like(value: str) -> str:
    escaped = str(value).lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return spl_quote(f"%{escaped}%")


__all__ = [
    "compact_text", "markdown_table", "safe_field", "safe_time", "spl_field", "spl_quote",
    "normalise", "tokens", "salient_terms", "term_variants", "parse_time_range",
    "extract_explicit_constraints", "quote_like",
]
