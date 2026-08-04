from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable


_FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_TIME_PATTERN = re.compile(r"^[A-Za-z0-9@._+:-]{1,40}$")
_SPAN_PATTERN = re.compile(r"^[1-9][0-9]{0,3}(s|m|h|d|w)$")
_ALIAS_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_time(value: str | None, default: str) -> str:
    text = str(value or "").strip()
    return text if _TIME_PATTERN.fullmatch(text) else default


def safe_span(value: str | None) -> str | None:
    text = str(value or "").strip()
    return text if _SPAN_PATTERN.fullmatch(text) else None


def safe_field(value: str | None) -> str | None:
    text = str(value or "").strip()
    return text if _FIELD_PATTERN.fullmatch(text) else None


def safe_alias(value: str | None, default: str) -> str:
    text = str(value or "").strip()
    if _ALIAS_PATTERN.fullmatch(text):
        return text
    fallback = re.sub(r"[^A-Za-z0-9_]", "_", default).strip("_") or "metric"
    if fallback[0].isdigit():
        fallback = f"m_{fallback}"
    return fallback[:64]


def spl_quote(value: Any) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def spl_field(field: str) -> str:
    validated = safe_field(field)
    if not validated:
        raise ValueError(f"Unsafe field name: {field!r}")
    return f"'{validated}'"


def compact_text(value: Any, limit: int = 500) -> str:
    text = str(value or "").replace("\x00", "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse_samples(raw: Any, limit: int = 5) -> list[str]:
    if raw is None:
        return []
    values: list[Any]
    if isinstance(raw, list):
        values = raw
    else:
        text = str(raw).strip()
        try:
            parsed = json.loads(text)
            values = parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            values = [text]
    output: list[str] = []
    for value in values:
        item = compact_text(value, 180)
        if item and item not in output:
            output.append(item)
        if len(output) >= limit:
            break
    return output


def normalize_row(row: dict[str, Any], max_fields: int = 30, max_chars: int = 300) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in list(row.items())[:max_fields]:
        if isinstance(value, (str, int, float, bool)) or value is None:
            output[str(key)] = compact_text(value, max_chars)
        elif isinstance(value, list):
            output[str(key)] = [compact_text(v, max_chars) for v in value[:10]]
        else:
            output[str(key)] = compact_text(value, max_chars)
    return output


def bounded_rows(rows: Iterable[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    return [normalize_row(row) for row in list(rows)[:limit]]


def clamp_int(value: float | int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(float(value)))))


def ratio(numerator: float | int, denominator: float | int) -> float:
    try:
        den = float(denominator)
        if den <= 0:
            return 0.0
        return max(0.0, min(1.0, float(numerator) / den))
    except Exception:
        return 0.0


def is_numeric(value: str) -> bool:
    try:
        number = float(str(value).strip())
        return math.isfinite(number)
    except Exception:
        return False


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None._"
    head = "| " + " | ".join(headers) + " |"
    sep = "|" + "|".join(["---"] * len(headers)) + "|"
    body = []
    for row in rows:
        body.append("| " + " | ".join(compact_text(value, 220).replace("|", "\\|") for value in row) + " |")
    return "\n".join([head, sep, *body])
