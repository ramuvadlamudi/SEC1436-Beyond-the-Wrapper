from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from aria.copilot.contracts import (
    CatalogCandidateChoice,
    CatalogCandidateSelection,
    InvestigationPlan,
)


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "could",
    "data",
    "do",
    "evidence",
    "find",
    "for",
    "from",
    "how",
    "i",
    "in",
    "into",
    "is",
    "it",
    "live",
    "my",
    "of",
    "on",
    "or",
    "please",
    "show",
    "splunk",
    "that",
    "the",
    "this",
    "to",
    "using",
    "what",
    "with",
}


def _tokens(value: Any) -> list[str]:
    text = str(value or "").lower()
    return [
        token
        for token in _TOKEN_RE.findall(text)
        if len(token) >= 3 and token not in _STOP_WORDS
    ]


def _query_terms(question: str, plan: InvestigationPlan) -> list[str]:
    parts: list[str] = [question, plan.goal]
    parts.extend(item.concept for item in plan.requirements)
    parts.extend(item.statement for item in plan.hypotheses)
    return _tokens(" ".join(parts))


def _candidate_terms(row: dict[str, Any]) -> list[str]:
    return _tokens(
        " ".join(
            [
                str(row.get("index") or ""),
                str(row.get("sourcetype") or ""),
                str(row.get("source") or ""),
                str(row.get("catalog_scope") or ""),
            ]
        )
    )


def _score_row(query_counter: Counter[str], row: dict[str, Any]) -> tuple[float, list[str]]:
    candidate_counter = Counter(_candidate_terms(row))
    if not candidate_counter:
        return 0.0, []

    overlap = sorted(set(query_counter) & set(candidate_counter))
    exact = sum(min(query_counter[token], candidate_counter[token]) for token in overlap)

    fuzzy_hits: list[str] = []
    for query_token in query_counter:
        if query_token in candidate_counter:
            continue
        for candidate_token in candidate_counter:
            if len(query_token) >= 4 and len(candidate_token) >= 4:
                if query_token in candidate_token or candidate_token in query_token:
                    fuzzy_hits.append(f"{query_token}~{candidate_token}")
                    break

    query_norm = math.sqrt(sum(value * value for value in query_counter.values())) or 1.0
    candidate_norm = math.sqrt(sum(value * value for value in candidate_counter.values())) or 1.0
    lexical_similarity = exact / (query_norm * candidate_norm)

    # Retrieval invariant: an exact live-catalog token match must always outrank
    # a substring-only fuzzy hit. The previous cosine-heavy score allowed a term
    # such as ``query`` to rank ``osquery`` above an exact ``dns`` label when the
    # analyst prompt contained many repeated tokens. Exact precedence is generic
    # lexical retrieval behaviour; it does not assign security meaning or accept
    # the source as evidence.
    exact_distinct = len(overlap)
    fuzzy_distinct = len(set(fuzzy_hits))

    event_count = 0
    try:
        event_count = max(0, int(float(row.get("event_count") or 0)))
    except (TypeError, ValueError):
        event_count = 0

    # Event count is a tie-breaker only. It can never outweigh semantic overlap.
    volume_tiebreaker = min(1.0, math.log10(event_count + 1) / 10.0)
    score = (
        exact_distinct * 1000.0
        + exact * 100.0
        + lexical_similarity * 10.0
        + fuzzy_distinct * 5.0
        + volume_tiebreaker
    )

    reasons = [*overlap, *fuzzy_hits]
    return score, reasons


def deterministic_catalog_selection(
    *,
    question: str,
    plan: InvestigationPlan,
    catalog_rows: list[dict[str, Any]],
    limit: int,
    positive_only: bool = False,
) -> CatalogCandidateSelection:
    """Generic semantic fallback for live catalog recall.

    The function never assigns security meaning to a source. It only compares the
    analyst's language and evidence concepts with live catalog labels. Live fields,
    values, co-occurrence and search results remain mandatory before acceptance.
    """

    safe_limit = max(0, int(limit))
    if safe_limit <= 0 or not catalog_rows:
        return CatalogCandidateSelection(candidates=[])

    query_counter = Counter(_query_terms(question, plan))
    ranked: list[tuple[float, int, dict[str, Any], list[str]]] = []

    for position, row in enumerate(catalog_rows):
        score, reasons = _score_row(query_counter, row)
        ranked.append((score, -position, row, reasons))

    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)

    positive = [item for item in ranked if item[0] > 1.0]
    chosen = positive[:safe_limit]

    # Callers can request only direct/fuzzy label matches when they need to ensure
    # that a saturated model shortlist cannot crowd out an obvious live-catalog
    # match. This remains retrieval recall, never source acceptance.
    if positive_only:
        chosen = positive[:safe_limit]
    elif not chosen:
        # When labels do not overlap with the analyst language, retain a small
        # diverse recall set rather than returning no candidates. This is recall
        # only and does not accept the source as evidence.
        chosen = ranked[:safe_limit]

    output: list[CatalogCandidateChoice] = []
    for score, _position, row, reasons in chosen:
        candidate_id = str(row.get("candidate_id") or "").strip()
        if not candidate_id:
            continue
        reason_text = ", ".join(reasons[:6]) if reasons else "no direct label overlap"
        output.append(
            CatalogCandidateChoice(
                candidate_id=candidate_id,
                rationale=(
                    "Deterministic live-catalog recall fallback; "
                    f"generic label similarity={score:.2f}; matches={reason_text}. "
                    "This is not evidence of behaviour and requires live profiling."
                ),
            )
        )

    return CatalogCandidateSelection(candidates=output)


def merge_candidate_selections(
    *,
    primary: CatalogCandidateSelection,
    fallback: CatalogCandidateSelection,
    allowed_ids: set[str],
    limit: int,
) -> CatalogCandidateSelection:
    output: list[CatalogCandidateChoice] = []
    seen: set[str] = set()

    for selection in (primary, fallback):
        for item in selection.candidates:
            candidate_id = str(item.candidate_id or "").strip()
            if not candidate_id or candidate_id not in allowed_ids or candidate_id in seen:
                continue
            seen.add(candidate_id)
            output.append(item)
            if len(output) >= max(0, int(limit)):
                return CatalogCandidateSelection(candidates=output)

    return CatalogCandidateSelection(candidates=output)
