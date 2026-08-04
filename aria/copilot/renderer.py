from __future__ import annotations

from typing import Any

from aria.copilot.contracts import CopilotResult
from aria.copilot.utils import compact_text, markdown_table


class CopilotResponseRenderer:
    def render(self, result: CopilotResult, deliverable: str = "") -> str:
        plan = result.plan
        finding = result.finding
        confidence = result.confidence
        risk = result.risk

        lines: list[str] = ["## ARIA Evidence-First SOC Copilot", ""]
        lines.extend(
            [
                f"**Capability:** `{result.capability}`  ",
                f"**Execution:** `LIVE_SPLUNK_READ_ONLY`  ",
                f"**Goal:** {result.goal}",
                "",
            ]
        )

        if finding:
            lines.extend(
                [
                    "## Finding",
                    "",
                    f"**Verdict:** `{finding.verdict}`  ",
                    f"**Evidence confidence:** `{confidence.score if confidence else 0}/100`",
                    "",
                    finding.summary,
                    "",
                ]
            )

        if plan:
            hypothesis_rows = [
                [item.hypothesis_id, item.statement, ", ".join(item.supporting_requirement_ids)]
                for item in plan.hypotheses
            ]
            lines.extend(["## Investigation Plan", ""])
            if hypothesis_rows:
                lines.extend(
                    [
                        markdown_table(["Hypothesis", "Statement", "Required evidence"], hypothesis_rows),
                        "",
                    ]
                )
            requirement_rows = [
                [
                    item.requirement_id,
                    item.role,
                    "Yes" if item.required else "No",
                    item.concept,
                ]
                for item in plan.requirements
            ]
            if requirement_rows:
                lines.extend(
                    [
                        markdown_table(["ID", "Role", "Required", "Evidence concept"], requirement_rows),
                        "",
                    ]
                )

        if result.metadata.get("all_time_recovery_attempted"):
            lines.extend(
                [
                    "## Evidence Acquisition Trace",
                    "",
                    "- Recent scoped telemetry did not satisfy evidence policy.",
                    f"- All-time live catalog rows evaluated: `{result.metadata.get('all_time_catalog_count', 0)}`",
                    f"- Historical candidates profiled: `{result.metadata.get('all_time_candidate_count', 0)}`",
                    f"- Raw-event or field-access gaps identified: `{result.metadata.get('profile_access_gap_count', 0)}`",
                    "",
                ]
            )

        lines.extend(["## Live Source Qualification", ""])
        source_rows: list[list[Any]] = []
        for source in result.source_evidence:
            access_gap = str(source.profile_error or "").startswith((
                "CATALOG_VISIBLE",
                "RAW_EVENTS_VISIBLE",
            ))
            decision = "ACCEPTED" if source.accepted else ("ACCESS_GAP" if access_gap else "REJECTED")
            source_rows.append(
                [
                    source.evidence_id,
                    source.index,
                    source.sourcetype,
                    decision,
                    f"{source.score:.1f}",
                    f"{source.fully_bound_events}/{source.sampled_events}",
                ]
            )
        lines.extend(
            [
                markdown_table(
                    ["Evidence", "Index", "Sourcetype", "Decision", "Score", "Required fields co-occur"],
                    source_rows,
                ),
                "",
            ]
        )

        binding_rows: list[list[Any]] = []
        for source in result.source_evidence:
            for binding in source.requirement_bindings:
                if not binding.fields and binding.status == "UNSUPPORTED":
                    continue
                binding_rows.append(
                    [
                        source.evidence_id,
                        binding.requirement_id,
                        binding.concept,
                        binding.status,
                        ", ".join(binding.fields) or "—",
                        compact_text(binding.rationale, 180),
                    ]
                )
        if binding_rows:
            lines.extend(
                [
                    "### Observed Field Bindings",
                    "",
                    markdown_table(
                        ["Source", "Requirement", "Concept", "Status", "Observed field(s)", "Binding basis"],
                        binding_rows,
                    ),
                    "",
                ]
            )

        rejected = [source for source in result.source_evidence if not source.accepted]
        if rejected:
            lines.extend(["### Why sources were rejected", ""])
            for source in rejected:
                reasons = "; ".join(source.rejection_reasons) or "Evidence qualification policy was not met."
                lines.append(f"- **{source.evidence_id} — `{source.index}` / `{source.sourcetype}`:** {reasons}")
            lines.append("")

        if result.searches:
            lines.extend(["## SPL Executed", ""])
            for search in result.searches:
                lines.extend(
                    [
                        f"### {search.evidence_id} — {compact_text(search.purpose, 160)}",
                        "",
                        "```spl",
                        search.spl or "No SPL was compiled.",
                        "```",
                        "",
                        f"- Safety gate: `{'PASS' if search.safe else 'BLOCKED'}`",
                        f"- Rows returned: `{len(search.rows)}`",
                    ]
                )
                if search.observed_event_count is not None:
                    lines.append(
                        f"- Bounded events represented: `{search.observed_event_count}`"
                    )
                if search.required_field_presence:
                    presence = ", ".join(
                        f"`{field}`={count}"
                        for field, count in search.required_field_presence.items()
                    )
                    lines.append(
                        f"- Required execution field presence: {presence}"
                    )
                if search.fully_bound_event_count is not None:
                    lines.append(
                        "- Fully-bound execution events: "
                        f"`{search.fully_bound_event_count}`"
                    )
                if search.qualification_consistent is not None:
                    lines.append(
                        "- Qualification/execution consistency: "
                        f"`{'PASS' if search.qualification_consistent else 'FAIL'}`"
                    )
                if search.execution_error:
                    lines.append(f"- Execution error: `{compact_text(search.execution_error, 400)}`")
                if search.validation_errors:
                    lines.append(f"- Validation errors: {', '.join(search.validation_errors)}")
                if search.rows:
                    headers = list(search.rows[0].keys())[:8]
                    rows = [[row.get(header, "") for header in headers] for row in search.rows[:10]]
                    lines.extend(["", markdown_table(headers, rows)])
                lines.append("")

        if finding:
            lines.extend(["## Evidence Logic", ""])
            if finding.supporting_claims:
                lines.append("### Supporting evidence")
                lines.append("")
                for claim in finding.supporting_claims:
                    lines.append(f"- {claim.claim} **[{', '.join(claim.evidence_refs)}]**")
                lines.append("")
            if finding.contradicting_claims:
                lines.append("### Contradicting evidence")
                lines.append("")
                for claim in finding.contradicting_claims:
                    lines.append(f"- {claim.claim} **[{', '.join(claim.evidence_refs)}]**")
                lines.append("")
            if finding.missing_evidence:
                lines.append("### Missing evidence")
                lines.append("")
                for item in finding.missing_evidence:
                    lines.append(f"- {item}")
                lines.append("")

        if confidence:
            lines.extend(["## Confidence Calculation", ""])
            factor_rows = [[factor.factor, f"{factor.points:+d}", factor.reason] for factor in confidence.factors]
            lines.extend(
                [
                    markdown_table(["Factor", "Points", "Evidence basis"], factor_rows),
                    "",
                    f"**Final evidence confidence: {confidence.score}/100**",
                    "",
                ]
            )

        if risk:
            lines.extend(["## RBA / ERS Recommendation", ""])
            lines.extend(
                [
                    f"- Eligible: `{'YES' if risk.eligible else 'NO'}`",
                    f"- Proposed score: `{risk.proposed_score}/100`",
                    f"- Writeback performed: `NO`",
                    f"- Rationale: {risk.rationale}",
                    "",
                ]
            )
            if risk.factors:
                lines.extend(
                    [
                        markdown_table(
                            ["Risk factor", "Points", "Evidence basis"],
                            [[item.factor, f"{item.points:+d}", item.reason] for item in risk.factors],
                        ),
                        "",
                    ]
                )

        if deliverable.strip():
            lines.extend(["## Requested Agentic Deliverable", "", deliverable.strip(), ""])

        if finding:
            lines.extend(
                [
                    "## Next Best Action",
                    "",
                    finding.next_best_query_goal,
                    "",
                ]
            )
            if finding.analyst_guidance:
                for item in finding.analyst_guidance:
                    lines.append(f"- {item}")
                lines.append("")

        lines.extend(
            [
                "## Safety Boundary",
                "",
                "- Splunk access was read-only.",
                "- No detection, notable, risk event or SOAR action was created or executed.",
                "- Indexes, sourcetypes, fields and values came from live Splunk discovery, analyst input or validated observations.",
                "- Unsupported evidence produced abstention or explicit gaps rather than invented logic.",
                "- Analyst approval is required before operationalisation.",
            ]
        )
        return "\n".join(lines).strip() + "\n"
