from __future__ import annotations

from copy import deepcopy
from typing import Any

from aria.copilot.contracts import CopilotResult, InvestigationPlan
from aria.v3.utils import compact_text, markdown_table


class EvidenceDeliverableAgent:
    """Deterministic post-investigation deliverables.

    This agent never discovers new telemetry and never executes SPL. It consumes
    only the bounded structured result handed off by Investigation, Triage, SPL
    Builder or another deliverable. Missing evidence remains explicit.
    """

    _TITLES = {
        "DETECTION_ENGINEERING": "Detection Candidate Agent",
        "RISK_SCORING": "RBA / ERS Recommendation Agent",
        "TDIR_WORKFLOW": "TDIR Workflow Agent",
        "SOAR_PLAYBOOK": "SOAR Playbook Drafting Agent",
    }

    def create(
        self,
        question: str,
        capability: str,
        *,
        last_result: Any | None = None,
    ) -> CopilotResult:
        context = self._evidence_context(last_result)
        evidence_ids = self._evidence_ids(context)
        if capability == "DETECTION_ENGINEERING":
            body, actions, readiness = self._detection(context, evidence_ids)
        elif capability == "RISK_SCORING":
            body, actions, readiness = self._risk(context, evidence_ids)
        elif capability == "TDIR_WORKFLOW":
            body, actions, readiness = self._tdir(context, evidence_ids)
        else:
            body, actions, readiness = self._soar(context, evidence_ids)

        title = self._TITLES.get(capability, "Evidence Deliverable Agent")
        answer = "\n".join([
            f"## ARIA v3 {title}",
            "",
            f"**Capability:** `{capability}`  ",
            "**Splunk execution:** `NO`  ",
            "**Operational action executed:** `NO`  ",
            f"**Evidence handoff:** `{'AVAILABLE' if context else 'MISSING'}`",
            "",
            body,
            "",
            "## Safety boundary",
            "",
            "- This output is an analyst-review draft.",
            "- No detection, notable, lookup, risk event, containment action or SOAR playbook was created or executed.",
            "- Missing entity, value, telemetry and corroboration cannot be filled by model inference.",
            "- Operationalisation requires the stated human approvals.",
        ])
        return CopilotResult(
            capability=capability,
            goal=question,
            answer=answer,
            plan=InvestigationPlan(
                capability=capability,
                goal=question,
                execute_read_only_search=False,
                requirements=[],
            ),
            context_actions=actions,
            metadata={
                "agent": "EVIDENCE_DELIVERABLE_AGENT_V3",
                "live_splunk_queries": False,
                "splunk_executed": False,
                "operational_action_executed": False,
                "evidence_reused": bool(context),
                "evidence_ids": evidence_ids,
                "readiness": readiness,
                "evidence_context": context,
            },
        )

    @classmethod
    def _evidence_context(cls, last_result: Any | None) -> dict[str, Any]:
        payload = cls._as_dict(last_result)
        if not payload:
            return {}
        metadata = payload.get("metadata") or {}
        inherited = metadata.get("evidence_context")
        if isinstance(inherited, dict) and inherited:
            context = deepcopy(inherited)
        else:
            context = {
                "origin_capability": payload.get("capability"),
                "goal": payload.get("goal"),
                "plan": payload.get("plan"),
                "source_evidence": payload.get("source_evidence") or [],
                "searches": payload.get("searches") or [],
                "finding": payload.get("finding"),
                "confidence": payload.get("confidence"),
                "risk": payload.get("risk"),
                "spl_variants": {
                    "generic": metadata.get("generic_spl"),
                    "deployment": metadata.get("deployment_spl"),
                },
            }
        if payload.get("capability") == "TRIAGE":
            context["triage"] = {
                "verdict": metadata.get("triage_verdict"),
                "confidence": metadata.get("triage_confidence"),
                "supporting_evidence": metadata.get("supporting_evidence") or [],
                "contradicting_evidence": metadata.get("contradicting_evidence") or [],
                "finding": payload.get("finding"),
            }
        return context

    @staticmethod
    def _as_dict(value: Any | None) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "model_dump"):
            dumped = value.model_dump()
            return dumped if isinstance(dumped, dict) else {}
        return {}

    @staticmethod
    def _evidence_ids(context: dict[str, Any]) -> list[str]:
        output: list[str] = []
        for source in context.get("source_evidence") or []:
            evidence_id = str(source.get("evidence_id") or "").strip()
            if evidence_id and evidence_id not in output:
                output.append(evidence_id)
        for search in context.get("searches") or []:
            evidence_id = str(search.get("evidence_id") or "").strip()
            if evidence_id and evidence_id not in output:
                output.append(evidence_id)
        triage = context.get("triage") or {}
        for key in ("supporting_evidence", "contradicting_evidence"):
            for evidence_id in triage.get(key) or []:
                value = str(evidence_id or "").strip()
                if value and value not in output:
                    output.append(value)
        return output

    @staticmethod
    def _confidence(context: dict[str, Any]) -> int:
        triage = context.get("triage") or {}
        value = triage.get("confidence")
        if value is None:
            value = (context.get("confidence") or {}).get("score")
        try:
            return max(0, min(100, int(value or 0)))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _verdict(context: dict[str, Any]) -> str:
        triage = context.get("triage") or {}
        value = triage.get("verdict")
        if value:
            return str(value)
        return str((context.get("finding") or {}).get("verdict") or "UNRESOLVED")

    @staticmethod
    def _gaps(context: dict[str, Any]) -> list[str]:
        output: list[str] = []
        for finding in (
            context.get("finding") or {},
            (context.get("triage") or {}).get("finding") or {},
        ):
            for gap in finding.get("missing_evidence") or []:
                value = str(gap or "").strip()
                if value and value not in output:
                    output.append(value)
        return output

    @staticmethod
    def _goal(context: dict[str, Any]) -> str:
        plan = context.get("plan") or {}
        return compact_text(
            str(plan.get("goal") or context.get("goal") or "Current investigation"),
            420,
        )

    @staticmethod
    def _telemetry_rows(context: dict[str, Any]) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for source in context.get("source_evidence") or []:
            if not source.get("accepted"):
                continue
            fields: list[str] = []
            for binding in source.get("requirement_bindings") or []:
                for field in binding.get("fields") or []:
                    value = str(field or "").strip()
                    if value and value not in fields:
                        fields.append(value)
            rows.append([
                source.get("evidence_id") or "—",
                source.get("index") or "—",
                source.get("sourcetype") or "—",
                ", ".join(fields) or "No populated evidence field recorded",
                f"{float(source.get('score') or 0):.1f}",
            ])
        return rows

    @staticmethod
    def _spl(context: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]]]:
        variants = context.get("spl_variants") or {}
        generic = variants.get("generic") if isinstance(variants.get("generic"), dict) else None
        deployment = variants.get("deployment") if isinstance(variants.get("deployment"), dict) else None
        searches = [
            item
            for item in context.get("searches") or []
            if item.get("safe") and str(item.get("spl") or "").strip()
        ]
        return generic, deployment, searches

    @classmethod
    def _detection(
        cls,
        context: dict[str, Any],
        evidence_ids: list[str],
    ) -> tuple[str, list[str], str]:
        gaps = cls._gaps(context)
        telemetry = cls._telemetry_rows(context)
        generic, deployment, searches = cls._spl(context)
        validated_rows = sum(len(item.get("rows") or []) for item in searches)
        readiness = (
            "EVIDENCE_BOUND_DRAFT"
            if context and evidence_ids
            else "BLOCKED_MISSING_EVIDENCE"
        )
        lines = [
            "## Security hypothesis",
            "",
            cls._goal(context),
            "",
            "## Current evidence",
            "",
            f"- Verdict: `{cls._verdict(context)}`",
            f"- Evidence confidence: `{cls._confidence(context)}/100`",
            f"- Evidence references: {', '.join(f'`{item}`' for item in evidence_ids) or 'None'}",
            f"- Returned result rows represented: `{validated_rows}`",
            "",
            "## Required telemetry",
            "",
        ]
        if telemetry:
            lines.extend([
                markdown_table(
                    ["Evidence", "Index", "Sourcetype", "Observed bound fields", "Score"],
                    telemetry,
                ),
                "",
            ])
        else:
            lines.extend([
                "No accepted source-and-field evidence was carried into this request. "
                "A deployment binding cannot be claimed.",
                "",
            ])

        lines.extend(["## Portable generic SPL", ""])
        if generic and generic.get("spl"):
            lines.extend([
                f"**Status:** `{generic.get('status') or 'PROPOSED'}`",
                "",
                "```spl",
                str(generic.get("spl")),
                "```",
                "",
            ])
        else:
            lines.extend([
                "**Status:** `NOT_AVAILABLE_FROM_CURRENT_EVIDENCE`",
                "",
                "The current Investigation/Triage handoff contains evidence SPL, not a "
                "portable SPL contract. Use the SPL Builder Agent to create the portable "
                "variant without inventing deployment fields.",
                "",
            ])

        lines.extend(["## Deployment-qualified or evidence SPL", ""])
        if deployment and deployment.get("spl"):
            lines.extend([
                f"**Status:** `{deployment.get('status') or 'PROPOSED'}`",
                "",
                "```spl",
                str(deployment.get("spl")),
                "```",
                "",
            ])
        elif searches:
            for search in searches[:2]:
                lines.extend([
                    f"### {search.get('evidence_id') or 'Evidence search'}",
                    "",
                    f"**Status:** `{'RESULT_EVIDENCE_AVAILABLE' if search.get('rows') else 'EXECUTED_NO_ROWS'}`  ",
                    f"**Qualification/execution consistency:** `{'PASS' if search.get('qualification_consistent') is not False else 'FAIL'}`",
                    "",
                    "```spl",
                    str(search.get("spl")),
                    "```",
                    "",
                ])
        else:
            lines.extend([
                "**Status:** `UNAVAILABLE`",
                "",
                "No validator-approved SPL was carried into the current evidence context.",
                "",
            ])

        lines.extend([
            "## Validation state",
            "",
            f"`{readiness}`",
            "",
            "This candidate is not production-ready. Investigation SPL demonstrates the "
            "bounded evidence path; it is not automatically a scheduled detection.",
            "",
            "## False-positive and tuning considerations",
            "",
            "- Establish expected behaviour and administrative or testing context.",
            "- Validate entity attribution and time-window completeness.",
            "- Baseline analyst-supplied thresholds against representative benign periods.",
            "- Test missing-field, duplicate-event and delayed-ingestion behaviour.",
            "",
            "## Evidence gaps",
            "",
            *([f"- {gap}" for gap in gaps] or ["- No structured gap list was carried forward; analyst validation is still required."]),
            "",
            "## Approval requirements",
            "",
            "1. Detection engineer validates SPL semantics and data-model assumptions.",
            "2. Data owner confirms source quality, field population and retention.",
            "3. SOC owner approves thresholds, schedule, suppression and severity.",
            "4. Test results must show expected attack and benign outcomes before activation.",
        ])
        return (
            "\n".join(lines),
            [
                "Build the missing portable SPL with the SPL Builder Agent.",
                "Review the candidate with a detection engineer.",
                "Create an evidence-aware RBA/ERS recommendation.",
                "Draft an approval-gated TDIR workflow.",
            ],
            readiness,
        )

    @classmethod
    def _risk(
        cls,
        context: dict[str, Any],
        evidence_ids: list[str],
    ) -> tuple[str, list[str], str]:
        plan = context.get("plan") or {}
        entities = [
            str(item).strip()
            for item in plan.get("explicit_entities") or []
            if str(item).strip()
        ]
        entity = entities[0] if entities else "UNRESOLVED"
        verdict = cls._verdict(context)
        confidence = cls._confidence(context)
        eligible = bool(
            entity != "UNRESOLVED"
            and evidence_ids
            and verdict in {
                "TRUE_POSITIVE",
                "SUSPICIOUS",
                "LIKELY_TRUE_POSITIVE",
                "SUSPICIOUS_REQUIRES_REVIEW",
            }
        )
        proposed_score = confidence if eligible else None
        readiness = "RECOMMENDATION_READY" if eligible else "NOT_ELIGIBLE"
        gaps = cls._gaps(context)
        rows = [
            ["Evidence confidence", f"{confidence}/100", "Bounded structured confidence carried from the current result."],
            ["Security verdict", verdict, "A definitive risk recommendation requires a supported security interpretation."],
            ["Risk object", entity, "The object must be analyst-supplied or returned as validated entity evidence."],
            ["Evidence references", ", ".join(evidence_ids) or "None", "Risk factors must remain traceable to evidence identifiers."],
        ]
        lines = [
            "## Recommendation",
            "",
            f"- Eligibility: `{readiness}`",
            f"- Proposed risk object: `{entity}`",
            f"- Proposed score: `{proposed_score if proposed_score is not None else 'NOT CALCULATED'}`",
            "- Risk object type: `UNRESOLVED`" if entity == "UNRESOLVED" else "- Risk object type: `ANALYST_VALIDATION_REQUIRED`",
            "",
            "## Proposed risk message",
            "",
            (
                f"Evidence-linked activity for `{entity}` requires SOC review. "
                f"Verdict `{verdict}`, confidence `{confidence}/100`; references "
                f"{', '.join(evidence_ids)}."
                if eligible
                else "A risk message cannot be safely finalised until a validated risk "
                "object and eligible evidence-linked verdict are available."
            ),
            "",
            "## Scoring rationale",
            "",
            markdown_table(["Factor", "Observed value", "Evidence rule"], rows),
            "",
            "## Uncertainty and gaps",
            "",
            *([f"- {gap}" for gap in gaps] or ["- A validated entity/risk object is not present in the current evidence handoff."]),
            "",
            "## Approval gates",
            "",
            "1. Analyst confirms the risk object and object type.",
            "2. Detection owner confirms the evidence-to-risk mapping and score.",
            "3. ES/RBA owner validates aggregation, decay and duplicate-risk behaviour.",
            "4. Change approval is required before any risk-event writeback is enabled.",
        ]
        return (
            "\n".join(lines),
            [
                "Gather the missing entity evidence.",
                "Review the score with the ES/RBA owner.",
                "Draft an approval-gated TDIR workflow.",
            ],
            readiness,
        )

    @classmethod
    def _tdir(
        cls,
        context: dict[str, Any],
        evidence_ids: list[str],
    ) -> tuple[str, list[str], str]:
        readiness = "DRAFT_WITH_EVIDENCE_GAPS" if context else "BLOCKED_MISSING_EVIDENCE"
        gaps = cls._gaps(context)
        lines = [
            "## Trigger and evidence",
            "",
            f"- Investigation goal: {cls._goal(context)}",
            f"- Current verdict: `{cls._verdict(context)}`",
            f"- Confidence: `{cls._confidence(context)}/100`",
            f"- Evidence references: {', '.join(f'`{item}`' for item in evidence_ids) or 'None'}",
            "",
            "## 1. Detect — automated, read-only",
            "",
            "1. Re-run only the validator-approved bounded evidence query when freshness is required.",
            "2. Record query, time range, returned row count and evidence identifiers.",
            "3. Stop if required fields are unpopulated or qualification/execution consistency fails.",
            "",
            "## 2. Investigate — automated enrichment with bounded access",
            "",
            "1. Resolve the affected entity, target and observation window from returned evidence.",
            "2. Correlate only approved identity, endpoint, network and application telemetry.",
            "3. Preserve supporting and contradicting facts separately.",
            "4. Recalculate confidence without treating event volume as maliciousness.",
            "",
            "## 3. Analyst decision points",
            "",
            "1. Confirm the evidence supports the security hypothesis.",
            "2. Confirm entity attribution and expected-business context.",
            "3. Decide whether to close, continue investigation or request response approval.",
            "4. Require incident commander approval for any disruptive action.",
            "",
            "## 4. Respond — approval-gated and unexecuted",
            "",
            "Select an environment-approved response only after the decision criteria pass. "
            "Possible response classes include identity restriction, endpoint isolation, "
            "network blocking or application-control changes; ARIA has executed none of them.",
            "",
            "## 5. Recovery and rollback",
            "",
            "1. Record the pre-action state and named rollback owner.",
            "2. Define reversal steps before approval.",
            "3. Validate service, identity and telemetry health after action or rollback.",
            "4. Reopen the incident if recovery validation fails.",
            "",
            "## Evidence preservation",
            "",
            "- Preserve original timestamps, search text, result rows and evidence IDs.",
            "- Retain analyst decisions, approvals, actions and validation outcomes.",
            "- Protect chain of custody and avoid modifying source evidence.",
            "",
            "## Escalation requirements",
            "",
            "- Escalate when scope, entity attribution or impact is unresolved.",
            "- Escalate before any action outside the approved read-only boundary.",
            "- Escalate immediately if the observed activity affects critical services or evidence integrity.",
            "",
            "## Current evidence gaps",
            "",
            *([f"- {gap}" for gap in gaps] or ["- No structured gap list was carried forward; analyst validation remains mandatory."]),
        ]
        return (
            "\n".join(lines),
            [
                "Assign an incident owner and approval authority.",
                "Gather the missing evidence before response.",
                "Convert this draft into an approved SOAR playbook.",
            ],
            readiness,
        )

    @classmethod
    def _soar(
        cls,
        context: dict[str, Any],
        evidence_ids: list[str],
    ) -> tuple[str, list[str], str]:
        readiness = "DRAFT_ONLY" if context else "BLOCKED_MISSING_EVIDENCE"
        lines = [
            "## Zero-trust playbook draft",
            "",
            f"- Trigger evidence: {', '.join(f'`{item}`' for item in evidence_ids) or 'Not available'}",
            "- Default branch: `STOP_AND_REQUEST_ANALYST_REVIEW`",
            "- Automated permissions: read-only enrichment only",
            "",
            "## Branches",
            "",
            "1. Validate evidence freshness and entity attribution.",
            "2. Stop on missing evidence, inconsistent fields or failed enrichment.",
            "3. Request named analyst approval before a disruptive branch.",
            "4. Record action result, failure handling and rollback validation.",
            "",
            "## Closure",
            "",
            "Close only after evidence, approvals, actions and recovery checks are recorded. "
            "No playbook was created in SOAR or executed.",
        ]
        return (
            "\n".join(lines),
            [
                "Review the playbook with the SOAR owner.",
                "Define approved connectors and rollback actions.",
            ],
            readiness,
        )


__all__ = ["EvidenceDeliverableAgent"]
