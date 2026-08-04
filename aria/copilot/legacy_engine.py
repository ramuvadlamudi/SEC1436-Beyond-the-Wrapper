from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from aria.audit_logger import audit_logger
from aria.copilot.contracts import (
    ConfidenceAssessment,
    CopilotResult,
    FindingSynthesis,
    IntentRoute,
    InvestigationPlan,
    SearchExecutionRecord,
    SourceEvidenceRecord,
    SourceProfileRecord,
)
from aria.copilot.build_spl_workbench import BuildSPLWorkbench
from aria.copilot.deliverables import EvidenceBoundDeliverableAgent
from aria.copilot.evidence_qualifier import DeterministicEvidenceQualifier
from aria.copilot.followups import ResponseFollowUpAgent
from aria.copilot.intent_router import LLMIntentRouter
from aria.copilot.planner import CopilotPlanner
from aria.copilot.policy import evidence_policy
from aria.copilot.reasoning import EvidenceReasoningAgent
from aria.copilot.renderer import CopilotResponseRenderer
from aria.copilot.risk_agent import EvidenceAwareRiskAgent
from aria.copilot.semantic_binder import SemanticFieldBinder
from aria.copilot.spl_agent import EvidenceBoundSPLAgent
from aria.copilot.spl_builder import DeterministicSPLBuilder
from aria.copilot.telemetry_agent import LiveTelemetryAgent
from aria.copilot.utils import compact_text, markdown_table
from aria.ollama_client import OllamaClient, ollama_client
from aria.spl_validator import spl_validator
from aria.splunk_client import SplunkClient, splunk_client
from aria.suppressed_exception_logger import log_suppressed_exception


ProgressCallback = Callable[[str, str, str], None]


class EvidenceFirstCopilotEngine:
    """One authoritative request path for ARIA Pattern B."""

    def __init__(
        self,
        *,
        ollama: OllamaClient | None = None,
        splunk: SplunkClient | None = None,
    ) -> None:
        self.ollama = ollama or ollama_client
        self.splunk = splunk or splunk_client
        self.policy = evidence_policy()
        self.intent_router = LLMIntentRouter(self.ollama)
        self.planner = CopilotPlanner(self.ollama)
        self.followups = ResponseFollowUpAgent(self.ollama)
        self.telemetry = LiveTelemetryAgent(self.splunk)
        self.semantic_binder = SemanticFieldBinder(self.ollama)
        self.qualifier = DeterministicEvidenceQualifier(self.telemetry)
        self.spl_agent = EvidenceBoundSPLAgent(self.ollama, self.splunk, spl_validator)
        self.spl_builder = DeterministicSPLBuilder(spl_validator, self.ollama)
        self.build_spl_workbench = BuildSPLWorkbench(
            ollama=self.ollama,
            telemetry=self.telemetry,
            binder=self.semantic_binder,
            qualifier=self.qualifier,
            spl_agent=self.spl_agent,
            spl_builder=self.spl_builder,
        )
        self.reasoning = EvidenceReasoningAgent(self.ollama)
        self.risk_agent = EvidenceAwareRiskAgent()
        self.deliverables = EvidenceBoundDeliverableAgent(self.ollama)
        self.renderer = CopilotResponseRenderer()

    def invoke(
        self,
        question: str,
        *,
        history: list[Any] | None = None,
        last_result: Any | None = None,
        progress: ProgressCallback | None = None,
    ) -> CopilotResult:
        started = time.monotonic()
        runtime_budget = max(60, int(self.policy.get("runtime_budget_seconds", 300)))
        deadline = started + runtime_budget
        question = str(question or "").strip()
        history = history or []
        contextual_followup = self.intent_router.is_contextual_followup(question)
        routed_history = history if contextual_followup else []
        routed_result = last_result if contextual_followup else None
        if not question:
            raise ValueError("Analyst question is empty.")

        try:
            self._emit(
                progress,
                "intent_routing",
                "Understanding your request",
                "ARIA is resolving the request through its reliable control plane; local models are advisory and cannot block unambiguous product actions.",
            )
            route = self.intent_router.route(
                question,
                history=routed_history,
                last_result=routed_result,
            )
            self._emit(
                progress,
                "intent_ready",
                "Intent understood",
                f"Capability {route.capability}; mode {route.mode}; live Splunk {'required' if route.requires_live_splunk else 'not required'}.",
            )

            self._emit(
                progress,
                "planning",
                "Creating the response plan",
                "ARIA is creating a scenario-agnostic plan from the routed capability, analyst language and generic observable roles.",
            )
            plan = self.planner.plan(
                question,
                history=routed_history,
                last_result=routed_result,
                route=route,
            )
            # INVESTIGATE_ENTITY is valid only when the planner extracted an
            # analyst-supplied entity or value. Generic behaviour searches remain
            # QUERY_SPLUNK even when the first model over-specialises the route.
            if (
                route.capability == "INVESTIGATE_ENTITY"
                and not plan.explicit_entities
                and not plan.explicit_values
            ):
                route.capability = "QUERY_SPLUNK"
                route.mode = "LIVE_EVIDENCE"
                route.requires_live_splunk = True
                route.requires_evidence_plan = True
                route.routing_summary = (
                    "No explicit entity or value was supplied, so ARIA corrected "
                    "the live request to the generic evidence-query capability."
                )
                plan.capability = "QUERY_SPLUNK"

            self._emit(
                progress,
                "plan_ready",
                "Response plan ready",
                f"Capability {plan.capability}; {len(plan.requirements)} evidence requirement(s); time range {plan.earliest} to {plan.latest}.",
            )

            if route.clarification_needed:
                result = self._clarification_response(question, plan, route)
            elif route.capability == "SCOPE_GUARD" or route.mode == "DOMAIN_REDIRECT":
                self._emit(progress, "scope", "Applying the SecOps scope boundary", "ARIA is redirecting an unrelated general-purpose request to supported SecOps capabilities without querying Splunk.")
                result = self._scope_guard_response(question, plan, route)
            elif route.unsafe_action_requested or plan.unsafe_action_requested:
                self._emit(progress, "safety", "Applying safety boundary", "The request is being redirected to a defender-safe workflow.")
                result = self._unsafe_redirect(question, plan)
            elif route.capability == "IDENTITY":
                self._emit(progress, "conversation", "Preparing an introduction", "The local model is tailoring ARIA's identity and capabilities to the analyst's question.")
                result = self._identity_response(question, plan, route, routed_history)
            elif route.capability == "SAFETY":
                self._emit(progress, "conversation", "Explaining product boundaries", "The local model is explaining ARIA's read-only and approval-gated safety model.")
                result = self._safety_response(question, plan, route)
            elif route.capability == "INVENTORY":
                self._emit(progress, "catalog", "Querying the live Splunk catalog", "ARIA is retrieving visible index and sourcetype combinations using read-only SPL.")
                result = self._inventory(question, plan)
            elif route.capability == "EXPLAIN_SPL":
                self._emit(progress, "spl_review", "Reviewing SPL", "The safety validator and local reasoning model are analysing the supplied pipeline.")
                result = self._explain_spl(question, plan)
            elif route.capability == "BUILD_SPL":
                self._emit(progress, "spl_build", "Designing generic SPL", "ARIA is creating a constrained generic SPL draft from the analyst intent before any environment-specific qualification.")
                result = self._build_spl(
                    question,
                    plan,
                    history=routed_history,
                    progress=progress,
                )
            elif route.capability == "SOC_CONVERSATION":
                self._emit(progress, "reasoning", "Preparing a conversational answer", "The local reasoning model is answering without claiming that Splunk was queried.")
                result = self._soc_conversation(question, plan, route=route, history=routed_history, last_result=routed_result)
            elif route.generic_template_only or plan.generic_template_only:
                self._emit(progress, "drafting", "Drafting a generic template", "The analyst explicitly requested a template without a live Splunk query.")
                result = self._generic_template(question, plan)
            else:
                result = self._run_evidence_workflow(
                    question,
                    plan,
                    progress=progress,
                    deadline=deadline,
                )

            self._emit(progress, "followups", "Preparing useful follow-ups", "ARIA is aligning next prompts to the completed response and any remaining evidence gaps.")
            result.context_actions = self._aligned_followups(
                question=question,
                route=route,
                result=result,
            )
            result.metadata["intent_route"] = route.model_dump()
            result.metadata["intent_model_role"] = "fast"
            result.metadata["duration_seconds"] = round(time.monotonic() - started, 2)
            result.metadata["engine"] = "ARIA_RELIABLE_EVIDENCE_COPILOT_V2_3_5"
            result.metadata["runtime_budget_seconds"] = runtime_budget
            result.metadata["conversation_context_mode"] = (
                "FOLLOW_UP" if contextual_followup else "STANDALONE"
            )

            self._emit(progress, "rendering", "Preparing the analyst response", "ARIA is finalising the answer and follow-up prompts for the conversation.")
            self._audit(question, result, started)
            self._emit(progress, "complete", "Response ready", "The routed response is ready for analyst review.")
            return result
        except Exception as exc:
            self._emit(progress, "error", "Request stopped", f"{exc.__class__.__name__}: {compact_text(exc, 300)}")
            result = CopilotResult(
                capability="COPILOT_ERROR",
                goal=question,
                answer=(
                    "## ARIA request stopped\n\n"
                    "ARIA could not complete the local intent and response workflow. It did not default the request to a Splunk search, fabricate an answer or execute a write action.\n\n"
                    f"**Error:** `{compact_text(exc, 800)}`\n\n"
                    "The request stopped at a bounded product stage. Review the error and service health before retrying; ARIA did not fabricate evidence or execute a write action."
                ),
                context_actions=["Check local model health", "Retry this request", "Start a new investigation"],
                metadata={
                    "error_type": exc.__class__.__name__,
                    "duration_seconds": round(time.monotonic() - started, 2),
                },
            )
            self._audit(question, result, started, status="error")
            return result

    def _run_evidence_workflow(
        self,
        question: str,
        plan: InvestigationPlan,
        *,
        progress: ProgressCallback | None = None,
        deadline: float | None = None,
    ) -> CopilotResult:
        def budget_remaining() -> float:
            if deadline is None:
                return float("inf")
            return max(0.0, deadline - time.monotonic())

        candidate_limit = max(1, int(self.policy.get("candidate_limit", 2)))
        recovery_candidate_limit = max(1, int(self.policy.get("recovery_candidate_limit", 1)))
        max_total_candidates = max(
            candidate_limit,
            int(self.policy.get("max_total_candidates_profiled", 4)),
        )
        historical_candidate_limit = min(
            max_total_candidates,
            max(candidate_limit, int(self.policy.get("historical_candidate_limit", candidate_limit))),
        )
        accepted_limit = max(1, int(self.policy.get("accepted_source_limit", 1)))
        fallback_used = False
        live_catalog: list[dict[str, Any]] = []
        explicit_mode = False
        all_time_recovery_attempted = False
        all_time_catalog_count = 0
        all_time_candidate_count = 0
        budget_exhausted = False

        self._emit(progress, "locating", "Locating explicit entities and values", "ARIA is checking whether analyst-supplied values identify relevant live source groups.")
        explicit_candidates, effective_earliest, fallback_used = self.telemetry.locate_explicit_values(
            plan, candidate_limit
        )
        if explicit_candidates:
            explicit_mode = True
            candidates = explicit_candidates
            plan.earliest = effective_earliest
        else:
            self._emit(progress, "catalog", "Discovering live Splunk telemetry", "ARIA is querying the connected Splunk catalog for the investigation time range; no source is accepted at this stage.")
            live_catalog = self.telemetry.live_catalog(plan.earliest, plan.latest)
            if not live_catalog and not plan.time_range_explicit and plan.earliest != "0":
                self._emit(progress, "catalog_fallback", "Widening catalog discovery", "No source groups were visible in the default range, so ARIA is checking all available time before abstaining.")
                live_catalog = self.telemetry.live_catalog("0", plan.latest)
                plan.earliest = "0"
                fallback_used = True
            self._emit(progress, "candidate_selection", "Selecting candidate sources", f"ARIA is deterministically ranking up to {candidate_limit} candidates from {len(live_catalog)} live source groups; source names are recall hints, not evidence.")
            selection = self.planner.select_candidates(
                question=question,
                plan=plan,
                catalog_rows=live_catalog,
                limit=candidate_limit,
            )
            allowed = {row["candidate_id"]: row for row in live_catalog}
            candidates = []
            for choice in selection.candidates:
                row = allowed.get(choice.candidate_id)
                if not row:
                    continue
                selected = dict(row)
                selected["selection_rationale"] = choice.rationale
                candidates.append(selected)
                if len(candidates) >= candidate_limit:
                    break

        if not candidates:
            finding = FindingSynthesis(
                verdict="NO_RELEVANT_TELEMETRY",
                summary="The live Splunk catalog did not yield a candidate source for the evidence requirements.",
                missing_evidence=[item.concept for item in plan.requirements if item.required],
                next_best_query_goal="Provide an explicit entity/value, widen the time range, or review data onboarding coverage.",
                analyst_guidance=["ARIA abstained instead of selecting a source by event volume alone."],
            )
            confidence = ConfidenceAssessment(score=0, factors=[])
            result = CopilotResult(
                capability=plan.capability,
                goal=plan.goal,
                answer="",
                plan=plan,
                finding=finding,
                confidence=confidence,
                context_actions=[finding.next_best_query_goal],
                metadata={"time_fallback_used": fallback_used},
            )
            result.answer = self.renderer.render(result)
            return result

        self._emit(progress, "profiling", "Profiling candidate telemetry", f"ARIA is validating observed fields and sample values across {len(candidates)} candidate source(s).")
        profiles = self.telemetry.profile_candidates(candidates, plan)
        if (
            not any(profile.fields for profile in profiles)
            and not plan.time_range_explicit
            and plan.earliest != "0"
        ):
            plan.earliest = "0"
            fallback_used = True
            self._emit(progress, "profiling_fallback", "Widening the evidence time range", "No fields were observed in the default range, so ARIA is retrying the same live profiles across all available time.")
            profiles = self.telemetry.profile_candidates(candidates, plan)

        self._emit(progress, "llm_qualification", "Mapping evidence concepts to observed fields", "ARIA is preparing observed-schema field binding from the live profiles returned by Splunk; generative qualification is not required.")
        proposals = self.planner.qualify_sources(
            question=question,
            plan=plan,
            profiles=self.telemetry.profile_prompt_records(profiles),
        )
        self._emit(
            progress,
            "semantic_binding",
            "Recovering observed-schema field bindings",
            "ARIA is using the configured local embedding model to recover any missing mappings from live observed field names and samples; no scenario-specific field dictionary is used.",
        )
        proposals = self.semantic_binder.enrich(
            plan=plan,
            profiles=profiles,
            proposals=proposals,
        )
        self._emit(progress, "evidence_validation", "Qualifying source evidence", "Deterministic controls are validating field existence, observed values and required-field co-occurrence.")
        source_evidence = self.qualifier.qualify(plan, profiles, proposals)
        accepted = [item for item in source_evidence if item.accepted][:accepted_limit]

        if (
            not accepted
            and not explicit_mode
            and live_catalog
            and budget_remaining() >= float(self.policy.get("recovery_minimum_budget_seconds", 55))
            and len(profiles) < max_total_candidates
        ):
            selected_ids = {str(item.get("candidate_id") or "") for item in candidates}
            remaining_catalog = [
                item for item in live_catalog
                if str(item.get("candidate_id") or "") not in selected_ids
            ]
            if remaining_catalog:
                self._emit(
                    progress,
                    "candidate_recovery",
                    "Expanding candidate discovery",
                    "The first candidate set did not satisfy evidence policy. ARIA is selecting a different live source set rather than returning a shallow result.",
                )
                recovery = self.planner.select_candidates(
                    question=(
                        question
                        + "\n\nThe first candidate set was rejected by deterministic evidence qualification. "
                        + "Select different candidates from the remaining live catalog that may expose the required concepts."
                    ),
                    plan=plan,
                    catalog_rows=remaining_catalog,
                    limit=min(
                        recovery_candidate_limit,
                        max_total_candidates - len(profiles),
                    ),
                )
                remaining_by_id = {row["candidate_id"]: row for row in remaining_catalog}
                recovery_candidates: list[dict[str, Any]] = []
                for choice in recovery.candidates:
                    row = remaining_by_id.get(choice.candidate_id)
                    if not row:
                        continue
                    selected = dict(row)
                    selected["selection_rationale"] = choice.rationale
                    recovery_candidates.append(selected)
                    if len(recovery_candidates) >= min(
                        recovery_candidate_limit,
                        max_total_candidates - len(profiles),
                    ):
                        break
                if recovery_candidates:
                    self._emit(
                        progress,
                        "recovery_profiling",
                        "Profiling additional live sources",
                        f"ARIA is checking observed fields and values in {len(recovery_candidates)} additional candidate source(s).",
                    )
                    recovery_profiles = self.telemetry.profile_candidates(recovery_candidates, plan)
                    self._emit(
                        progress,
                        "recovery_qualification",
                        "Qualifying the expanded evidence set",
                        "Observed-schema binding and deterministic co-occurrence controls are evaluating the additional profiles.",
                    )
                    recovery_proposals = self.planner.qualify_sources(
                        question=question,
                        plan=plan,
                        profiles=self.telemetry.profile_prompt_records(recovery_profiles),
                    )
                    recovery_proposals = self.semantic_binder.enrich(
                        plan=plan,
                        profiles=recovery_profiles,
                        proposals=recovery_proposals,
                    )
                    recovery_evidence = self.qualifier.qualify(plan, recovery_profiles, recovery_proposals)
                    profiles.extend(recovery_profiles)
                    source_evidence.extend(recovery_evidence)
                    source_evidence = sorted(source_evidence, key=lambda item: item.score, reverse=True)
                    accepted = [item for item in source_evidence if item.accepted][:accepted_limit]

        if not accepted and budget_remaining() < float(self.policy.get("recovery_minimum_budget_seconds", 55)):
            budget_exhausted = True
            self._emit(
                progress,
                "latency_budget",
                "Stopping additional recovery rounds",
                "ARIA reached the bounded interactive latency budget and is returning the qualified evidence gaps already collected instead of waiting indefinitely.",
            )

        # When a default recent window contains platform telemetry but no source
        # can express the analyst goal, discover a new all-time catalog rather
        # than repeatedly profiling only the recent candidates. This is essential
        # for historical or replay datasets and remains fully live/read-only.
        if (
            not accepted
            and not explicit_mode
            and not plan.time_range_explicit
            and not budget_exhausted
            and budget_remaining() >= float(self.policy.get("historical_recovery_minimum_budget_seconds", 75))
            and len(profiles) < max_total_candidates
        ):
            all_time_recovery_attempted = True
            tried_pairs = {(item.index, item.sourcetype) for item in profiles}
            all_time_catalog = self.telemetry.live_catalog("0", plan.latest)
            all_time_catalog_count = len(all_time_catalog)
            additional_catalog: list[dict[str, Any]] = []
            for position, row in enumerate(all_time_catalog, start=1):
                pair = (str(row.get("index") or ""), str(row.get("sourcetype") or ""))
                if not all(pair) or pair in tried_pairs:
                    continue
                item = dict(row)
                item["candidate_id"] = f"A{position}"
                additional_catalog.append(item)

            if additional_catalog:
                self._emit(
                    progress,
                    "all_time_catalog_recovery",
                    "Checking historical live telemetry",
                    "Recent telemetry could not express the required concepts, so ARIA is querying the connected Splunk catalog across all available time and selecting different sources.",
                )
                previous_earliest = plan.earliest
                plan.earliest = "0"
                fallback_used = True
                all_time_selection = self.planner.select_candidates(
                    question=question,
                    plan=plan,
                    catalog_rows=additional_catalog,
                    limit=min(
                        historical_candidate_limit,
                        max_total_candidates - len(profiles),
                    ),
                )
                all_time_by_id = {row["candidate_id"]: row for row in additional_catalog}
                all_time_candidates: list[dict[str, Any]] = []
                for choice in all_time_selection.candidates:
                    row = all_time_by_id.get(choice.candidate_id)
                    if not row:
                        continue
                    selected = dict(row)
                    selected["selection_rationale"] = choice.rationale
                    all_time_candidates.append(selected)
                    if len(all_time_candidates) >= min(
                        historical_candidate_limit,
                        max_total_candidates - len(profiles),
                    ):
                        break

                all_time_candidate_count = len(all_time_candidates)
                if all_time_candidates:
                    self._emit(progress, "all_time_profiling", "Profiling historical live sources", f"ARIA is validating observed fields and values across {len(all_time_candidates)} additional source(s).")
                    all_time_profiles = self.telemetry.profile_candidates(all_time_candidates, plan)
                    self._emit(progress, "all_time_qualification", "Qualifying historical evidence", "Observed-schema binding and deterministic co-occurrence controls are evaluating the historical source profiles.")
                    all_time_proposals = self.planner.qualify_sources(
                        question=question,
                        plan=plan,
                        profiles=self.telemetry.profile_prompt_records(all_time_profiles),
                    )
                    all_time_proposals = self.semantic_binder.enrich(
                        plan=plan,
                        profiles=all_time_profiles,
                        proposals=all_time_proposals,
                    )
                    all_time_evidence = self.qualifier.qualify(plan, all_time_profiles, all_time_proposals)
                    profiles.extend(all_time_profiles)
                    source_evidence.extend(all_time_evidence)
                    source_evidence = sorted(source_evidence, key=lambda item: item.score, reverse=True)
                    accepted = [item for item in source_evidence if item.accepted][:accepted_limit]
                elif previous_earliest != "0":
                    plan.earliest = previous_earliest

        # Qualification runs occur in several bounded rounds. Reassign evidence
        # identifiers once after merging so every source has a stable unique ID.
        source_evidence = sorted(source_evidence, key=lambda item: item.score, reverse=True)
        for evidence_number, source in enumerate(source_evidence, start=1):
            source.evidence_id = f"SRC-{evidence_number}"

        profile_by_id = {item.candidate_id: item for item in profiles}
        searches: list[SearchExecutionRecord] = []

        if plan.execute_read_only_search:
            for source_number, source in enumerate(accepted, start=1):
                self._emit(progress, "spl_strategy", "Designing evidence-bound SPL", f"Preparing read-only search {source_number} of {len(accepted)} for {source.index} / {source.sourcetype}.")
                profile = profile_by_id.get(source.candidate_id)
                if not profile:
                    continue
                strategy = self.spl_agent.propose_strategy(question, plan, source, profile)
                self._emit(progress, "spl_execution", "Executing read-only Splunk search", f"Running bounded search {source_number} of {len(accepted)} after the deterministic SPL safety gate.")
                searches.append(
                    self.spl_agent.compile_and_execute(
                        plan=plan,
                        source=source,
                        profile=profile,
                        strategy=strategy,
                        execution_number=len(searches) + 1,
                    )
                )

        self._emit(progress, "evidence_reasoning", "Reasoning over bounded Splunk evidence", "ARIA is producing a conservative evidence summary from qualified sources and returned Splunk rows; optional local-model reasoning cannot block completion.")
        if budget_remaining() < float(self.policy.get("reasoning_minimum_budget_seconds", 30)):
            budget_exhausted = True
            finding = self.reasoning.synthesize_without_model(plan, source_evidence, searches)
        else:
            finding = self.reasoning.synthesize(question, plan, source_evidence, searches)
        self._emit(progress, "confidence", "Calculating evidence confidence", "ARIA is calculating a reproducible score from coverage, observations, co-occurrence, execution and traceability.")
        confidence = self.reasoning.confidence(plan, source_evidence, searches, finding)
        risk = None
        if plan.capability in {"RISK_SCORING", "TDIR_WORKFLOW", "SOAR_PLAYBOOK"}:
            risk = self.risk_agent.recommend(plan, source_evidence, searches, finding, confidence)

        self._emit(progress, "deliverable", "Preparing the SOC deliverable", "ARIA is generating only the detection, risk, TDIR or SOAR material requested and supported by the current evidence.")
        deliverable = self.deliverables.generate(
            question=question,
            plan=plan,
            sources=source_evidence,
            searches=searches,
            finding=finding,
            confidence=confidence,
            risk=risk,
        )
        actions = self._context_actions(finding, plan.capability)
        result = CopilotResult(
            capability=plan.capability,
            goal=plan.goal,
            answer="",
            plan=plan,
            source_evidence=source_evidence,
            searches=searches,
            finding=finding,
            confidence=confidence,
            risk=risk,
            context_actions=actions,
            metadata={
                "time_fallback_used": fallback_used,
                "candidate_count": len(candidates),
                "accepted_source_count": len(accepted),
                "all_time_recovery_attempted": all_time_recovery_attempted,
                "all_time_catalog_count": all_time_catalog_count,
                "all_time_candidate_count": all_time_candidate_count,
                "profile_access_gap_count": sum(
                    1 for item in profiles if str(item.profile_error or "").startswith((
                        "CATALOG_VISIBLE",
                        "RAW_EVENTS_VISIBLE",
                    ))
                ),
                "live_splunk_queries": True,
                "dataset_assumptions": "NONE_ADDED_BY_ARIA",
                "latency_budget_exhausted": budget_exhausted,
                "latency_budget_remaining_seconds": round(budget_remaining(), 2),
                "max_total_candidates_profiled": max_total_candidates,
            },
        )
        result.answer = self.renderer.render(result, deliverable=deliverable)
        return result

    def _identity_response(
        self,
        question: str,
        plan: InvestigationPlan,
        route: IntentRoute,
        history: list[Any],
    ) -> CopilotResult:
        answer = """## Hello — I’m ARIA

I’m an **air-gapped, evidence-first SOC copilot for Splunk**. I help analysts work in natural language while keeping Splunk access read-only and security conclusions tied to observable evidence.

### What I can do

- Show the telemetry visible in the connected Splunk instance.
- Explain and review SPL without executing it.
- Translate an investigation goal into evidence-qualified read-only SPL.
- Discover live source groups, profile observed fields and validate field co-occurrence.
- Investigate entities, test threat hypotheses and summarise evidence gaps.
- Draft detection, RBA/ERS, TDIR and SOAR material for analyst review.

### How I work

**Reliable control plane → live Splunk facts → deterministic safety and evidence checks → optional local-model reasoning → analyst decision.**

Try: **“Show me the telemetry available in Splunk.”**"""
        return CopilotResult(
            capability="IDENTITY",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=list(route.suggested_followups),
            metadata={"live_splunk_queries": False, "response_mode": "RELIABLE_CONVERSATION"},
        )

    def _safety_response(
        self,
        question: str,
        plan: InvestigationPlan,
        route: IntentRoute,
    ) -> CopilotResult:
        answer = """## ARIA safety boundary

- Splunk access is **read-only**.
- Generated SPL must pass the local deterministic safety policy.
- ARIA does not create notables, write risk events, enable detections, contain systems or execute SOAR actions.
- Malware payloads, exploit instructions, destructive actions, credential theft and evasion guidance are not provided.
- Security conclusions require traceable live evidence; weak evidence produces explicit gaps or abstention.
- Analyst approval is required before operationalisation.
- Data and inference remain inside the local network.

No Splunk search was run for this explanation."""
        return CopilotResult(
            capability="SAFETY",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=list(route.suggested_followups),
            metadata={"live_splunk_queries": False, "response_mode": "RELIABLE_CONVERSATION"},
        )

    def _clarification_response(
        self,
        question: str,
        plan: InvestigationPlan,
        route: IntentRoute,
    ) -> CopilotResult:
        clarification = route.clarifying_question or (
            "What outcome should ARIA deliver: a conceptual explanation, SPL review, or a live read-only Splunk investigation?"
        )
        answer = "\n".join(
            [
                "## I need one detail before acting",
                "",
                route.routing_summary,
                "",
                clarification,
                "",
                "ARIA has not queried Splunk because the requested outcome is not yet clear.",
            ]
        )
        return CopilotResult(
            capability="SOC_CONVERSATION",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=list(route.suggested_followups),
            metadata={"live_splunk_queries": False, "clarification_needed": True},
        )

    def _aligned_followups(
        self,
        *,
        question: str,
        route: IntentRoute,
        result: CopilotResult,
    ) -> list[str]:
        suggestions = self.followups.suggest(
            question=question,
            route=route,
            result=result,
        )
        if suggestions:
            return suggestions
        fallback = list(route.suggested_followups) + list(result.context_actions)
        if result.finding and result.finding.next_best_query_goal:
            fallback.insert(0, result.finding.next_best_query_goal)
        output: list[str] = []
        for raw in fallback:
            item = " ".join(str(raw or "").split()).strip()
            if item and item.lower() not in {value.lower() for value in output}:
                output.append(item)
            if len(output) >= 4:
                break
        return output

    def _inventory(self, question: str, plan: InvestigationPlan) -> CopilotResult:
        catalog = self.telemetry.live_catalog()
        rows = [
            [
                item["candidate_id"],
                item["index"],
                item["sourcetype"],
                item["event_count"],
                item.get("first_seen") or "",
                item.get("last_seen") or "",
            ]
            for item in catalog[:30]
        ]
        answer = "\n".join(
            [
                "## Live Splunk Telemetry Inventory",
                "",
                "ARIA queried the connected Splunk instance in real time. This is source visibility, not a claim that every source is suitable for every investigation.",
                "",
                markdown_table(
                    ["ID", "Index", "Sourcetype", "Events", "First seen", "Last seen"],
                    rows,
                ),
                "",
                "## How ARIA uses this inventory",
                "",
                "For an analyst goal, ARIA deterministically ranks live catalog labels, profiles candidate sources, maps generic evidence concepts only to observed fields, validates values and co-occurrence, and only then compiles read-only SPL. Local models may enrich the answer but do not control access to telemetry.",
                "",
                "## Boundary",
                "",
                "- Read-only Splunk catalog query.",
                "- No source was treated as security evidence solely because it appears in this list.",
            ]
        )
        return CopilotResult(
            capability="INVENTORY",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=[
                "Query Splunk in natural language",
                "Investigate an entity",
                "Validate telemetry for a threat hypothesis",
            ],
            metadata={"catalog_rows": len(catalog), "live_splunk_queries": True},
        )

    def _build_spl(
        self,
        question: str,
        plan: InvestigationPlan,
        *,
        history: list[Any] | None = None,
        progress: ProgressCallback | None = None,
    ) -> CopilotResult:
        effective_question = self._reconstruct_build_request(question, history or [])
        # The BUILD_SPL request is reconstructed from user turns above. Passing the
        # assistant's prior rendered answer back into the builder pollutes intent
        # extraction with headings and follow-up controls, so the generic builder
        # receives only the reconstructed analyst request.
        generic = self.spl_builder.build(
            effective_question,
            context="",
        )

        generic_lines = [
            "## SPL Builder",
            "",
            "**Capability:** `BUILD_SPL`  ",
            "**Build contract:** `GENERIC_INTENT_DRAFT + LIVE_ENVIRONMENT_QUALIFICATION`  ",
            "**Final SPL execution:** `NO`",
            "",
            "## 1. Generic intent SPL",
            "",
            f"**Intent:** {generic.intent_summary or self.spl_builder.extract_intent(effective_question)}  ",
            f"**Generation path:** `{generic.generation_path}`  ",
            f"**Safety status:** `{generic.safety_status}`",
            "",
            "```spl",
            generic.spl,
            "```",
            "",
        ]
        if generic.unresolved_bindings:
            generic_lines.extend([
                "### Generic draft placeholders and unresolved inputs",
                "",
                *[f"- `{item}`" for item in generic.unresolved_bindings],
                "",
            ])
        if generic.notes:
            generic_lines.extend([
                "### Generic draft constraints",
                "",
                *[f"- {item}" for item in generic.notes],
                "",
            ])

        if not generic.time_range_explicit:
            generic_lines.extend([
                "## 2. Live Splunk-assisted SPL",
                "",
                "**Status:** `WAITING_FOR_TIME_RANGE`",
                "",
                "ARIA needs a time range before querying the connected Splunk catalogue and profiling live fields. This prevents an unbounded or misleading environment-specific search.",
                "",
                "Choose one of the following:",
                "",
                "- `Use the last 24 hours.`",
                "- `Use the last 7 days.`",
                "- `Use all available time.`",
                "- `Use earliest=<value> latest=<value>.`",
                "",
                "After the time range is supplied, ARIA will evaluate the visible catalogue, profile the most relevant live sources, validate observed fields and co-occurrence, and produce a second environment-qualified SPL alongside the generic draft.",
            ])
            return CopilotResult(
                capability="BUILD_SPL",
                goal=plan.goal,
                answer="\n".join(generic_lines),
                plan=plan,
                context_actions=[
                    "Use the last 24 hours.",
                    "Use the last 7 days.",
                    "Use all available time.",
                    "Use earliest=-1h latest=now.",
                ],
                metadata={
                    "live_splunk_queries": False,
                    "spl_executed": False,
                    "builder": "SPL_WORKBENCH_V2_3_5",
                    "awaiting_time_range": True,
                    "generic_generation_path": generic.generation_path,
                    "generic_spl": generic.spl,
                    "resolved_bindings": generic.resolved_bindings,
                    "unresolved_bindings": generic.unresolved_bindings,
                },
            )

        self._emit(
            progress,
            "build_catalog",
            "Discovering live telemetry for SPL",
            "ARIA is evaluating the connected Splunk catalogue for the analyst-selected time range. Catalogue labels are recall hints, not evidence.",
        )
        live = self._build_live_assisted_spl(effective_question, generic, progress=progress)
        generic_lines.extend(live["answer_lines"])
        return CopilotResult(
            capability="BUILD_SPL",
            goal=plan.goal,
            answer="\n".join(generic_lines),
            plan=live.get("plan") or plan,
            source_evidence=live.get("source_evidence") or [],
            context_actions=[
                "Execute the live-qualified SPL as a safe bounded search.",
                "Explain the differences between the generic and live-qualified SPL.",
                "Change the time range and rebuild both SPL variants.",
                "Turn the live-qualified SPL into a detection candidate.",
            ],
            metadata={
                "live_splunk_queries": True,
                "spl_executed": False,
                "builder": "SPL_WORKBENCH_V2_3_5",
                "awaiting_time_range": False,
                "generic_generation_path": generic.generation_path,
                "generic_spl": generic.spl,
                "live_spl": live.get("spl") or "",
                "live_spl_safe": bool(live.get("safe")),
                "catalog_rows_evaluated": int(live.get("catalog_rows", 0)),
                "profiles_evaluated": int(live.get("profiles_evaluated", 0)),
                "accepted_sources": int(live.get("accepted_sources", 0)),
                "value_grounded_field": str(live.get("value_grounded_field") or ""),
                "intent_matched_events": int(live.get("intent_matched_events", 0)),
                "value_probe_sampled_events": int(live.get("value_probe_sampled_events", 0)),
            },
        )

    def _build_live_assisted_spl(
        self,
        question: str,
        generic: Any,
        *,
        progress: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        discovery = self.build_spl_workbench.discover(
            question=question,
            generic=generic,
            progress=progress,
        )
        live_plan = discovery.plan
        source_evidence = discovery.evidence
        accepted = discovery.accepted

        lines = [
            "## 2. Live Splunk-assisted SPL",
            "",
            f"**Selected time range:** `{live_plan.earliest}` to `{live_plan.latest}`  ",
            f"**Visible catalogue labels evaluated:** `{discovery.total_catalog_rows}`  ",
            f"**Candidate source profiles evaluated:** `{discovery.scanned_profiles}`  ",
            f"**Progressive source scan complete:** `{'YES' if discovery.scan_complete else 'NO — stopped after qualification or budget'}`  ",
            "**Live operations performed:** read-only catalogue, raw field profiling, co-occurrence probes and bounded intent-value probes  ",
            "**Final generated SPL execution:** `NO`",
            "",
        ]

        source_rows = []
        for item in source_evidence:
            probe = discovery.value_probes.get(item.candidate_id, {})
            decision = "VALUE-QUALIFIED" if item.accepted and int(probe.get("all_terms_hits") or 0) > 0 else "REJECTED"
            source_rows.append([
                item.evidence_id,
                item.index,
                item.sourcetype,
                decision,
                f"{item.score:.1f}",
                f"{item.fully_bound_events}/{item.sampled_events}",
            ])
        if source_rows:
            lines.extend([
                "### Live source qualification",
                "",
                markdown_table(
                    ["Evidence", "Index", "Sourcetype", "Decision", "Score", "Schema fields present"],
                    source_rows,
                ),
                "",
            ])

        if not accepted:
            lines.extend([
                "**Status:** `NO_ENVIRONMENT_QUALIFIED_SPL`",
                "",
                "ARIA evaluated every visible catalogue label for recall and progressively profiled the highest-ranked live sources, but no source passed both schema and bounded intent-value policy within the configured build budget.",
                "",
                "The generic intent SPL remains available above. ARIA did not invent a source or field binding.",
                "",
                "### Qualification gaps",
                "",
            ])
            for item in source_evidence[:12]:
                reasons = "; ".join(item.rejection_reasons) or "Evidence qualification policy was not met."
                lines.append(f"- `{item.index}` / `{item.sourcetype}`: {reasons}")
            return {
                "answer_lines": lines,
                "spl": "",
                "safe": False,
                "plan": live_plan,
                "source_evidence": source_evidence,
                "catalog_rows": discovery.catalog_rows,
                "profiles_evaluated": discovery.scanned_profiles,
                "accepted_sources": 0,
                "scan_complete": discovery.scan_complete,
            }

        source = accepted[0]
        profile = next((item for item in discovery.profiles if item.candidate_id == source.candidate_id), None)
        if profile is None:
            lines.extend([
                "**Status:** `PROFILE_NOT_AVAILABLE`",
                "",
                "The accepted evidence record could not be matched to its live profile. No environment-specific SPL was emitted.",
            ])
            return {
                "answer_lines": lines,
                "spl": "",
                "safe": False,
                "plan": live_plan,
                "source_evidence": source_evidence,
                "catalog_rows": discovery.catalog_rows,
                "profiles_evaluated": discovery.scanned_profiles,
                "accepted_sources": len(accepted),
                "scan_complete": discovery.scan_complete,
            }

        value_probe = discovery.value_probes.get(source.candidate_id, {})
        if int(value_probe.get("all_terms_hits") or 0) <= 0:
            lines.extend([
                "**Status:** `NO_VALUE_GROUNDED_SPL`",
                "",
                "A live source exposed relevant schema, but bounded live values did not support all analyst-derived intent terms in the same field. ARIA did not promote field-name similarity into detection logic.",
            ])
            return {
                "answer_lines": lines,
                "spl": "",
                "safe": False,
                "plan": live_plan,
                "source_evidence": source_evidence,
                "catalog_rows": discovery.catalog_rows,
                "profiles_evaluated": discovery.scanned_profiles,
                "accepted_sources": 0,
                "scan_complete": discovery.scan_complete,
            }

        self._emit(
            progress,
            "build_strategy",
            "Designing live field-aware SPL",
            "The local fast model may choose an analytical shape using only the accepted source, observed fields and analyst-supplied terms. A deterministic observed-schema strategy remains available.",
        )
        proposed_strategy = self.spl_agent.propose_strategy(
            question=question,
            plan=live_plan,
            source=source,
            profile=profile,
            force_llm=True,
        )
        strategy = self.build_spl_workbench.ground_strategy(
            proposed=proposed_strategy,
            source=source,
            profile=profile,
            plan=live_plan,
            value_probe=value_probe,
        )
        try:
            spl = self.spl_agent.compile(live_plan, source, profile, strategy)
            if not strategy.filters or "| where " not in spl.lower():
                strategy = self.build_spl_workbench.deterministic_intent_strategy(
                    source=source,
                    profile=profile,
                    plan=live_plan,
                    value_probe=value_probe,
                )
                spl = self.spl_agent.compile(live_plan, source, profile, strategy)
            validation = spl_validator.validate(spl)
            safe = bool(getattr(validation, "safe", False))
            errors = list(getattr(validation, "errors", []) or [])
        except Exception as exc:
            spl = ""
            safe = False
            errors = [f"{exc.__class__.__name__}: {exc}"]

        probe_rows = []
        for item in value_probe.get("fields") or []:
            hits = int(item.get("all_terms_hits") or 0)
            if hits <= 0 and item.get("field") != value_probe.get("best_field"):
                continue
            term_hits = ", ".join(
                f"{term}={count}" for term, count in (item.get("term_hits") or {}).items()
            )
            probe_rows.append([item.get("field"), hits, term_hits])
        if probe_rows:
            lines.extend([
                "### Live intent-value validation",
                "",
                markdown_table(
                    ["Field", "Events containing all intent terms", "Per-term bounded hits"],
                    probe_rows[:8],
                ),
                "",
                f"**Value-grounded field:** `{value_probe.get('best_field')}`  ",
                f"**Intent-matched bounded events:** `{value_probe.get('all_terms_hits')}/{value_probe.get('sampled_events')}`  ",
                "",
            ])

        field_selection_rows = []
        primary_field = str(value_probe.get("best_field") or "")
        if primary_field:
            field_selection_rows.append([
                "Intent content",
                primary_field,
                "LIVE_VALUE_GROUNDED",
                f"{value_probe.get('all_terms_hits')} bounded event(s) contained all analyst-derived terms",
            ])
        for field in strategy.group_by:
            if field == primary_field:
                continue
            field_selection_rows.append([
                "Grouping context",
                field,
                "OBSERVED_SCHEMA",
                "Used only for aggregation context; not treated as proof of the requested activity",
            ])
        if field_selection_rows:
            lines.extend([
                "### Environment field selection",
                "",
                markdown_table(
                    ["Role", "Field", "Evidence status", "Basis"],
                    field_selection_rows,
                ),
                "",
            ])

        strategy_path = (
            "LIVE_VALUE_PROBE + ANALYST_TERMS + DETERMINISTIC_COMPILER"
            if strategy.purpose.startswith("Environment-qualified draft")
            else "LOCAL_LLM_SHAPE + LIVE_VALUE_GROUNDED_FILTERS + DETERMINISTIC_COMPILER"
        )
        lines.extend([
            "### Environment-qualified SPL",
            "",
            f"**Source:** `{source.index}` / `{source.sourcetype}`  ",
            f"**Schema field presence:** `{source.fully_bound_events}/{source.sampled_events}` bounded events  ",
            f"**Intent-matched events:** `{value_probe.get('all_terms_hits')}/{value_probe.get('sampled_events')}` bounded events  ",
            f"**Generation path:** `{strategy_path}`  ",
            f"**Safety gate:** `{'PASS' if safe else 'BLOCKED'}`",
            "",
            "```spl",
            spl or "No SPL was compiled.",
            "```",
            "",
            "### Defensibility boundary",
            "",
            "- Every visible catalogue label was evaluated for recall; only a bounded progressive set required raw profiling.",
            "- The accepted source came from the connected Splunk catalogue for the analyst-selected time range.",
            "- Every emitted field came from the live profile or Splunk platform metadata and passed deterministic field validation.",
            "- Schema presence and intent evidence were evaluated separately; field-name similarity alone could not qualify the SPL.",
            "- Every emitted intent filter was backed by a bounded live value probe in the selected field.",
            "- Filter terms came from the analyst's request and generic punctuation variants; no scenario dictionary was used.",
            "- The generated SPL was safety-validated but was not executed by BUILD_SPL.",
        ])
        if errors:
            lines.extend(["", "### Safety or compilation errors", "", *[f"- {compact_text(item, 300)}" for item in errors]])
        return {
            "answer_lines": lines,
            "spl": spl,
            "safe": safe,
            "plan": live_plan,
            "source_evidence": source_evidence,
            "catalog_rows": discovery.catalog_rows,
            "profiles_evaluated": discovery.scanned_profiles,
            "accepted_sources": len(accepted),
            "scan_complete": discovery.scan_complete,
            "value_grounded_field": str(value_probe.get("best_field") or ""),
            "intent_matched_events": int(value_probe.get("all_terms_hits") or 0),
            "value_probe_sampled_events": int(value_probe.get("sampled_events") or 0),
        }

    @staticmethod
    def _reconstruct_build_request(question: str, history: list[Any]) -> str:
        if DeterministicSPLBuilder.has_explicit_time(question):
            for item in reversed(history):
                if not isinstance(item, dict):
                    continue
                if str(item.get("role") or "").lower() != "user":
                    continue
                content = str(item.get("content") or "").strip()
                if content and re.search(r"\b(?:build|create|generate|write|give\s+me)\b.*\bspl\b", content, flags=re.IGNORECASE | re.DOTALL):
                    return content + "\n\n" + question
        return question

    def _explain_spl(self, question: str, plan: InvestigationPlan) -> CopilotResult:
        spl = self._extract_spl(question)
        validation = spl_validator.validate(spl)
        generation_path = "DETERMINISTIC_SPL_REVIEW"
        try:
            explanation = self.ollama.chat(
                system_prompt="""You are ARIA's local SPL reasoning agent.
Explain the supplied SPL precisely and concisely. Cover intent, each pipeline stage, field dependencies, time range, performance, assumptions, interpretation risks and safer improvements. Do not invent data contents or claim execution. Output Markdown.""",
                user_prompt=(
                    f"Analyst request:\n{question}\n\nExtracted SPL:\n{spl}\n\n"
                    f"Deterministic safety validation:\n{json.dumps(dict(validation), indent=2)}"
                ),
                model_role="fast",
                temperature=0.1,
                num_predict=650,
                timeout=int(self.policy.get("spl_explanation_timeout_seconds", 60)),
            )
            generation_path = "LOCAL_MODEL+DETERMINISTIC_SAFETY"
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.engine.spl_explanation")
            explanation = self._deterministic_spl_explanation(spl)

        answer = "\n".join([
            "## SPL Explanation",
            "",
            f"**Generation path:** `{generation_path}`  ",
            "**Splunk execution:** `NO`  ",
            f"**Safety gate:** `{'PASS' if getattr(validation, 'safe', False) else 'BLOCKED'}`",
            "",
            explanation,
            "",
            "## SPL Reviewed",
            "",
            "```spl",
            spl,
            "```",
        ])
        return CopilotResult(
            capability="EXPLAIN_SPL",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=["Validate this SPL against live telemetry", "Optimise this SPL", "Run a safe bounded version"],
            metadata={"spl_executed": False, "safety": dict(validation), "generation_path": generation_path},
        )

    @staticmethod
    def _deterministic_spl_explanation(spl: str) -> str:
        stages = [part.strip() for part in str(spl or "").split("|") if part.strip()]
        lines = [
            "The local explanation model was unavailable, so ARIA produced a deterministic pipeline review.",
            "",
            "### Pipeline stages",
        ]
        command_notes = {
            "search": "Selects events and applies the base time/index constraints.",
            "tstats": "Runs an accelerated statistical search over indexed metadata or data models.",
            "stats": "Aggregates events into metrics, optionally grouped by fields.",
            "timechart": "Aggregates values over time buckets.",
            "table": "Limits the displayed fields.",
            "fields": "Includes or excludes fields from the pipeline.",
            "where": "Applies a boolean filter after fields are available.",
            "eval": "Creates or transforms fields.",
            "sort": "Orders the result set and may be expensive on large unbounded results.",
            "head": "Limits the number of returned rows.",
            "dedup": "Removes duplicate values and may retain only one event per key.",
            "rex": "Extracts fields with a regular expression.",
            "lookup": "Enriches events from a lookup definition.",
        }
        for position, stage in enumerate(stages, start=1):
            command = stage.split(None, 1)[0].lower() if stage else "stage"
            note = command_notes.get(command, "Processes the current result set; review its arguments and field dependencies.")
            lines.append(f"{position}. `{stage}` — {note}")
        lines.extend([
            "",
            "### Review points",
            "- Confirm the time range and index scope are intentionally bounded.",
            "- Confirm every referenced field exists in the intended telemetry.",
            "- Treat high event count as activity, not proof of maliciousness.",
            "- Prefer early filtering and bounded output for interactive searches.",
            "- Validate interpretation against returned events before operationalising the logic.",
        ])
        return "\n".join(lines)

    def _soc_conversation(
        self,
        question: str,
        plan: InvestigationPlan,
        *,
        route: IntentRoute,
        history: list[Any] | None = None,
        last_result: Any | None = None,
    ) -> CopilotResult:
        system = """You are ARIA, an air-gapped SecOps conversational agent and evidence-first SOC copilot for Splunk.
Answer the current cybersecurity or security-operations question directly. Do not treat natural-language security prose as SPL. Explain what the concept is, why defenders care, observable evidence, investigation considerations and when live Splunk validation adds value. Do not claim Splunk was queried. Do not invent customer datasets, fields, event IDs or results. Do not emit concrete SPL unless the current analyst explicitly requested a template. Output clear Markdown."""
        context = []
        for item in (history or [])[-4:]:
            if isinstance(item, dict) and item.get("content"):
                context.append(f"{item.get('role', 'message')}: {compact_text(item.get('content'), 350)}")
        user_prompt = (
            f"CURRENT ANALYST MESSAGE:\n{question}\n\n"
            f"Recent context supplied only for explicit follow-up:\n{chr(10).join(context) or 'None'}"
        )
        model_status = "LOCAL_MODEL"
        try:
            answer = self.ollama.chat(
                system_prompt=system,
                user_prompt=user_prompt,
                model_role="fast",
                temperature=0.1,
                num_predict=700,
                timeout=int(self.policy.get("conversation_model_timeout_seconds", 75)),
            )
            if self._looks_like_scope_redirect(answer):
                answer = self.ollama.chat(
                    system_prompt=(
                        system
                        + "\nThe request is already confirmed in scope. Ignore all prior scope decisions and answer only the current security question."
                    ),
                    user_prompt=f"Current in-scope SecOps question:\n{question}",
                    model_role="fast",
                    temperature=0.1,
                    num_predict=650,
                    timeout=int(self.policy.get("conversation_retry_timeout_seconds", 45)),
                )
                model_status = "LOCAL_MODEL_ISOLATED_RETRY"
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.engine.soc_conversation")
            model_status = "LOCAL_MODEL_UNAVAILABLE"
            answer = (
                "## Local SecOps model temporarily unavailable\n\n"
                "ARIA correctly recognised this as a cybersecurity question, but the local conversational model did not respond within its bounded latency window. No Splunk query was run and no explanation was fabricated.\n\n"
                "You can retry the question, check local model health, or ask ARIA to investigate the topic using live read-only Splunk evidence."
            )

        answer = self._remove_unvalidated_spl_examples(answer)
        if self._looks_like_scope_redirect(answer):
            answer = (
                "## Local response conflict\n\n"
                "ARIA confirmed this request is inside SecOps, but the local model returned an incompatible scope response. No Splunk query was run and no unsupported answer was fabricated."
            )
            model_status = "LOCAL_MODEL_CONFLICT"

        return CopilotResult(
            capability="SOC_CONVERSATION",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=list(route.suggested_followups),
            metadata={"live_splunk_queries": False, "model_status": model_status},
        )

    @classmethod
    def _remove_unvalidated_spl_examples(cls, answer: str) -> str:
        """Remove concrete model-generated SPL from conceptual responses.

        Conceptual SecOps answers may describe telemetry concepts, but concrete SPL
        requires either explicit template mode or live field binding.
        """
        text = str(answer or "")
        lines = text.splitlines()
        output: list[str] = []
        removed = False
        in_fence = False
        fence_buffer: list[str] = []
        for line in lines:
            if line.strip().startswith("```"):
                if not in_fence:
                    in_fence = True
                    fence_buffer = [line]
                else:
                    fence_buffer.append(line)
                    block = "\n".join(fence_buffer)
                    if LLMIntentRouter._looks_like_spl(block):
                        removed = True
                    else:
                        output.extend(fence_buffer)
                    in_fence = False
                    fence_buffer = []
                continue
            if in_fence:
                fence_buffer.append(line)
                continue
            if LLMIntentRouter._looks_like_spl(line):
                removed = True
                continue
            output.append(line)
        if fence_buffer:
            if LLMIntentRouter._looks_like_spl("\n".join(fence_buffer)):
                removed = True
            else:
                output.extend(fence_buffer)
        cleaned = "\n".join(output).strip()
        if removed:
            cleaned += (
                "\n\n> ARIA omitted an unvalidated model-generated SPL example. "
                "Ask for an evidence-backed Splunk investigation or an explicit placeholder-only template."
            )
        return cleaned

    @staticmethod
    def _looks_like_scope_redirect(answer: str) -> bool:
        text = " ".join(str(answer or "").lower().split())
        boundary_markers = (
            "aria secops scope boundary",
            "specialised security operations and splunk copilot",
            "cannot help with unrelated general-purpose requests",
            "recipes, cooking, entertainment or lifestyle",
        )
        return any(marker in text for marker in boundary_markers)

    def _scope_guard_response(
        self,
        question: str,
        plan: InvestigationPlan,
        route: IntentRoute,
    ) -> CopilotResult:
        answer = """## ARIA SecOps scope boundary

I am a specialised **security operations and Splunk copilot**, so I cannot help with unrelated general-purpose requests such as recipes, cooking, entertainment or lifestyle tasks.

I can help you with:

- Cybersecurity and SecOps concepts.
- Explaining, reviewing and optimising SPL.
- Translating natural language into evidence-qualified read-only SPL.
- Querying the connected Splunk instance using natural language.
- Entity investigations, threat hypotheses and evidence-linked triage.
- Detection engineering, RBA/ERS recommendations and approval-gated TDIR/SOAR workflows.

No Splunk search was run for this response."""
        return CopilotResult(
            capability="SCOPE_GUARD",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=list(route.suggested_followups) or [
                "Explain a cybersecurity concept.",
                "Explain or optimise an SPL search.",
                "Query Splunk using natural language.",
                "Start an evidence-first security investigation.",
            ],
            metadata={
                "live_splunk_queries": False,
                "response_mode": "DOMAIN_REDIRECT",
                "domain_scope": "OUT_OF_SCOPE",
            },
        )

    def _generic_template(self, question: str, plan: InvestigationPlan) -> CopilotResult:
        system = """Generate a generic review-only SPL template because the analyst explicitly requested no live Splunk query.
Use descriptive braces for every unresolved index, sourcetype, field, value, time range and threshold.
Do not insert vendor event IDs or concrete customer values.
Use only read-only commands.
Explain that the template is not evidence-backed. Output Markdown."""
        answer = self.ollama.chat(
            system_prompt=system,
            user_prompt=f"Analyst request:\n{question}\n\nPlan:\n{plan.model_dump_json(indent=2)}",
            model_role="fast",
            temperature=0.0,
            num_predict=700,
            timeout=int(self.policy.get("template_model_timeout_seconds", 60)),
        )
        return CopilotResult(
            capability="GENERIC_SPL_TEMPLATE",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=["Run the evidence-backed workflow against live Splunk"],
            metadata={"live_splunk_queries": False, "template_only": True},
        )

    def _unsafe_redirect(self, question: str, plan: InvestigationPlan) -> CopilotResult:
        redirect = plan.safe_redirect_goal or "Translate the request into defender-safe telemetry, detection and validation objectives."
        answer = "\n".join(
            [
                "## ARIA Safety Redirect",
                "",
                "ARIA cannot generate malware payloads, exploit code, credential theft instructions, destructive actions, evasion guidance or guardrail bypasses.",
                "",
                "### Defender-safe alternative",
                "",
                redirect,
                "",
                "ARIA can use live Splunk evidence to assess telemetry coverage, generate read-only hunt SPL, draft a detection candidate and create an approval-gated TDIR or SOAR workflow.",
            ]
        )
        return CopilotResult(
            capability="SAFETY_REDIRECT",
            goal=plan.goal,
            answer=answer,
            plan=plan,
            context_actions=[redirect],
            metadata={"live_splunk_queries": False, "unsafe_request_blocked": True},
        )

    @staticmethod
    def _extract_spl(question: str) -> str:
        text = question.strip()
        if "```" in text:
            blocks = text.split("```")
            if len(blocks) >= 3:
                block = blocks[1]
                if block.lower().startswith("spl\n"):
                    block = block[4:]
                return block.strip()
        lines = text.splitlines()
        for position, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("|") or stripped.lower().startswith("search ") or "index=" in stripped.lower():
                return "\n".join(lines[position:]).strip()
        return text

    @staticmethod
    def _context_actions(finding: FindingSynthesis, capability: str) -> list[str]:
        actions = [finding.next_best_query_goal]
        if capability not in {"DETECTION_ENGINEERING", "MALWARE_SIMULATION"}:
            actions.append("Turn validated evidence into a detection candidate")
        if capability != "RISK_SCORING":
            actions.append("Create an evidence-aware RBA/ERS recommendation")
        if capability not in {"TDIR_WORKFLOW", "SOAR_PLAYBOOK"}:
            actions.append("Draft an approval-gated TDIR workflow")
        return list(dict.fromkeys(item for item in actions if item))[:4]

    @staticmethod
    def _emit(
        progress: ProgressCallback | None,
        stage: str,
        label: str,
        detail: str = "",
    ) -> None:
        if progress is None:
            return
        try:
            progress(stage, label, detail)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.engine.progress")

    @staticmethod
    def _audit(
        question: str,
        result: CopilotResult,
        started: float,
        status: str = "success",
    ) -> None:
        try:
            audit_logger.log_interaction(
                prompt=question,
                answer=result.answer,
                capability=result.capability,
                route="COPILOT_ENGINE",
                status=status,
                metadata={
                    "duration_seconds": round(time.monotonic() - started, 2),
                    "source_evidence_count": len(result.source_evidence),
                    "search_count": len(result.searches),
                    "finding_verdict": result.finding.verdict if result.finding else None,
                    "confidence": result.confidence.score if result.confidence else None,
                },
            )
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.copilot.engine.audit")

