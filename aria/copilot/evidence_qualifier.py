from __future__ import annotations

from typing import Any

from aria.copilot.contracts import (
    InvestigationPlan,
    RequirementBindingRecord,
    SourceEvidenceRecord,
    SourceProfileRecord,
    SourceQualificationSet,
)
from aria.copilot.policy import evidence_policy
from aria.copilot.telemetry_agent import LiveTelemetryAgent
from aria.copilot.utils import parse_samples, ratio


class DeterministicEvidenceQualifier:
    """Validate LLM proposals against live observed fields and co-occurrence probes."""

    def __init__(self, telemetry: LiveTelemetryAgent) -> None:
        self.telemetry = telemetry
        self.policy = evidence_policy()

    def qualify(
        self,
        plan: InvestigationPlan,
        profiles: list[SourceProfileRecord],
        proposal_set: SourceQualificationSet,
    ) -> list[SourceEvidenceRecord]:
        proposal_by_id = {item.candidate_id: item for item in proposal_set.sources}
        requirement_by_id = {item.requirement_id: item for item in plan.requirements}
        required_total = sum(1 for item in plan.requirements if item.required)
        optional_total = sum(1 for item in plan.requirements if not item.required)
        output: list[SourceEvidenceRecord] = []

        for position, profile in enumerate(profiles, start=1):
            proposal = proposal_by_id.get(profile.candidate_id)
            available_fields = {
                str(field.get("name") or ""): field
                for field in profile.fields
                if str(field.get("name") or "")
            }
            mappings = {
                item.requirement_id: item
                for item in (proposal.requirement_mappings if proposal else [])
            }
            bindings: list[RequirementBindingRecord] = []

            for requirement in plan.requirements:
                mapping = mappings.get(requirement.requirement_id)
                proposed_fields = mapping.fields if mapping else []
                validated_fields = [field for field in proposed_fields if field in available_fields]
                observed_samples = {
                    field: parse_samples(available_fields[field].get("sample_values"), 5)
                    for field in validated_fields
                }

                if not mapping or not validated_fields:
                    status = "UNSUPPORTED"
                    rationale = (
                        mapping.rationale
                        if mapping
                        else "The local qualification model did not map this requirement to an observed field."
                    )
                elif mapping.status == "SUPPORTED" and any(observed_samples.values()):
                    status = "SUPPORTED"
                    rationale = mapping.rationale
                else:
                    status = "PARTIAL"
                    rationale = mapping.rationale

                bindings.append(
                    RequirementBindingRecord(
                        requirement_id=requirement.requirement_id,
                        concept=requirement.concept,
                        role=requirement.role,
                        required=requirement.required,
                        status=status,
                        fields=validated_fields,
                        observed_samples=observed_samples,
                        rationale=rationale,
                    )
                )

            required_supported = sum(
                1.0 if item.status == "SUPPORTED" else 0.5
                for item in bindings
                if item.required and item.status in {"SUPPORTED", "PARTIAL"} and item.fields
            )
            optional_supported = sum(
                1.0 if item.status == "SUPPORTED" else 0.5
                for item in bindings
                if not item.required and item.status in {"SUPPORTED", "PARTIAL"} and item.fields
            )
            observed_field_bindings = [
                item
                for item in bindings
                if item.fields and any(item.observed_samples.values())
            ]
            primary_fields: list[str] = []
            for item in bindings:
                if item.required and item.fields:
                    primary_fields.append(item.fields[0])
            primary_fields = list(dict.fromkeys(primary_fields))

            probe: dict[str, Any] = {
                "sampled_events": 0,
                "fully_bound_events": 0,
                "field_presence": {},
            }
            probe_error: str | None = None
            if primary_fields and not profile.profile_error:
                try:
                    probe = self.telemetry.cooccurrence_probe(
                        profile=profile,
                        fields=primary_fields,
                        earliest=plan.earliest,
                        latest=plan.latest,
                    )
                except Exception as exc:
                    probe_error = f"{exc.__class__.__name__}: {exc}"

            required_coverage = ratio(required_supported, required_total or 1)
            optional_coverage = ratio(optional_supported, optional_total or 1) if optional_total else 0.0
            field_observation = ratio(len(observed_field_bindings), len(bindings) or 1)
            sampled_events = int(probe.get("sampled_events") or 0)
            fully_bound_events = int(probe.get("fully_bound_events") or 0)
            cooccurrence = ratio(fully_bound_events, sampled_events)

            score = (
                required_coverage * 55.0
                + field_observation * 15.0
                + cooccurrence * 20.0
                + optional_coverage * 5.0
                + (5.0 if profile.event_count > 0 else 0.0)
            )

            rejection_reasons: list[str] = []
            if profile.profile_error:
                rejection_reasons.append(f"Live profile failed: {profile.profile_error}")
            deterministic_live_support = (
                required_coverage >= float(self.policy.get("minimum_required_coverage", 0.60))
                and sampled_events > 0
                and (
                    required_total <= 1
                    or fully_bound_events > 0
                    or not bool(
                        self.policy.get(
                            "require_cooccurrence_for_multiple_required_concepts",
                            True,
                        )
                    )
                )
            )
            if proposal is None:
                rejection_reasons.append(
                    "No field qualification proposal was returned for this live source."
                )
            else:
                suitability_rank = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
                minimum_suitability = str(
                    self.policy.get("minimum_llm_suitability", "MEDIUM")
                ).upper()
                if (
                    suitability_rank.get(proposal.suitability, 0)
                    < suitability_rank.get(minimum_suitability, 2)
                    and not deterministic_live_support
                ):
                    rejection_reasons.append(
                        f"Qualification suitability {proposal.suitability} is below the policy minimum {minimum_suitability}, and live field/co-occurrence evidence did not independently validate the source."
                    )
            if required_coverage < float(self.policy.get("minimum_required_coverage", 0.60)):
                rejection_reasons.append(
                    f"Required concept coverage {required_coverage:.0%} is below policy minimum."
                )
            if (
                required_total >= 1
                and primary_fields
                and bool(self.policy.get("require_required_field_presence", True))
                and fully_bound_events <= 0
            ):
                rejection_reasons.append(
                    "No bounded live event contained the required observed field set."
                )
            if required_total > 1 and bool(
                self.policy.get("require_cooccurrence_for_multiple_required_concepts", True)
            ) and fully_bound_events <= 0:
                rejection_reasons.append(
                    "Required concept fields were not observed together in the bounded live co-occurrence probe."
                )
            if sampled_events <= 0:
                rejection_reasons.append("The bounded live probe returned no sampled events.")
            if probe_error:
                rejection_reasons.append(f"Co-occurrence probe failed: {probe_error}")
            if score < float(self.policy.get("minimum_source_score", 55.0)):
                rejection_reasons.append(f"Evidence score {score:.1f} is below policy minimum.")

            accepted = not rejection_reasons
            output.append(
                SourceEvidenceRecord(
                    evidence_id=f"SRC-{position}",
                    candidate_id=profile.candidate_id,
                    index=profile.index,
                    sourcetype=profile.sourcetype,
                    suitability=(proposal.suitability if proposal else "NONE"),
                    score=round(score, 1),
                    accepted=accepted,
                    rejection_reasons=rejection_reasons,
                    requirement_bindings=bindings,
                    sampled_events=sampled_events,
                    fully_bound_events=fully_bound_events,
                    cooccurrence_ratio=round(cooccurrence, 4),
                    profile_error=profile.profile_error,
                )
            )

        return sorted(output, key=lambda item: item.score, reverse=True)
