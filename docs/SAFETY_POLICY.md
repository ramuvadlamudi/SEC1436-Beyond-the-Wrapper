# ARIA Runtime Safety Policy

## Product

ARIA — Air-gapped Reasoning and Investigation Assistant

## Version

1.0.0-preview

## Release Channel

Controlled Preview / Field Pilot

## Core Principle

The LLM reasons. Splunk provides evidence. Guardrails constrain. The analyst approves.

## Default Execution Mode

ARIA V1 is read-only by default.

## Safety Boundaries

ARIA V1 does not:

- Execute destructive SPL.
- Execute SOAR actions.
- Create enabled detections automatically.
- Write risk events automatically.
- Treat placeholders as real values.
- Hardcode customer datasets.
- Perform automatic containment.
- Generate malware code.
- Send data to external cloud LLMs.

## Allowed Outputs

ARIA V1 may generate:

- Read-only SPL.
- Candidate comparison SPL.
- Field-binding worksheets.
- Detection drafts.
- RBA/ERS recommendations.
- Zero-trust SOAR playbook drafts.
- TDIR workflow drafts.
- Analyst next steps.

## Approval Gates

The analyst must approve:

- Field bindings.
- Detection logic.
- Behaviour validation.
- RBA/ERS scoring.
- SOAR playbook operationalisation.
- Any production deployment.

## Dataset-Agnostic Design Rules

ARIA V1 must not hardcode:

- Indexes.
- Sourcetypes.
- Fields.
- Event IDs.
- Hosts.
- Users.
- IP addresses.
- Dataset-specific use cases.

ARIA V1 may only use:

- Analyst-supplied values.
- Splunk-discovered values.
- Customer-defined local pattern files.

## V1 Caveats

ARIA V1 is a controlled preview release. It is suitable for field pilots, demos, and controlled SOC evaluation. It is not yet a fully supported enterprise GA product.
