# Security Policy

## Supported release

ARIA `3.0.0-rc11` is a controlled-preview release candidate. It is intended for approved demonstrations, laboratories and read-only pilot environments.

## Reporting a vulnerability

Do not open a public issue containing credentials, private telemetry, customer identifiers, exploit details or other sensitive material.

Before public publication, the repository owner must configure a private vulnerability-reporting channel and update this section with that contact. Until then, share reports only through the authorised private channel for the deployment or repository owner.

Include:

- affected version and component;
- a minimal reproduction with secrets and customer data removed;
- expected and observed safety behaviour;
- impact assessment;
- suggested remediation, if known.

## Deployment requirements

- Use a dedicated Splunk account with the minimum read-only search permissions required.
- Keep `.env`, audit output, runtime data and release archives out of source control.
- Terminate TLS using certificates trusted by the deployment; do not disable verification outside an isolated demonstration.
- Bind services to loopback or a protected interface unless an approved reverse proxy provides authentication and transport security.
- Keep Ollama, Splunk management endpoints and ARIA services on trusted network segments.
- Run `python validate_v3_acceptance.py --skip-live` before deployment and connected acceptance in the target environment.
- Review all proposed detections, RBA/ERS recommendations and TDIR/SOAR workflows before operationalisation.

## Security boundaries

ARIA is designed to:

- route without a generative-model decision;
- validate executable SPL deterministically;
- execute only bounded read-only investigation searches;
- abstain when evidence is insufficient;
- prevent conversational output from claiming live evidence;
- prevent a failed local model from disabling deterministic safety and inventory controls.

ARIA does not provide:

- automatic containment or response;
- automatic detection, notable or risk-event writeback;
- protection against a compromised host, Splunk instance or local model runtime;
- a substitute for network controls, identity controls, change management or analyst review.

See `SECURITY_MODEL.md` and `docs/SAFETY_POLICY.md` for the full design boundary.

## Pattern A and Pattern C material

- Pattern A `ai_result_*` output is untrusted assistance. It must not bypass Splunk permissions, SPL review, framework validation or change control.
- Restrict AI Toolkit connection editing to approved administrators and bound input rows, fields and time before `| ai`.
- Pattern C content is an experimental design roadmap. It does not add DSDL, RAG, container or action authority to ARIA RC11.
- Any Pattern C experiment requires a separate threat model, corpus ACLs, offline supply-chain review, evaluation and rollback plan.
