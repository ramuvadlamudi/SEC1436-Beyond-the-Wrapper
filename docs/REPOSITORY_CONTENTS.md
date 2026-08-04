# Repository Contents

## SEC1436 pattern guides

| Path | Purpose |
|---|---|
| `patterns/pattern-a-ai-toolkit/` | AI Toolkit `| ai` to local Ollama: installation, controls, portable templates, five validated demo use cases and screenshots |
| `patterns/pattern-c-dsdl-rag/` | DSDL/private-RAG future architecture, experiment backlog, security evaluation and starter governance templates |
| `docs/SEC1436_THREE_PATTERN_ARCHITECTURE.md` | Pattern A/B/C runtime separation, data flows and trust boundaries |
| `docs/PATTERN_COMPARISON.md` | Selection guidance and capability comparison |

Pattern B remains the implemented ARIA runtime at the repository root. Pattern A is demonstration guidance. Pattern C is explicitly experimental and contains no claim of RC11 implementation.

## Runtime entry points

| File | Purpose |
|---|---|
| `web_ui.py` | Analyst workspace web UI |
| `aria_llm_gateway.py` | Local gateway between product services and Ollama |
| `main.py` | Command-line entry point |
| `aria_health.py` | Runtime health check |
| `aria_safe_startup_check.py` | Pre-start safety and configuration checks |

## Product source

| Path | Purpose |
|---|---|
| `aria/v3/` | RC11 orchestrator, router, agent contracts and telemetry intelligence |
| `aria/copilot/` | Shared planning, evidence, SPL, rendering and compatibility services |
| `aria/splunk_client.py` | Read-only Splunk REST client |
| `aria/ollama_client.py` | Local Ollama client |
| `aria/spl_validator.py` | Deterministic SPL safety validation |
| `product/` | Version, release manifest, public knowledge cards and policy JSON |

## Validation and operations

| Path | Purpose |
|---|---|
| `validate_v3_acceptance.py` | Complete package and connected release gate |
| `scripts/test_*.py` | Routing, agent, evidence, safety and UI regression tests |
| `scripts/audit_*.py` | Hardcoding, safety, source and packaging audits |
| `scripts/live_v3_acceptance.py` | Connected Splunk/Ollama acceptance |
| `scripts/deploy_v3_release.py` | Transactional deployment with rollback |
| `scripts/install_systemd_services.sh` | Example service installation |

## Public repository controls

| Path | Purpose |
|---|---|
| `.github/workflows/validate.yml` | GitHub Actions RC11 acceptance |
| `.github/ISSUE_TEMPLATE/` | Sanitized bug and feature intake |
| `.github/dependabot.yml` | Dependency update configuration |
| `.env.example` | Safe configuration template; contains no credentials |
| `.gitignore` | Excludes secrets, runtime data, caches and release artifacts |
| `PUBLIC_RELEASE_CHECKLIST.md` | Human publication approvals and controls |
| `SECURITY.md` | Vulnerability reporting and deployment requirements |
| `LICENSE` and `NOTICE` | Licence and attribution material |

## Intentionally excluded

- populated `.env` files;
- credentials, tokens, certificates and keys;
- runtime `data/`, prompts, audit logs and customer telemetry;
- `.venv`, caches and bytecode;
- local checkpoints and backup files;
- nested runtime or source archives;
- private hostnames, addresses and user-specific deployment paths.

The Pattern A screenshots show approved public laboratory/demo searches and model responses. Dataset-specific values visible in those captures are demonstration evidence only and are not embedded in product logic or reusable SPL templates.
