# Installation

This guide installs ARIA Pattern B v3.0.0-rc11 on an Ubuntu-based agentic server. It assumes Splunk Enterprise and Ollama are already reachable inside the same approved network boundary.

## Prerequisites

- Ubuntu or a comparable Linux distribution
- Python 3.10 or newer
- Network reachability from ARIA to:
  - Splunk's management/search API;
  - the local Ollama API
- A dedicated Splunk account with the minimum read-only search permissions needed for approved indexes
- At least one local Ollama chat model
- An embedding model for semantic field matching is recommended

## Install from source

```bash
mkdir -p ~/aria-pattern-b
cd ~/aria-pattern-b
```

Copy the repository contents into that directory, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
```

Populate `.env` using [Configuration](CONFIGURATION.md). Never commit the populated file.

## Validate before starting

```bash
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
python validate_product.py
python validate_runtime.py
python aria_safe_startup_check.py
python validate_v3_acceptance.py --skip-live
```

Expected package marker:

```text
ARIA_V3_FINAL_ACCEPTANCE_STATUS=PASS
```

## Start interactively

Use separate terminals with the virtual environment active.

```bash
python aria_llm_gateway.py
```

```bash
python web_ui.py
```

The configured product bind address and port control browser access. Bind to loopback unless an approved protected interface or authenticated reverse proxy is used.

## Install system services

Review `scripts/install_systemd_services.sh` before running it. Confirm paths, service user, bind addresses and security controls match the target environment.

```bash
sudo bash scripts/install_systemd_services.sh
sudo systemctl daemon-reload
sudo systemctl enable --now aria-llm-gateway aria-web
```

Check status:

```bash
sudo systemctl status aria-llm-gateway aria-web --no-pager
python aria_health.py
```

## Connected acceptance

Use approved positive-control telemetry rather than assuming a public demonstration dataset:

```bash
python scripts/live_v3_acceptance.py \
  --build-question 'Build portable and deployment-qualified SPL for an approved security behaviour. Use the connected Splunk catalogue and observed schema, and do not execute the final SPL.' \
  --investigation-question 'Investigate an approved positive-control hypothesis using live Splunk evidence. Execute only safe read-only SPL and report evidence gaps.' \
  --conversation-question 'What is MITRE ATLAS?' \
  --conversation-followup-question 'How can a SOC use that framework to monitor AI-enabled systems with Splunk?'

python validate_v3_acceptance.py
```

Required connected markers are documented in [V3_ACCEPTANCE.md](V3_ACCEPTANCE.md).

## Upgrade or transactional deployment

For a checksum-verified runtime archive:

```bash
python scripts/deploy_v3_release.py \
  --archive /approved/path/aria-v3.0.0-rc11.tar \
  --target ~/aria-pattern-b \
  --no-restart
```

Restart services only after the deployment script passes. The script creates a rollback checkpoint and restores it when a post-copy validation fails.
