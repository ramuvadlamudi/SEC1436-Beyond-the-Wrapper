#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "${1:-.}" && pwd)"
PYTHON="$ROOT/.venv/bin/python"
RUN_USER="${SUDO_USER:-$USER}"

if [[ ! -x "$PYTHON" ]]; then
  echo "Missing virtualenv Python: $PYTHON" >&2
  exit 1
fi

sudo tee /etc/systemd/system/aria-web.service >/dev/null <<EOF
[Unit]
Description=ARIA Evidence-First SOC Copilot Web UI
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$ROOT
Environment=PYTHONPATH=$ROOT
ExecStart=$PYTHON $ROOT/web_ui.py --host 0.0.0.0 --port 8501
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/aria-llm-gateway.service >/dev/null <<EOF
[Unit]
Description=ARIA Local LLM Gateway
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$ROOT
Environment=PYTHONPATH=$ROOT
ExecStart=$PYTHON $ROOT/aria_llm_gateway.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now aria-llm-gateway aria-web
systemctl status aria-llm-gateway aria-web --no-pager
