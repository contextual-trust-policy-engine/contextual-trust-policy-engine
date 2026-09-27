#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q -e ".[dev]"
if [ -d "../zero-trust-agent-benchmark" ]; then
  python -m pip install -q -e "../zero-trust-agent-benchmark"
fi
ruff check . && ruff format --check .
mypy src
pytest -q --cov=contextual_trust_policy_engine --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
