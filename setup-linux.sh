#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3 was not found. Set PYTHON_BIN to your Python executable." >&2
  exit 1
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip
if ! "$VENV_DIR/bin/python" -m pip install --upgrade --force-reinstall -r requirements.txt; then
  cat >&2 <<'EOF'

The exact model dependencies could not be installed on this Linux architecture.
Do not ignore scikit-learn's InconsistentVersionWarning: serialized estimators are
not supported across scikit-learn versions.

Install versions available for this machine, retrain, and regenerate replay data:
  .venv/bin/python -m pip install Flask waitress numpy pandas scikit-learn joblib
  .venv/bin/python pqconnect/train.py --data-dir pqconnect/data
  .venv/bin/python build_replay.py --classical-csv pqconnect/reference_data/s1_ECDSA-SHA256_signed-by_ECDSA-SHA256.csv
  .venv/bin/python environment_check.py
EOF
  exit 1
fi

"$VENV_DIR/bin/python" environment_check.py
"$VENV_DIR/bin/python" -m pip check
cat <<EOF

Setup complete. Start PQConnect with:
  $VENV_DIR/bin/python app.py --demo
EOF
