set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="${XSOLVER_ENV_DIR:-$HOME/.local/share/xsolver/venv}"
MARKER="$ENV_DIR/.xsolver-install-ok"
if [[ ! -x "$ENV_DIR/bin/python" || ! -f "$MARKER" ]]; then
  bash "$ROOT/setup.sh"
fi
cd "$ROOT"
if [[ $# -eq 0 ]]; then
  set -- tui "$ROOT"
fi
PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" exec "$ENV_DIR/bin/python" -m xsolver "$@"
