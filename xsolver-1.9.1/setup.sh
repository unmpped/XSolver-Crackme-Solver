set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="${XSOLVER_ENV_DIR:-$HOME/.local/share/xsolver/venv}"
MARKER="$ENV_DIR/.xsolver-install-ok"
if [[ -f "$MARKER" && -x "$ENV_DIR/bin/python" ]]; then
  exit 0
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Use Ubuntu or Debian for automatic setup." >&2
  exit 2
fi
sudo -v
ARCH="$(dpkg --print-architecture)"
if [[ "$ARCH" == "amd64" ]]; then
  sudo dpkg --add-architecture i386
fi
sudo apt-get update
PACKAGES=(python3 python3-venv python3-pip python3-dev build-essential mingw-w64 wine wine64 xvfb valgrind)
if [[ "$ARCH" == "amd64" ]]; then
  PACKAGES+=(wine32:i386)
fi
sudo apt-get install -y "${PACKAGES[@]}"
mkdir -p "$(dirname "$ENV_DIR")"
python3 -m venv "$ENV_DIR"
"$ENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$ENV_DIR/bin/python" -m pip install -e "$ROOT"
printf 'installed\n' > "$MARKER"
