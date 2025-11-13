#!/bin/bash
# §7.2 Storage Analysis (Tables 5, 6)
# Analyzes ciphertext sizes for string and integer data
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/../../build/bin" && pwd)"

QUICK=false
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=true ;;
  esac
done

if $QUICK; then
  RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/../results_quick}"
else
  RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/../results_full}"
fi

mkdir -p "$RESULTS_DIR"
cd "$RESULTS_DIR"
echo "[Storage] Running ciphertext storage analysis..."
"$BIN_DIR/benchmark/ciphertext-size" 2>&1 | tee "$RESULTS_DIR/ciphertext_size.log"
echo "[Storage] Done."
