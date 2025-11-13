#!/bin/bash
# §7.3 String Pattern Matching (Figures 7, 8)
# Tests substring matching and wildcard pattern matching
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
echo "[Pattern] Running string pattern matching benchmarks..."
"$BIN_DIR/benchmark/pattern_match" 2>&1 | tee "$RESULTS_DIR/pattern_match.log"
echo "[Pattern] Done. Results in benchmark_test*.csv"
