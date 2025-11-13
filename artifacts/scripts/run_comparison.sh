#!/bin/bash
# §7.3 Numeric Comparison Microbenchmarks (Figure 6)
# Tests relational and equality comparison across precisions (8-64 bit)
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
  BENCH_FLAG="--quick"
else
  RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/../results_full}"
  BENCH_FLAG=""
fi

mkdir -p "$RESULTS_DIR"
cd "$RESULTS_DIR"
echo "[Comparison] Running numeric comparison benchmarks..."
"$BIN_DIR/benchmark/comparison" $BENCH_FLAG 2>&1 | tee "$RESULTS_DIR/comparison.log"
echo "[Comparison] Done. Results in comparison_results.csv"
