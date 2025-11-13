#!/bin/bash
# §7.1 TPC-H Benchmarks (Figure 4, Table 2)
# Runs TPC-H queries Q1, Q6, Q12 with radix 2, 4, 8
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
echo "[TPC-H] Running TPC-H benchmarks..."
"$BIN_DIR/benchmark/tpch" $BENCH_FLAG 2>&1 | tee "$RESULTS_DIR/tpch.log"
echo "[TPC-H] Done. Results in tpch_results.csv"
