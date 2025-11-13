#!/bin/bash
# §7.1 Hybrid Queries (Figure 5, Tables 3, 4)
# Runs HQ1 and HQ2 with lazy/eager carry comparison
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
  mkdir -p "$RESULTS_DIR"
  cd "$RESULTS_DIR"
  echo "[Hybrid] Running hybrid query benchmarks (quick)..."
  "$BIN_DIR/benchmark/hybrid_queries" --quick 2>&1 | tee "$RESULTS_DIR/hybrid_queries.log"
else
  RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/../results_full}"
  mkdir -p "$RESULTS_DIR"
  cd "$RESULTS_DIR"
  for LOG_N in 12 14 16; do
    RING_DIM=$((1 << LOG_N))
    echo "[Hybrid] Running hybrid queries with RingDim=2^${LOG_N} (${RING_DIM} slots)..."
    "$BIN_DIR/benchmark/hybrid_queries" --ring-dim "$RING_DIM" 2>&1 | tee -a "$RESULTS_DIR/hybrid_queries.log"
  done
fi
echo "[Hybrid] Done. Results in hybrid_queries_q1_results.csv and hybrid_queries_q2_results.csv"
