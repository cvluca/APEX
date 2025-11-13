#!/bin/bash
#
# run.sh - Run APEX benchmarks
#
# Usage:
#   ./run.sh           # Full reproduction (15+ hours, 32GB+ RAM)
#   ./run.sh --quick   # Quick validation (~15-30 min, 8GB+ RAM)
#
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_DIR/build/bin"
QUICK=false
FAILED=0

for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=true ;;
  esac
done

if $QUICK; then
  MODE="quick"
  RESULTS_DIR="$SCRIPT_DIR/results_quick"
  BENCH_FLAG="--quick"
else
  MODE="full"
  RESULTS_DIR="$SCRIPT_DIR/results_full"
  BENCH_FLAG=""
fi

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/*.csv

echo "============================================"
if $QUICK; then
  echo "APEX Artifact - Quick Validation Mode"
  echo "This runs scaled-down experiments for fast verification."
  echo "For full paper reproduction, run without --quick."
else
  echo "APEX Artifact - Full Benchmark Suite"
fi
echo "============================================"
echo "Results will be saved to: $RESULTS_DIR"
echo "Start time: $(date)"
echo ""

run_benchmark() {
  local name="$1"
  local label="$2"
  shift 2

  echo "--------------------------------------------"
  echo "$label"
  echo "Start: $(date)"
  echo "--------------------------------------------"
  cd "$RESULTS_DIR"
  if "$@" 2>&1 | tee "$RESULTS_DIR/${name}.log"; then
    echo "[PASS] $name"
  else
    echo "[FAIL] $name (exit code: $?)"
    FAILED=$((FAILED + 1))
  fi
  echo "[$name] Completed at $(date)"
  echo ""
}

# §7.1 TPC-H Benchmarks (Figure 4, Table 2)
run_benchmark "tpch" "[1/7] TPC-H queries Q1/Q6/Q12 (§7.1)" \
    "$BIN_DIR/benchmark/tpch" $BENCH_FLAG

# §7.1 Hybrid Queries (Figure 5, Tables 3, 4)
if $QUICK; then
  run_benchmark "hybrid_queries" "[2/7] Hybrid queries HQ1/HQ2 (§7.1)" \
      "$BIN_DIR/benchmark/hybrid_queries" --quick
else
  for LOG_N in 12 14 16; do
    RING_DIM=$((1 << LOG_N))
    echo "--------------------------------------------"
    echo "[2/7] Hybrid queries HQ1/HQ2 with RingDim=2^${LOG_N} (${RING_DIM} slots)"
    echo "Start: $(date)"
    echo "--------------------------------------------"
    cd "$RESULTS_DIR"
    if "$BIN_DIR/benchmark/hybrid_queries" --ring-dim "$RING_DIM" 2>&1 | tee -a "$RESULTS_DIR/hybrid_queries.log"; then
      echo "[PASS] hybrid_queries RingDim=2^${LOG_N}"
    else
      echo "[FAIL] hybrid_queries RingDim=2^${LOG_N} (exit code: $?)"
      FAILED=$((FAILED + 1))
    fi
    echo "[hybrid_queries] RingDim=2^${LOG_N} completed at $(date)"
    echo ""
  done
fi

# §7.2 Storage Analysis (Tables 5, 6)
run_benchmark "ciphertext_size" "[3/7] Ciphertext storage analysis (§7.2)" \
    "$BIN_DIR/benchmark/ciphertext-size"

# §7.3 Numeric Comparison (Figure 6)
run_benchmark "comparison" "[4/7] Numeric comparison microbenchmarks (§7.3)" \
    "$BIN_DIR/benchmark/comparison" $BENCH_FLAG

# §7.3 String Pattern Matching (Figures 7, 8)
run_benchmark "pattern_match" "[5/7] String pattern matching (§7.3)" \
    "$BIN_DIR/benchmark/pattern_match"

# §7.4 Lazy Carry Propagation (Figure 9, Table 7)
run_benchmark "lazy_carry" "[6/7] Lazy carry propagation (§7.4)" \
    "$BIN_DIR/benchmark/lazy_carry" $BENCH_FLAG

# Correctness tests
run_benchmark "test_string" "[7/7] Running correctness tests" \
    "$BIN_DIR/tests/string"

echo "============================================"
if [ "$FAILED" -eq 0 ]; then
  echo "All benchmarks completed successfully!"
else
  echo "Benchmarks completed with $FAILED failure(s)."
  echo "Check logs in $RESULTS_DIR for details."
fi
echo "End time: $(date)"
echo "Results saved to: $RESULTS_DIR"
echo "============================================"

# Generate plots from benchmark results
echo ""
echo "--------------------------------------------"
echo "Generating plots from results..."
echo "--------------------------------------------"
PLOT_DIR="$SCRIPT_DIR/plot"

if ! command -v python3 &> /dev/null; then
  echo "[skip] python3 not found. Install Python 3 to generate plots."
else
  python3 "$PLOT_DIR/plot_all.py" "$RESULTS_DIR"
fi

if $QUICK; then
  echo ""
  echo "NOTE: Quick mode uses small ring dimensions (N=2^7) with minimal"
  echo "SIMD parallelism. Absolute numbers will differ from the paper."
  echo "With low parallelism, fixed overheads (e.g., key switching in carry"
  echo "propagation) are amplified, so trends for higher-radix configs"
  echo "(especially 8-bit) may appear distorted. This is expected."
  echo "Run without --quick for full reproduction with paper parameters."
fi

exit $FAILED
