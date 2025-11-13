#!/bin/bash
# §7.4 Lazy Carry Propagation (Figure 9, Table 7)
# Tests carry propagation after additions and multiplications
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
echo "[LazyCarry] Running lazy carry propagation benchmarks..."
"$BIN_DIR/benchmark/lazy_carry" $BENCH_FLAG 2>&1 | tee "$RESULTS_DIR/lazy_carry.log"
echo "[LazyCarry] Done. Results in lazy_carry_results.csv"
