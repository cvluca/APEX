# APEX: Artifact Evaluation

This document describes the artifact for the paper **"APEX: Accurate Parallel Expressive Homomorphic Execution for Encrypted Databases"** (IEEE S&P 2026).

## Overview

APEX is the first FHE-based database system that jointly achieves efficient SIMD execution and precise SQL semantics within a single BGV/BFV framework. The artifact contains the complete source code, benchmarks, and scripts to reproduce the experimental results presented in the paper.

**Key components:**
- **UniCo**: Semantics-aware unified encoding (PSR for integers, columnar alignment for strings)
- **RAHC**: Range-Aware Homomorphic Comparison (complexity depends on segment base B, not plaintext modulus p)
- **PLCP**: Parallel Lazy Carry Propagation (defers normalization until needed)

## Claims

The following claims from the paper can be verified with this artifact:

| # | Claim | Section | Experiment | Expected Result |
|---|-------|---------|-----------|----------------|
| C1 | APEX efficiently executes TPC-H queries on encrypted data | §7.1 | TPC-H benchmarks | Correct results on Q1, Q6, Q12; performance trends and breakdown match **Figure 4, Table 2** |
| C2 | APEX supports hybrid queries combining string matching and arithmetic | §7.1 | Hybrid queries | Correct results on HQ1/HQ2; performance trends and breakdown match **Figure 5, Tables 3, 4** |
| C3 | APEX achieves compact ciphertext storage for strings and integers | §7.2 | Storage analysis | 8-bit uses least storage, 2-bit uses most among APEX configs; size ratios match **Tables 5, 6** |
| C4 | APEX performs efficient homomorphic comparisons via RAHC | §7.3 | Comparison benchmarks | Latency scales with segment base B, independent of plaintext modulus p; trends match **Figure 6** |
| C5 | APEX supports efficient substring and wildcard pattern matching | §7.3 | Pattern matching | Matching latency scales linearly with pattern/string length; trends match **Figures 7, 8** |
| C6 | APEX achieves effective lazy carry propagation for consecutive arithmetic | §7.4 | Lazy carry benchmarks | Amortized cost reduces with more additions; range balancing improves performance; trends match **Figure 9, Table 7** |

> [!NOTE]
> This artifact includes only the APEX implementation. Relative speedup claims should be validated against the baseline numbers reported in the paper (from prior papers and our same-hardware measurements).

## Hardware Requirements

- **CPU**: Any modern processor (paper results obtained on AMD EPYC 7D12)
- **RAM**: 32 GB (full reproduction) / 4 GB minimum (quick validation)
- **Disk**: 25 GB free space (for Docker image, build artifacts, and OpenFHE)
- **OS**: Any OS with Docker support, or Linux/macOS with native build tools
- **Estimated runtime**: 15+ hours (full reproduction, depends on CPU) / 15-30 minutes (quick validation)

## Getting Started

### Option 1: Docker (Recommended)

```bash
# Quick validation (~15-30 min)
cd artifacts && docker compose run --rm quick

# Full reproduction (15+ hours, depends on CPU)
cd artifacts && docker compose run --rm full
```

> [!IMPORTANT]
> On macOS/Windows, Docker typically runs inside a VM with limited memory. Ensure the VM is allocated at least 32 GB of RAM (e.g., in Docker Desktop: **Settings → Resources**; for Colima: `colima start --memory 32`). If a benchmark is killed during execution, insufficient VM memory is the most likely cause. On Linux, Docker uses host memory directly and no adjustment is needed.

Results (CSV) and plots (PDF) are automatically saved to the host under `artifacts/results_{quick,full}/` and `artifacts/plot/output_{quick,full}/`.

### Option 2: Manual Installation

**Prerequisites:**
```bash
# Ubuntu 24.04
sudo apt-get update
sudo apt-get install -y build-essential g++-13 cmake git python3
```

**Build:**
```bash
git clone --recursive https://github.com/cvluca/APEX.git
cd APEX
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DWITH_OPENMP=OFF
cmake --build build -j$(nproc)
```

**Run:**
```bash
# Quick validation
./artifacts/run.sh --quick

# Full reproduction
./artifacts/run.sh
```

### Generating Plots

`run.sh` automatically generates plots after benchmarks complete (requires Python 3). The plot script bootstraps a virtual environment and installs dependencies automatically.

To regenerate plots manually:
```bash
# From full results (default)
./artifacts/plot/plot_all.py

# From quick results
./artifacts/plot/plot_all.py artifacts/results_quick
```

Generated plots are saved to `artifacts/plot/output_{quick,full}/` as PDF files.

## Experiment Details

Each experiment can be run individually. With Docker, override the command:
```bash
cd artifacts && docker compose run --rm quick ./artifacts/scripts/<script>.sh --quick
cd artifacts && docker compose run --rm full ./artifacts/scripts/<script>.sh
```

### §7.1 TPC-H Benchmarks (Figure 4, Table 2)
- **Run individually:**
  ```bash
  ./artifacts/scripts/run_tpch.sh [--quick]
  ```
- **What it tests**: Queries Q1, Q6, Q12 on encrypted data with N=2^16 slots
- **Configurations**: Radix 2-bit, 4-bit, 8-bit segments
- **Output**: `artifacts/results_{quick,full}/tpch_results.csv` with per-query filtering and aggregation times
- **Log**: `artifacts/results_{quick,full}/tpch.log`
- **Key metric**: Total query latency (ms) and amortized time per row
- **Plot**: `artifacts/plot/output_{quick,full}/tpch.pdf`

### §7.1 Hybrid Queries (Figure 5, Tables 3, 4)
- **Run individually:**
  ```bash
  ./artifacts/scripts/run_hybrid.sh [--quick]
  ```
- **What it tests**: HQ1 (string matching + IN predicate), HQ2 (string + arithmetic + comparison)
- **Configurations**: Three ring dimensions (N=2^12, 2^14, 2^16) with radix 2/4/8; HQ2 with lazy vs eager carry
- **Output**: `artifacts/results_{quick,full}/hybrid_queries_q1_results.csv`, `artifacts/results_{quick,full}/hybrid_queries_q2_results.csv`
- **Log**: `artifacts/results_{quick,full}/hybrid_queries.log`
- **Key metric**: Detailed operation breakdown and total latency
- **Plots**: `artifacts/plot/output_{quick,full}/hq1.pdf`, `artifacts/plot/output_{quick,full}/hq2.pdf`

### §7.2 Storage Analysis (Tables 5, 6)
- **Run individually:**
  ```bash
  ./artifacts/scripts/run_storage.sh [--quick]
  ```
- **What it tests**: Ciphertext sizes for encrypted strings (Table 5) and encrypted integers (Table 6)
- **Configurations**: String analysis with radix 2/4/8 (length-16 strings); Integer analysis across precisions 8–64 bit with radix 2/4/8
- **Output**: Console output with per-configuration ciphertext sizes and summary comparison tables
- **Log**: `artifacts/results_{quick,full}/ciphertext_size.log`
- **Key metric**: Ciphertext size (MB) per configuration

### §7.3 Numeric Comparison (Figure 6)
- **Run individually:**
  ```bash
  ./artifacts/scripts/run_comparison.sh [--quick]
  ```
- **What it tests**: RAHC comparison latency across precisions (8-64 bit)
- **Configurations**: Relational (GT) and equality (EQ) comparisons, radix 2/4/8
- **Output**: `artifacts/results_{quick,full}/comparison_results.csv`
- **Log**: `artifacts/results_{quick,full}/comparison.log`
- **Key metric**: Average time per comparison (ms), depth consumed
- **Plots**: `artifacts/plot/output_{quick,full}/precision_latency_gt.pdf`, `artifacts/plot/output_{quick,full}/precision_latency_eq.pdf`

### §7.3 String Pattern Matching (Figures 7, 8)
- **Run individually:**
  ```bash
  ./artifacts/scripts/run_pattern.sh [--quick]
  ```
- **What it tests**: Substring matching (varying string/query lengths), wildcard matching (varying wildcard counts)
- **Output**: `artifacts/results_{quick,full}/benchmark_test1_*.csv` through `benchmark_test4_*.csv`
- **Log**: `artifacts/results_{quick,full}/pattern_match.log`
- **Key metric**: Per-string matching latency (ms)
- **Plots**: `artifacts/plot/output_{quick,full}/varying_string_length.pdf`, `artifacts/plot/output_{quick,full}/varying_query_length.pdf`, `artifacts/plot/output_{quick,full}/varying_any1_wildcards.pdf`, `artifacts/plot/output_{quick,full}/varying_star_wildcards.pdf`

### §7.4 Lazy Carry Propagation (Figure 9, Table 7)
- **Run individually:**
  ```bash
  ./artifacts/scripts/run_lazy_carry.sh [--quick]
  ```
- **What it tests**: Carry propagation cost after consecutive additions and multiplications
- **Configurations**: With/without range balancing, 1-50 operations
- **Output**: `artifacts/results_{quick,full}/lazy_carry_results.csv`
- **Log**: `artifacts/results_{quick,full}/lazy_carry.log`
- **Key metric**: Per-operation amortized carry cost (ms)
- **Plots**: `artifacts/plot/output_{quick,full}/carry_propagation_total.pdf`, `artifacts/plot/output_{quick,full}/carry_propagation_amortized.pdf`

## Interpreting Results

### Performance
- Relative speedups across APEX configurations (2-bit vs 4-bit vs 8-bit) should match paper trends
- 2-bit should be fastest, 8-bit slowest for filtering operations
- Amortized times should remain roughly constant between N=2^14 and N=2^16

### Correctness
Every benchmark verifies correctness by comparing encrypted computation results against plaintext reference values. Look for:
- `✓ Result is CORRECT!` in benchmark outputs
- `Expected count == Encrypted count` in query results
- No `✗ Result is INCORRECT!` messages

### Quick Mode Limitations
Quick mode (`run.sh --quick`) uses a small ring dimension (N=2^7) with minimal SIMD parallelism, so trends may appear distorted. Run `run.sh` without flags for accurate reproduction.

## File Structure

```
APEX/
├── ARTIFACT.md              # This file
├── Dockerfile               # Docker build for reproducible environment
├── artifacts/
│   ├── docker-compose.yml   # Docker Compose for quick/full experiments
│   ├── run.sh               # Run experiments (--quick for validation, default full)
│   ├── scripts/             # Individual experiment scripts
│   │   ├── run_tpch.sh
│   │   ├── run_hybrid.sh
│   │   ├── run_comparison.sh
│   │   ├── run_pattern.sh
│   │   ├── run_lazy_carry.sh
│   │   └── run_storage.sh
│   └── plot/                # Plotting pipeline
│       ├── plot_all.py      # One-click: parse results + generate all plots
│       ├── parse_results.py # Transform benchmark CSVs into plot-ready format
│       ├── tpch.py          # TPC-H bar chart
│       ├── hq.py            # Hybrid query scaling plots
│       ├── precision_latency.py  # Comparison latency plots
│       ├── keyword_wildcards.py  # Pattern matching plots
│       ├── carry_propagation.py  # Carry propagation plots
│       └── requirements.txt # Python dependencies (auto-installed)
├── include/                 # APEX header files
├── src/                     # APEX implementation
├── benchmark/               # Benchmark source code
├── tests/                   # Test suite
└── third-party/
    └── openfhe-development/ # OpenFHE library (git submodule)
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.
