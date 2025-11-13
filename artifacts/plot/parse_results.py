"""Parse benchmark CSV outputs and transform them into plot-ready CSV format.

Usage:
    python parse_results.py <results_dir> [--output-dir <output_dir>]

    results_dir: directory containing raw benchmark CSV files (default: artifacts/results)
    output_dir:  directory to write plot-ready CSVs (default: artifacts/plot/data)

Expected input files in results_dir:
    tpch_results.csv
    hybrid_queries_q1_results.csv
    hybrid_queries_q2_results.csv
    comparison_results.csv
    benchmark_test1_varying_string_length.csv
    benchmark_test2_varying_query_length.csv
    benchmark_test3_varying_any1_wildcards.csv
    benchmark_test4_varying_star_wildcards.csv
    lazy_carry_results.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------------------------
# Radix → display name mappings (must match plot scripts' LEGEND_NAMES keys)
# ---------------------------------------------------------------------------

# tpch.py / precision_latency.py use "APEX (Xb)" naming
# CSV radix column contains the actual base value: 2, 4, 8
RADIX_TO_TPCH = {2: "APEX (2b)", 4: "APEX (3b)", 8: "APEX (4b)"}

# hq.py uses "APEX-Xbit" naming
RADIX_TO_HQ = {2: "APEX-2bit", 4: "APEX-4bit", 8: "APEX-8bit"}

# keyword_wildcards.py uses "APEX (X-bit)" naming
RADIX_TO_KW = {2: "APEX (2-bit)", 4: "APEX (4-bit)", 8: "APEX (8-bit)"}

# carry_propagation.py uses "APEX (Xb) RB/NoRB" naming
RADIX_TO_CARRY_RB = {2: "APEX (2b) RB", 4: "APEX (4b) RB", 8: "APEX (8b) RB"}
RADIX_TO_CARRY_NORB = {2: "APEX (2b) NoRB", 4: "APEX (4b) NoRB", 8: "APEX (8b) NoRB"}


def radix_display(radix: int) -> int:
    """Map radix value (1,2,3) to bit width for display name lookups."""
    return radix


def parse_tpch(results_dir: Path, output_dir: Path) -> None:
    """tpch_results.csv → data/tpch.csv

    Input columns: query_name, ring_dim, radix, ..., total_time_ms
    Output: Query, APEX (2b), APEX (3b), APEX (4b)
    """
    src = results_dir / "tpch_results.csv"
    if not src.exists():
        print(f"[skip] {src.name} not found", file=sys.stderr)
        return

    df = pd.read_csv(src)
    pivot = df.pivot_table(
        index="query_name", columns="radix", values="total_time_ms", aggfunc="mean"
    )
    pivot = pivot.rename(columns=RADIX_TO_TPCH)
    pivot.index.name = "Query"
    pivot = pivot.reset_index()

    # Ensure query order
    order = ["Q1", "Q6", "Q12"]
    pivot["Query"] = pd.Categorical(pivot["Query"], categories=order, ordered=True)
    pivot = pivot.sort_values("Query").reset_index(drop=True)

    out = output_dir / "tpch.csv"
    pivot.to_csv(out, index=False)
    print(f"[ok] {out}")


def parse_hq(results_dir: Path, output_dir: Path) -> None:
    """hybrid_queries_q{1,2}_results.csv → data/hq1.csv, data/hq2.csv

    Output: Records, APEX-2bit, APEX-4bit, APEX-8bit
    """
    for qnum, filename in [("1", "hybrid_queries_q1_results.csv"),
                            ("2", "hybrid_queries_q2_results.csv")]:
        src = results_dir / filename
        if not src.exists():
            print(f"[skip] {filename} not found", file=sys.stderr)
            continue

        df = pd.read_csv(src)

        # For Q2, filter to only one mode (lazy or eager)
        if "mode" in df.columns:
            # Prefer lazy; fall back to eager
            if "lazy" in df["mode"].values:
                df = df[df["mode"] == "lazy"]
            else:
                df = df[df["mode"] == "eager"]

        pivot = df.pivot_table(
            index="ring_dim", columns="radix", values="total_time_ms", aggfunc="mean"
        )
        pivot = pivot.rename(columns=RADIX_TO_HQ)
        pivot.index.name = "Records"
        pivot = pivot.sort_index().reset_index()

        out = output_dir / f"hq{qnum}.csv"
        pivot.to_csv(out, index=False)
        print(f"[ok] {out}")


def parse_comparison(results_dir: Path, output_dir: Path) -> None:
    """comparison_results.csv → data/precision_latency_gt.csv, data/precision_latency_eq.csv

    Output: precision, APEX (2b), APEX (3b), APEX (4b)
    """
    src = results_dir / "comparison_results.csv"
    if not src.exists():
        print(f"[skip] {src.name} not found", file=sys.stderr)
        return

    df = pd.read_csv(src)

    type_map = {
        "greater": "precision_latency_gt.csv",
        "equal": "precision_latency_eq.csv",
    }

    for comp_type, out_name in type_map.items():
        subset = df[df["comparison_type"] == comp_type]
        if subset.empty:
            print(f"[skip] No {comp_type} data in {src.name}", file=sys.stderr)
            continue

        pivot = subset.pivot_table(
            index="precision", columns="radix", values="avg_time_ms", aggfunc="mean"
        )
        pivot = pivot.rename(columns=RADIX_TO_TPCH)
        pivot.index.name = "precision"
        pivot = pivot.sort_index().reset_index()

        out = output_dir / out_name
        pivot.to_csv(out, index=False)
        print(f"[ok] {out}")


def parse_pattern_match(results_dir: Path, output_dir: Path) -> None:
    """benchmark_testN_*.csv → data/varying_*.csv

    Output: <x_col>, APEX (2-bit), APEX (4-bit), APEX (8-bit)
    """
    tests = [
        ("benchmark_test1_varying_string_length.csv", "varying_string_length.csv",
         "string_length", "length"),
        ("benchmark_test2_varying_query_length.csv", "varying_query_length.csv",
         "query_length", "length"),
        ("benchmark_test3_varying_any1_wildcards.csv", "varying_any1_wildcards.csv",
         "num_wildcards", "wildcards"),
        ("benchmark_test4_varying_star_wildcards.csv", "varying_star_wildcards.csv",
         "num_wildcards", "wildcards"),
    ]

    for in_name, out_name, x_col, out_x_col in tests:
        src = results_dir / in_name
        if not src.exists():
            print(f"[skip] {in_name} not found", file=sys.stderr)
            continue

        df = pd.read_csv(src)

        # Test 2 records query_length including '%' delimiters (+2); strip them
        if x_col == "query_length":
            df[x_col] = df[x_col] - 2

        # per_string_time_ms is the amortized per-string latency
        pivot = df.pivot_table(
            index=x_col, columns="radix", values="per_string_time_ms", aggfunc="mean"
        )
        pivot = pivot.rename(columns=RADIX_TO_KW)
        pivot.index.name = out_x_col
        pivot = pivot.sort_index().reset_index()

        out = output_dir / out_name
        pivot.to_csv(out, index=False)
        print(f"[ok] {out}")


def parse_lazy_carry(results_dir: Path, output_dir: Path) -> None:
    """lazy_carry_results.csv → data/carry_propagation.csv

    Output: operations, APEX (2b) RB, APEX (2b) NoRB, ..., APEX (8b) NoRB
    """
    src = results_dir / "lazy_carry_results.csv"
    if not src.exists():
        print(f"[skip] {src.name} not found", file=sys.stderr)
        return

    df = pd.read_csv(src)

    # Filter to addition test only (the carry propagation plot)
    if "test_type" in df.columns:
        df = df[df["test_type"] == "addition"]

    # Create a combined key: radix + balance
    def make_col_name(row: pd.Series) -> str:
        r = row["radix"]
        rb = row["use_balance"]
        if rb == "yes":
            return RADIX_TO_CARRY_RB.get(r, f"radix={r} RB")
        else:
            return RADIX_TO_CARRY_NORB.get(r, f"radix={r} NoRB")

    df["series"] = df.apply(make_col_name, axis=1)

    pivot = df.pivot_table(
        index="operation_count", columns="series", values="total_time_ms", aggfunc="mean"
    )
    pivot.index.name = "operations"
    pivot = pivot.sort_index().reset_index()

    # Reorder columns
    col_order = ["operations"]
    for r in [2, 4, 8]:
        rb = RADIX_TO_CARRY_RB.get(r)
        norb = RADIX_TO_CARRY_NORB.get(r)
        if rb and rb in pivot.columns:
            col_order.append(rb)
        if norb and norb in pivot.columns:
            col_order.append(norb)
    pivot = pivot[[c for c in col_order if c in pivot.columns]]

    out = output_dir / "carry_propagation.csv"
    pivot.to_csv(out, index=False)
    print(f"[ok] {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse benchmark CSVs into plot-ready format")
    parser.add_argument(
        "results_dir", nargs="?", default=None,
        help="Directory containing raw benchmark CSV files",
    )
    parser.add_argument(
        "--output-dir", "-o", default=None,
        help="Directory to write plot-ready CSVs (default: <script_dir>/data)",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent

    if args.results_dir:
        results_dir = Path(args.results_dir)
    else:
        results_dir = script_dir.parent / "results"

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = script_dir / "data"

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Input:  {results_dir}")
    print(f"Output: {output_dir}")
    print()

    parse_tpch(results_dir, output_dir)
    parse_hq(results_dir, output_dir)
    parse_comparison(results_dir, output_dir)
    parse_pattern_match(results_dir, output_dir)
    parse_lazy_carry(results_dir, output_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
