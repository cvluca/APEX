#!/usr/bin/env python3
"""Parse benchmark results and generate all plots.

Usage:
    python plot_all.py <results_dir>
    python plot_all.py               # defaults to artifacts/results

This script:
  0. Bootstraps a Python venv with required packages (if needed)
  1. Parses raw benchmark CSVs into plot-ready format (→ data/)
  2. Runs all plot scripts to generate PDFs (→ output/)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Venv bootstrap – ensures matplotlib/pandas/etc. are available
# ---------------------------------------------------------------------------

def _in_venv() -> bool:
    """Return True if we're already running inside our managed venv."""
    return sys.prefix != sys.base_prefix


def _bootstrap_venv() -> None:
    """Create a venv, install dependencies, and re-exec this script inside it."""
    venv_dir = SCRIPT_DIR / ".venv"
    installed_marker = venv_dir / ".installed"
    requirements = SCRIPT_DIR / "requirements.txt"
    venv_python = venv_dir / "bin" / "python"

    if installed_marker.exists() and venv_python.exists():
        # Venv exists and deps installed – re-exec with venv python
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)

    print("Setting up Python virtual environment...")
    subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
    subprocess.check_call(
        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "-q"]
    )
    if requirements.exists():
        subprocess.check_call(
            [str(venv_python), "-m", "pip", "install", "-r", str(requirements), "-q"]
        )
    installed_marker.touch()

    # Re-exec this script with the venv python
    os.execv(str(venv_python), [str(venv_python)] + sys.argv)


if not _in_venv():
    _bootstrap_venv()
    # _bootstrap_venv calls os.execv and never returns

PLOT_SCRIPTS = [
    "tpch",
    "hq",
    "precision_latency",
    "keyword_wildcards",
    "carry_propagation",
]


def run_parse(results_dir: str) -> bool:
    """Run parse_results.py to transform benchmark CSVs."""
    print("=" * 60)
    print("Step 1: Parsing benchmark results")
    print("=" * 60)

    data_dir = os.environ.get("APEX_DATA_DIR", "")
    cmd = [sys.executable, str(SCRIPT_DIR / "parse_results.py"), results_dir]
    if data_dir:
        cmd += ["--output-dir", data_dir]
    ret = subprocess.run(cmd, cwd=SCRIPT_DIR)
    if ret.returncode != 0:
        print("[error] parse_results.py failed", file=sys.stderr)
        return False
    return True


def run_plots() -> bool:
    """Run each plot script."""
    print()
    print("=" * 60)
    print("Step 2: Generating plots")
    print("=" * 60)

    success = True
    for name in PLOT_SCRIPTS:
        script = SCRIPT_DIR / f"{name}.py"
        if not script.exists():
            print(f"[skip] {name}.py not found")
            continue

        print(f"\n--- {name} ---")
        ret = subprocess.run(
            [sys.executable, str(script)],
            cwd=SCRIPT_DIR,
        )
        if ret.returncode != 0:
            print(f"[warn] {name}.py exited with code {ret.returncode}")
            success = False

    return success


def _derive_suffix(results_dir: str) -> str:
    """Derive a suffix like '_quick' or '_full' from the results directory name."""
    name = Path(results_dir).name
    for tag in ("_quick", "_full"):
        if name.endswith(tag):
            return tag
    return ""


def main() -> None:
    results_dir = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else str(SCRIPT_DIR.parent / "results_full")

    suffix = _derive_suffix(results_dir)
    data_dir = SCRIPT_DIR / f"data{suffix}"
    output_dir = SCRIPT_DIR / f"output{suffix}"

    print(f"Results directory: {results_dir}")
    print(f"Data directory:    {data_dir}")
    print(f"Output directory:  {output_dir}")
    print()

    # Pass directories to parse and plot scripts
    os.environ["APEX_DATA_DIR"] = str(data_dir)
    os.environ["APEX_OUTPUT_DIR"] = str(output_dir)

    if not run_parse(results_dir):
        sys.exit(1)

    if not run_plots():
        print("\n[warn] Some plots failed (likely missing data).")
        sys.exit(1)

    print()
    print("=" * 60)
    print(f"All plots saved to: {output_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()
