"""Generate carry propagation plots (total and amortized latency)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import matplotlib.pyplot as plt
from matplotlib import ticker
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Configuration section
# ---------------------------------------------------------------------------

X_COLUMN = "operations"
Y_COLUMNS: Sequence[str] | None = None

LEGEND_NAMES: Mapping[str, str] = {
    "APEX (2b) RB": "APEX (2-bit)",
    "APEX (2b) NoRB": "APEX (2-bit) w/o RB",
    "APEX (4b) RB": "APEX (4-bit)",
    "APEX (4b) NoRB": "APEX (4-bit) w/o RB",
    "APEX (8b) RB": "APEX (8-bit)",
    "APEX (8b) NoRB": "APEX (8-bit) w/o RB",
}

SERIES_ORDER = [
    "APEX (2b) RB",
    "APEX (2b) NoRB",
    "APEX (4b) RB",
    "APEX (4b) NoRB",
    "APEX (8b) RB",
    "APEX (8b) NoRB",
]

PLOT_TITLE: str | None = None
X_LABEL = "Number of Operations"
Y_LABEL = "Latency (s)"
PLOT_STYLE = "seaborn-v0_8-paper"
FIG_SIZE = (2.2, 1.5)
STYLE_OVERRIDES = {
    "axes.titlesize": 4.8,
    "axes.labelsize": 4.8,
    "xtick.labelsize": 4.8,
    "ytick.labelsize": 4.8,
    "legend.fontsize": 4.2,
    "legend.title_fontsize": 4.2,
    "axes.labelpad": 0.6,
    "xtick.major.pad": 0.6,
    "ytick.major.pad": 0.6,
    "xtick.major.size": 1.2,
    "ytick.major.size": 1.2,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "lines.linewidth": 0.3,
    "lines.markersize": 1.2,
}
LINE_WIDTH = 0.7
MARKER_SIZE = 2.0

# Line and marker styles
SERIES_STYLES = {
    "APEX (2b) RB": {"linestyle": "-", "marker": "o", "markeredgewidth": 0.1},
    "APEX (2b) NoRB": {"linestyle": "--", "marker": "o", "markeredgewidth": 0.1},
    "APEX (4b) RB": {"linestyle": "-", "marker": "s", "markeredgewidth": 0.1},
    "APEX (4b) NoRB": {"linestyle": "--", "marker": "s", "markeredgewidth": 0.1},
    "APEX (8b) RB": {"linestyle": "-", "marker": "^", "markeredgewidth": 0.1},
    "APEX (8b) NoRB": {"linestyle": "--", "marker": "^", "markeredgewidth": 0.1},
}

# Dataset configuration
SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
OUTPUT_DIR = Path(os.environ.get("APEX_OUTPUT_DIR", SCRIPT_DIR / "output"))
DATA_DIR = Path(os.environ.get("APEX_DATA_DIR", SCRIPT_DIR / "data"))
INPUT_CSV = "carry_propagation.csv"
OUTPUT_PDF_TOTAL = "carry_propagation_total.pdf"
OUTPUT_PDF_AMORTIZED = "carry_propagation_amortized.pdf"


@dataclass
class PlotData:
    x: str
    ys: Sequence[str]
    frame: pd.DataFrame


def load_dataframe(csv_path: Path, dataset_label: str) -> PlotData | None:
    """Return a DataFrame for the provided CSV file."""

    tag = f"carry_propagation[{dataset_label}]"

    if not csv_path.exists():
        print(f"[{tag}] Missing CSV: {csv_path.name}", file=sys.stderr)
        return None

    frame = pd.read_csv(csv_path)

    if not frame.columns.size:
        print(f"[{tag}] CSV contains no columns.", file=sys.stderr)
        return None

    first_column = frame.columns[0]
    if first_column != X_COLUMN:
        frame = frame.rename(columns={first_column: X_COLUMN})

    y_columns = (
        list(Y_COLUMNS)
        if Y_COLUMNS
        else [
            column
            for column in frame.columns
            if column != X_COLUMN
            and column in LEGEND_NAMES
            and frame[column].dropna().any()
        ]
    )

    for column in (X_COLUMN, *y_columns):
        if column not in frame.columns:
            print(f"[{tag}] CSV missing required column: {column}", file=sys.stderr)
            return None

    numeric_columns = [X_COLUMN, *[column for column in y_columns if column != X_COLUMN]]
    original = frame[numeric_columns].copy()
    frame[numeric_columns] = frame[numeric_columns].apply(pd.to_numeric, errors="coerce")
    missing_input = original.isna() | original.eq("")
    non_numeric = (~missing_input) & frame[numeric_columns].isnull()
    non_numeric[X_COLUMN] = False
    if non_numeric.any().any():
        offenders: list[str] = []
        for column in non_numeric.columns:
            invalid = non_numeric.index[non_numeric[column]].tolist()
            if invalid:
                offenders.append(
                    f"{column} (rows {', '.join(str(i + 1) for i in invalid)})"
                )
        if offenders:
            print(
                f"[{tag}] CSV contains non-numeric values in columns: "
                + "; ".join(offenders),
                file=sys.stderr,
            )
            return None

    frame = frame.sort_values(by=X_COLUMN).reset_index(drop=True)
    if frame[X_COLUMN].isnull().any():
        print(f"[{tag}] CSV operations column contains missing values.", file=sys.stderr)
        return None

    return PlotData(x=X_COLUMN, ys=y_columns, frame=frame)


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def plot_lines(data: PlotData, output_path: Path, dataset_label: str, amortized: bool = False) -> None:
    plt.style.use(PLOT_STYLE)

    with plt.rc_context(STYLE_OVERRIDES):
        fig, ax = plt.subplots(figsize=FIG_SIZE)

        fig.patch.set_facecolor("white")
        ax.set_facecolor("white")

        plotted_columns = 0
        for column in SERIES_ORDER:
            if column not in data.ys:
                continue

            subset = data.frame[[data.x, column]].dropna()
            if subset.empty:
                continue

            # Calculate amortized values if needed, and convert ms to seconds
            y_values = subset[column].values / 1000.0  # Convert ms to s
            if amortized:
                y_values = y_values / subset[data.x].values

            style = SERIES_STYLES.get(column, {})

            ax.plot(
                subset[data.x],
                y_values,
                markersize=MARKER_SIZE,
                linewidth=LINE_WIDTH,
                label=LEGEND_NAMES.get(column, column),
                **style,
            )
            plotted_columns += 1

        if plotted_columns == 0:
            print(
                f"[{dataset_label}] No valid data to plot.",
                file=sys.stderr,
            )
            plt.close(fig)
            return

        if PLOT_TITLE:
            ax.set_title(PLOT_TITLE)

        ax.set_xlabel(X_LABEL)
        ax.set_ylabel(Y_LABEL)

        # Auto-scale x-axis from data
        x_vals = data.frame[data.x].dropna().values
        if len(x_vals) > 0:
            ax.set_xlim(-2, max(x_vals) + 2)
            xticks = sorted(data.frame[data.x].dropna().unique())
            ax.set_xticks(xticks)
        else:
            ax.set_xlim(-2, 52)

        # Auto-scale y-axis from the actually plotted values (ms→s, optionally amortized)
        y_max = 0
        for column in data.ys:
            subset = data.frame[[data.x, column]].dropna()
            if subset.empty:
                continue
            y_vals = subset[column].values / 1000.0
            if amortized:
                y_vals = y_vals / subset[data.x].values
            col_max = float(np.max(y_vals))
            if col_max > y_max:
                y_max = col_max
        y_max = y_max * 1.15 if y_max > 0 else 1.0
        # Generate nice round ticks
        if y_max > 50:
            step = float(np.ceil(y_max / 5 / 10) * 10)
        elif y_max > 1:
            step = float(np.ceil(y_max / 5))
        else:
            step = float(np.ceil(y_max / 5 * 100) / 100)
        if step == 0:
            step = 0.1
        fixed_ticks = [round(step * i, 4) for i in range(int(y_max / step) + 2)]
        ax.set_ylim(0, y_max)
        ax.yaxis.set_major_locator(ticker.FixedLocator(fixed_ticks))

        # Format y-axis with K abbreviations for thousands
        def _format_abbreviated(val: float, _: float) -> str:
            if val == 0:
                return "0"
            elif val >= 1_000:
                return f"{int(val / 1_000)}K"
            else:
                return f"{int(val)}"

        ax.yaxis.set_major_formatter(ticker.FuncFormatter(_format_abbreviated))
        ax.grid(False)

        for spine in ax.spines.values():
            spine.set_edgecolor("black")
            spine.set_linewidth(0.5)

        # Create legend
        handles, labels = ax.get_legend_handles_labels()
        handle_map = {label: handle for handle, label in zip(handles, labels)}
        ordered_labels = [
            LEGEND_NAMES.get(name, name)
            for name in SERIES_ORDER
            if LEGEND_NAMES.get(name, name) in handle_map
        ]
        if not ordered_labels:
            ordered_labels = labels

        legend_handles = [handle_map[label] for label in ordered_labels]

        # Set legend position based on whether it's amortized or total
        if amortized:
            legend_loc = "upper right"
            legend_bbox = (0.92, 0.96)
        else:
            legend_loc = "upper left"
            legend_bbox = (0.04, 0.96)

        legend = ax.legend(
            legend_handles,
            ordered_labels,
            frameon=True,
            loc=legend_loc,
            bbox_to_anchor=legend_bbox,
            borderaxespad=0.0,
            ncol=1,
            columnspacing=0.6,
            handlelength=1.6,
            handletextpad=0.4,
        )
        frame = legend.get_frame()
        frame.set_edgecolor("#cccccc")
        frame.set_linewidth(0.5)
        frame.set_facecolor("white")

        fig.subplots_adjust(left=0.24, right=0.94, bottom=0.22, top=0.96)
        ensure_output_dir(output_path.parent)
        fig.savefig(output_path, bbox_inches="tight", pad_inches=0.01, facecolor="white")
        plt.close(fig)

    try:
        pretty_path = output_path.relative_to(Path.cwd())
    except ValueError:
        pretty_path = output_path

    print(f"[{dataset_label}] Wrote figure to {pretty_path}")


def main() -> None:
    csv_path = DATA_DIR / INPUT_CSV
    dataset_label = "carry_propagation"

    data = load_dataframe(csv_path, dataset_label)
    if not data:
        sys.exit(1)

    # Generate total latency plot
    output_path_total = OUTPUT_DIR / OUTPUT_PDF_TOTAL
    plot_lines(data, output_path_total, f"{dataset_label}_total", amortized=False)

    # Generate amortized latency plot
    output_path_amortized = OUTPUT_DIR / OUTPUT_PDF_AMORTIZED
    plot_lines(data, output_path_amortized, f"{dataset_label}_amortized", amortized=True)


if __name__ == "__main__":
    main()
