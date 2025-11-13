"""Generate TPC-H bar charts for records vs latency."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from math import log10
from pathlib import Path
from typing import Mapping, Sequence

import matplotlib.pyplot as plt
from matplotlib import ticker
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Configuration section
# ---------------------------------------------------------------------------

X_COLUMN = "Query"
Y_COLUMNS: Sequence[str] | None = None

LEGEND_NAMES: Mapping[str, str] = {
    "APEX (2b)": "APEX (2-bit)",
    "APEX (3b)": "APEX (4-bit)",
    "APEX (4b)": "APEX (8-bit)",
}
SERIES_ORDER = [
    "APEX (4b)",
    "APEX (3b)",
    "APEX (2b)",
]

# Order for plotting bars (reversed from legend order)
# These are the actual CSV column names
BAR_PLOT_ORDER = [
    "APEX (4b)",
    "APEX (3b)",
    "APEX (2b)",
]

PLOT_TITLE: str | None = None
X_LABEL = "Query"
Y_LABEL = "Latency (ms)"
PLOT_STYLE = "seaborn-v0_8-paper"
FIG_SIZE = (5.0, 2.8)
STYLE_OVERRIDES = {
    "axes.titlesize": 5.8,
    "axes.labelsize": 5.8,
    "xtick.labelsize": 5.8,
    "ytick.labelsize": 5.8,
    "legend.fontsize": 6.0,
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
    "hatch.linewidth": 0.3,
}

BAR_LABEL_FONTSIZE = 3.8

BAR_WIDTH = 0.14
BAR_EDGE_WIDTH = 0.3

# Dataset configuration.
SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
OUTPUT_DIR = Path(os.environ.get("APEX_OUTPUT_DIR", SCRIPT_DIR / "output"))
DATA_DIR = Path(os.environ.get("APEX_DATA_DIR", SCRIPT_DIR / "data"))
INPUT_CSV = "tpch.csv"
OUTPUT_PDF = "tpch.pdf"
QUERY_ORDER = ["Q1", "Q6", "Q12"]


@dataclass
class PlotData:
    x: str
    ys: Sequence[str]
    frame: pd.DataFrame


def load_dataframe(csv_path: Path, dataset_label: str) -> PlotData | None:
    """Return a DataFrame for the provided CSV file."""

    tag = f"records_latency[{dataset_label}]"

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

    numeric_columns = [column for column in y_columns if column != X_COLUMN]
    original = frame[numeric_columns].copy()
    frame[numeric_columns] = frame[numeric_columns].apply(pd.to_numeric, errors="coerce")
    missing_input = original.isna() | original.eq("")
    non_numeric = (~missing_input) & frame[numeric_columns].isnull()
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

    # Sort by custom query order if available
    if X_COLUMN == "Query" and "QUERY_ORDER" in globals():
        query_order = QUERY_ORDER
        frame[X_COLUMN] = pd.Categorical(frame[X_COLUMN], categories=query_order, ordered=True)
        frame = frame.sort_values(by=X_COLUMN).reset_index(drop=True)
        frame[X_COLUMN] = frame[X_COLUMN].astype(str)
    else:
        frame = frame.sort_values(by=X_COLUMN).reset_index(drop=True)

    if frame[X_COLUMN].isnull().any():
        print(f"[{tag}] CSV {X_COLUMN} column contains missing values.", file=sys.stderr)
        return None

    return PlotData(x=X_COLUMN, ys=y_columns, frame=frame)


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def plot_bars(data: PlotData, output_path: Path, dataset_label: str) -> None:
    plt.style.use(PLOT_STYLE)

    with plt.rc_context(STYLE_OVERRIDES):
        fig, ax = plt.subplots(figsize=FIG_SIZE)

        fig.patch.set_facecolor("white")
        ax.set_facecolor("white")

        # Get x values (Records)
        x_values = data.frame[data.x].values
        x_positions = np.arange(len(x_values))

        # Filter valid series
        valid_series = []
        for column in data.ys:
            subset = data.frame[[data.x, column]].dropna()
            if not subset.empty:
                valid_series.append(column)

        if not valid_series:
            print(
                f"[records_latency[{dataset_label}]] No valid data to plot.",
                file=sys.stderr,
            )
            plt.close(fig)
            return

        # Reorder valid_series according to BAR_PLOT_ORDER
        ordered_series = [
            col for col in BAR_PLOT_ORDER
            if col in valid_series
        ]
        # Add any series not in BAR_PLOT_ORDER
        for col in valid_series:
            if col not in ordered_series:
                ordered_series.append(col)

        n_series = len(ordered_series)
        bar_positions = []

        # Calculate bar positions for grouped bars
        total_width = BAR_WIDTH * n_series
        offset = -(total_width / 2) + (BAR_WIDTH / 2)

        # Plot bars for each series
        bars_by_series = {}
        for i, column in enumerate(ordered_series):
            positions = x_positions + offset + (i * BAR_WIDTH)
            values = data.frame[column].values

            # Add hatch pattern for APEX series
            hatch_pattern = None
            if "APEX (2b)" in column:
                hatch_pattern = "ooo"
            elif "APEX (3b)" in column:
                hatch_pattern = "ooo"
            elif "APEX (4b)" in column:
                hatch_pattern = "ooo"

            bars = ax.bar(
                positions,
                values,
                width=BAR_WIDTH,
                label=LEGEND_NAMES.get(column, column),
                edgecolor="black",
                linewidth=BAR_EDGE_WIDTH,
                hatch=hatch_pattern,
            )
            bars_by_series[column] = (positions, values, bars)

        # Add multiplier annotations on top of bars
        for x_idx in range(len(x_values)):
            # Get all values for this x position
            group_values = []
            group_positions = []
            group_series = []

            for column in ordered_series:
                if x_idx < len(data.frame):
                    val = data.frame[column].iloc[x_idx]
                    if pd.notna(val) and val > 0:
                        pos, vals, bars = bars_by_series[column]
                        group_values.append(val)
                        group_positions.append(pos[x_idx])
                        group_series.append(column)

            if not group_values:
                continue

            # Find tallest bar
            max_val = max(group_values)

            # Annotate each bar
            for val, pos, series in zip(group_values, group_positions, group_series):
                multiplier = max_val / val
                label_text = f"{multiplier:.0f}×" if multiplier >= 1.5 else "1×"

                # Position label above bar
                _, _, bars = bars_by_series[series]
                bar_height = val

                # Adjust horizontal offset for specific series
                x_offset = 0
                y_scale = 1.05
                if "APEX (2b)" in series or "APEX (3b)" in series:
                    x_offset = 0.015  # Shift slightly to the right
                if "APEX (3b)" in series:
                    y_scale = 1.18  # Shift slightly upward

                ax.text(
                    pos + x_offset,
                    bar_height * y_scale,
                    label_text,
                    ha="center",
                    va="bottom",
                    fontsize=BAR_LABEL_FONTSIZE,
                    color="black",
                )

        if PLOT_TITLE:
            ax.set_title(PLOT_TITLE)

        ax.set_xlabel(X_LABEL)
        ax.set_ylabel(Y_LABEL)

        # Format x-axis to show query names
        ax.set_xticks(x_positions)
        ax.set_xticklabels(x_values)
        ax.set_xlim(-0.6, len(x_values) - 0.4)

        # Set log scale on y-axis
        ax.set_yscale("log")

        # Determine appropriate y-axis ticks based on data range
        all_values = data.frame[ordered_series].values.flatten()
        all_values = all_values[~np.isnan(all_values)]
        min_data = all_values.min()
        max_data = all_values.max()
        min_exp = int(np.floor(np.log10(min_data)))
        max_exp = int(np.ceil(np.log10(max_data)))
        fixed_ticks = [10 ** i for i in range(min_exp, max_exp + 1)]
        ax.yaxis.set_major_locator(ticker.FixedLocator(fixed_ticks))
        Y_LIMITS = (10 ** min_exp, 10 ** max_exp)
        ax.set_ylim(*Y_LIMITS)

        def _format_power_of_ten(val: float, _: float) -> str:
            if val <= 0:
                return ""
            exponent = round(log10(val))
            if abs(val - 10 ** exponent) < 1e-8 and val in fixed_ticks:
                return rf"$10^{{{int(exponent)}}}$"
            return ""

        ax.yaxis.set_major_formatter(ticker.FuncFormatter(_format_power_of_ten))
        ax.yaxis.set_minor_formatter(ticker.NullFormatter())
        ax.yaxis.set_minor_locator(ticker.NullLocator())
        ax.grid(False)

        for spine in ax.spines.values():
            spine.set_edgecolor("black")
            spine.set_linewidth(0.5)

        # Order legend according to SERIES_ORDER
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

        # Place legend above the plot
        legend = ax.legend(
            legend_handles,
            ordered_labels,
            frameon=True,
            loc="lower left",
            bbox_to_anchor=(0.0, 1.02),
            borderaxespad=0.0,
            ncol=3,
            columnspacing=0.6,
            handlelength=1.0,
            handletextpad=0.4,
        )
        frame = legend.get_frame()
        frame.set_edgecolor("#cccccc")
        frame.set_linewidth(0.5)
        frame.set_facecolor("white")

        fig.subplots_adjust(left=0.24, right=0.94, bottom=0.22, top=0.72)
        ensure_output_dir(output_path.parent)
        fig.savefig(output_path, bbox_inches="tight", pad_inches=0.01, facecolor="white")
        plt.close(fig)

    try:
        pretty_path = output_path.relative_to(Path.cwd())
    except ValueError:
        pretty_path = output_path

    print(f"[records_latency[{dataset_label}]] Wrote figure to {pretty_path}")


def main() -> None:
    csv_path = DATA_DIR / INPUT_CSV
    output_path = OUTPUT_DIR / OUTPUT_PDF
    dataset_label = "tpch"

    data = load_dataframe(csv_path, dataset_label)
    if not data:
        sys.exit(1)

    plot_bars(data, output_path, dataset_label)


if __name__ == "__main__":
    main()
