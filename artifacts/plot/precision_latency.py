"""Generate APEX precision/latency plots for GT and EQ datasets."""

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

# Leave as `None` to load data from the CSV inputs.
HARDCODED_DATA: Sequence[Mapping[str, float]] | None = None

X_COLUMN = "precision"
Y_COLUMNS: Sequence[str] | None = None

LEGEND_NAMES: Mapping[str, str] = {
    "APEX (2b)": "APEX (2-bit)",
    "APEX (3b)": "APEX (4-bit)",
    "APEX (4b)": "APEX (8-bit)",
}
SERIES_ORDER = [
    "APEX (2b)",
    "APEX (3b)",
    "APEX (4b)",
]

SPAN_ANNOTATIONS: list[dict] = []

PLOT_TITLE: str | None = None
X_LABEL = "Precision"
Y_LABEL = "Latency (ms)"
PLOT_STYLE = "seaborn-v0_8-paper"
FIG_SIZE = (2.0, 3.2)
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

# Marker configuration.
CARRY_MARKER = dict(marker="o", markeredgewidth=0.1)
DEFAULT_MARKER = dict(marker="D")
CARRY_MARKER_COLUMNS = {"APEX (2b)", "APEX (3b)", "APEX (4b)"}

# Dataset configuration.
SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
OUTPUT_DIR = Path(os.environ.get("APEX_OUTPUT_DIR", SCRIPT_DIR / "output"))
DATA_DIR = Path(os.environ.get("APEX_DATA_DIR", SCRIPT_DIR / "data"))
DATASET_FILES = (
    "precision_latency_gt.csv",
    "precision_latency_eq.csv",
)

LABEL_HEIGHT_SCALE: Mapping[str, float] = {
    "precision_latency_gt": 0.9,
    "precision_latency_eq": 0.9,
}

DATASET_YLIMS: Mapping[str, tuple[float, float]] = {
    "precision_latency_gt": (0.05, 100),
    "precision_latency_eq": (0.05, 100),
}


@dataclass
class PlotData:
    x: str
    ys: Sequence[str]
    frame: pd.DataFrame


def load_dataframe(csv_path: Path, dataset_label: str) -> PlotData | None:
    """Return a DataFrame for the provided CSV file."""

    tag = f"precision_latency[{dataset_label}]"

    if HARDCODED_DATA:
        frame = pd.DataFrame(HARDCODED_DATA)
        y_columns = (
            list(Y_COLUMNS)
            if Y_COLUMNS
            else [col for col in frame.columns if col != X_COLUMN]
        )
        missing = [col for col in (X_COLUMN, *y_columns) if col not in frame.columns]
        if missing:
            print(
                f"[{tag}] Hardcoded data missing columns: {', '.join(missing)}",
                file=sys.stderr,
            )
            return None
        frame = frame.sort_values(by=X_COLUMN).reset_index(drop=True)
        if frame[X_COLUMN].isnull().any():
            print(f"[{tag}] Hardcoded data missing precision values.", file=sys.stderr)
            return None
        return PlotData(x=X_COLUMN, ys=y_columns, frame=frame)

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
        print(f"[{tag}] CSV precision column contains missing values.", file=sys.stderr)
        return None

    return PlotData(x=X_COLUMN, ys=y_columns, frame=frame)


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def plot_lines(data: PlotData, output_path: Path, dataset_label: str) -> None:
    plt.style.use(PLOT_STYLE)

    with plt.rc_context(STYLE_OVERRIDES):
        fig, ax = plt.subplots(figsize=FIG_SIZE)

        fig.patch.set_facecolor("white")
        ax.set_facecolor("white")

        plotted_columns = 1
        for column in data.ys:
            subset = data.frame[[data.x, column]].dropna()
            if subset.empty:
                continue

            if column in CARRY_MARKER_COLUMNS:
                marker_kwargs = {**CARRY_MARKER}
                marker_size = MARKER_SIZE
            else:
                marker_kwargs = {**DEFAULT_MARKER}
                marker_size = MARKER_SIZE

            ax.plot(
                subset[data.x],
                subset[column],
                markersize=marker_size,
                linewidth=LINE_WIDTH,
                label=LEGEND_NAMES.get(column, column),
                **marker_kwargs,
            )
            plotted_columns += 1

        if plotted_columns == 0:
            print(
                f"[precision_latency[{dataset_label}]] No valid data to plot.",
                file=sys.stderr,
            )
            plt.close(fig)
            return

        if PLOT_TITLE:
            ax.set_title(PLOT_TITLE)

        ax.set_xlabel(X_LABEL)
        ax.set_ylabel(Y_LABEL)

        xticks = sorted(data.frame[data.x].dropna().unique())
        if xticks:
            ax.set_xticks(xticks)

        ax.set_yscale("log")
        # Auto-scale y-axis from data
        all_vals = data.frame[data.ys].values.flatten()
        all_vals = all_vals[~pd.isna(all_vals)]
        all_vals = all_vals[all_vals > 0]
        if len(all_vals) > 0:
            min_exp = int(np.floor(np.log10(all_vals.min()))) - 1
            max_exp = int(np.ceil(np.log10(all_vals.max()))) + 1
        else:
            min_exp, max_exp = -1, 3
        fixed_ticks = [10.0**e for e in range(min_exp, max_exp + 1)]
        ax.yaxis.set_major_locator(ticker.FixedLocator(fixed_ticks))
        ax.set_ylim(10.0**min_exp, 10.0**max_exp)

        def _format_power_of_ten(val: float, _: float) -> str:
            if val <= 0:
                return ""
            exponent = round(log10(val))
            if abs(val - 10 ** exponent) < 1e-8 and val in fixed_ticks:
                if exponent < 0:
                    return rf"$10^{{{int(exponent)}}}$"
                return rf"$10^{{{int(exponent)}}}$"
            return ""

        ax.yaxis.set_major_formatter(ticker.FuncFormatter(_format_power_of_ten))
        ax.yaxis.set_minor_formatter(ticker.NullFormatter())
        ax.yaxis.set_minor_locator(ticker.NullLocator())
        ax.grid(False)

        for spine in ax.spines.values():
            spine.set_edgecolor("black")
            spine.set_linewidth(0.5)

        legend_cols = min(3, plotted_columns) if plotted_columns else 1
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
        legend_cols = 1
        legend = ax.legend(
            legend_handles,
            ordered_labels,
            frameon=True,
            loc="upper right",
            bbox_to_anchor=(0.92, 0.96),
            borderaxespad=0.0,
            ncol=legend_cols,
            columnspacing=0.6,
            handlelength=1.6,
            handletextpad=0.4,
        )
        frame = legend.get_frame()
        frame.set_edgecolor("#cccccc")
        frame.set_linewidth(0.5)
        frame.set_facecolor("white")

        for annotation in SPAN_ANNOTATIONS:
            target_precision = annotation["precision"]
            high_series = annotation["high"]
            low_series = annotation["low"]
            text_dx = annotation.get("text_dx", -2.0)
            text_scale = annotation.get("text_scale", 0.9)
            mutation_scale = annotation.get("mutation_scale", 2.8)

            target_rows = data.frame.loc[data.frame[data.x] == target_precision]
            if (
                target_rows.empty
                or high_series not in data.frame.columns
                or low_series not in data.frame.columns
            ):
                continue

            row = target_rows.iloc[0]
            high_val = row.get(high_series)
            low_val = row.get(low_series)
            if not (
                pd.notna(high_val)
                and pd.notna(low_val)
                and float(low_val) > 0
                and float(high_val) > float(low_val)
            ):
                continue

            target_x = float(row[data.x])
            high_val = float(high_val)
            low_val = float(low_val)
            arrow_kwargs = dict(
                arrowstyle="<|-|>",
                linewidth=0.6,
                color="black",
                shrinkA=0,
                shrinkB=0,
                mutation_scale=mutation_scale,
            )
            ax.annotate(
                "",
                xy=(target_x, high_val),
                xytext=(target_x, low_val),
                arrowprops=arrow_kwargs,
            )

            label_scale = annotation.get("label_height_scale", 1.0)
            ratio = high_val / low_val
            text_y = (high_val * low_val) ** 0.5 * text_scale * label_scale
            ax.text(
                target_x + text_dx,
                text_y,
                f"{ratio:.0f}×",
                fontsize=4.2,
                ha="right",
                va="top",
                color="black",
                bbox=dict(
                    facecolor="none",
                    edgecolor="none",
                    boxstyle="round,pad=0.08",
                ),
            )

        fig.subplots_adjust(left=0.24, right=0.94, bottom=0.22, top=0.56)
        ensure_output_dir(output_path.parent)
        fig.savefig(output_path, bbox_inches="tight", pad_inches=0.01, facecolor="white")
        plt.close(fig)

    try:
        pretty_path = output_path.relative_to(Path.cwd())
    except ValueError:
        pretty_path = output_path

    print(f"[precision_latency[{dataset_label}]] Wrote figure to {pretty_path}")


def main() -> None:
    generated_any = False

    for csv_name in DATASET_FILES:
        csv_path = DATA_DIR / csv_name
        dataset_label = Path(csv_name).stem
        output_path = OUTPUT_DIR / f"{dataset_label}.pdf"

        data = load_dataframe(csv_path, dataset_label)
        if not data:
            continue

        plot_lines(data, output_path, dataset_label)
        generated_any = True

    if not generated_any:
        sys.exit(1)


if __name__ == "__main__":
    main()
