"""Generate keyword length and wildcards latency plots."""

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

X_COLUMN = "length"
Y_COLUMNS: Sequence[str] | None = None

LEGEND_NAMES: Mapping[str, str] = {
    "APEX (2-bit)": "APEX (2-bit)",
    "APEX (4-bit)": "APEX (4-bit)",
    "APEX (8-bit)": "APEX (8-bit)",
}
SERIES_ORDER = [
    "APEX (2-bit)",
    "APEX (4-bit)",
    "APEX (8-bit)",
]

PLOT_TITLE: str | None = None
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
CARRY_MARKER_COLUMNS = {"APEX (2-bit)", "APEX (4-bit)", "APEX (8-bit)"}

# Dataset configuration.
SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
OUTPUT_DIR = Path(os.environ.get("APEX_OUTPUT_DIR", SCRIPT_DIR / "output"))
DATA_DIR = Path(os.environ.get("APEX_DATA_DIR", SCRIPT_DIR / "data"))
DATASET_FILES = (
    "varying_string_length.csv",
    "varying_query_length.csv",
    "varying_any1_wildcards.csv",
    "varying_star_wildcards.csv",
)

X_LABELS: Mapping[str, str] = {
    "varying_string_length": "Length of string",
    "varying_query_length": "Length of query",
    "varying_any1_wildcards": "Number of wildcards",
    "varying_star_wildcards": "Number of wildcards",
}

DATASET_YLIMS: Mapping[str, tuple[float, float]] = {
    "varying_string_length": (0.1, 1000),
    "varying_query_length": (1, 10000),
    "varying_any1_wildcards": (1, 1000),
    "varying_star_wildcards": (1, 100000),
}

DATASET_TICKS: Mapping[str, list[float]] = {
    "varying_string_length": [0.1, 1, 10, 100, 1000],
    "varying_query_length": [1, 10, 100, 1000, 10000],
    "varying_any1_wildcards": [1, 10, 100, 1000],
    "varying_star_wildcards": [1, 10, 100, 1000, 10000, 100000],
}

LEGEND_COLUMN_SPACING: Mapping[str, float] = {
    "varying_string_length": 0.3,
    "varying_query_length": 0.3,
    "varying_any1_wildcards": 0.3,
    "varying_star_wildcards": 0.3,
}

OOM_ANNOTATIONS: Mapping[str, list[dict]] = {}

SPAN_ANNOTATIONS: Mapping[str, list[dict]] = {}


@dataclass
class PlotData:
    x: str
    ys: Sequence[str]
    frame: pd.DataFrame


def load_dataframe(csv_path: Path, dataset_label: str) -> PlotData | None:
    """Return a DataFrame for the provided CSV file."""

    tag = f"keyword_wildcards[{dataset_label}]"

    if not csv_path.exists():
        print(f"[{tag}] Missing CSV: {csv_path.name}", file=sys.stderr)
        return None

    frame = pd.read_csv(csv_path)

    if not frame.columns.size:
        print(f"[{tag}] CSV contains no columns.", file=sys.stderr)
        return None

    first_column = frame.columns[0]
    x_column = first_column

    y_columns = (
        list(Y_COLUMNS)
        if Y_COLUMNS
        else [
            column
            for column in frame.columns
            if column != x_column
            and column in LEGEND_NAMES
            and frame[column].dropna().any()
        ]
    )

    for column in (x_column, *y_columns):
        if column not in frame.columns:
            print(f"[{tag}] CSV missing required column: {column}", file=sys.stderr)
            return None

    numeric_columns = [x_column, *[column for column in y_columns if column != x_column]]
    original = frame[numeric_columns].copy()
    frame[numeric_columns] = frame[numeric_columns].apply(pd.to_numeric, errors="coerce")
    missing_input = original.isna() | original.eq("")
    non_numeric = (~missing_input) & frame[numeric_columns].isnull()
    non_numeric[x_column] = False
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

    frame = frame.sort_values(by=x_column).reset_index(drop=True)
    if frame[x_column].isnull().any():
        print(f"[{tag}] CSV x-axis column contains missing values.", file=sys.stderr)
        return None

    return PlotData(x=x_column, ys=y_columns, frame=frame)


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def plot_lines(data: PlotData, output_path: Path, dataset_label: str) -> None:
    plt.style.use(PLOT_STYLE)

    with plt.rc_context(STYLE_OVERRIDES):
        fig, ax = plt.subplots(figsize=FIG_SIZE)

        fig.patch.set_facecolor("white")
        ax.set_facecolor("white")

        plotted_columns = 0
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
                f"[keyword_wildcards[{dataset_label}]] No valid data to plot.",
                file=sys.stderr,
            )
            plt.close(fig)
            return

        if PLOT_TITLE:
            ax.set_title(PLOT_TITLE)

        x_label = X_LABELS.get(dataset_label, data.x)
        ax.set_xlabel(x_label)
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
            # Don't show the first tick (starting position)
            if val == fixed_ticks[0]:
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
        legend_cols = 3
        column_spacing = LEGEND_COLUMN_SPACING.get(dataset_label, 0.6)
        legend = ax.legend(
            legend_handles,
            ordered_labels,
            frameon=True,
            loc="lower left",
            bbox_to_anchor=(0.0, 1.02),
            borderaxespad=0.0,
            ncol=legend_cols,
            columnspacing=column_spacing,
            handlelength=1.0,
            handletextpad=0.4,
        )
        frame = legend.get_frame()
        frame.set_edgecolor("#cccccc")
        frame.set_linewidth(0.5)
        frame.set_facecolor("white")

        # Add span annotations for this dataset
        annotations = SPAN_ANNOTATIONS.get(dataset_label, [])
        for annotation in annotations:
            target_x = annotation["x_value"]
            high_series = annotation["high"]
            low_series = annotation["low"]
            text_dx = annotation.get("text_dx", 0)
            text_scale = annotation.get("text_scale", 0.9)
            mutation_scale = annotation.get("mutation_scale", 2.8)

            target_rows = data.frame.loc[data.frame[data.x] == target_x]
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

            target_x_val = float(row[data.x])
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
                xy=(target_x_val, high_val),
                xytext=(target_x_val, low_val),
                arrowprops=arrow_kwargs,
            )

            label_scale = annotation.get("label_height_scale", 1.0)
            ratio = high_val / low_val
            text_y = (high_val * low_val) ** 0.5 * text_scale * label_scale
            ax.text(
                target_x_val + text_dx,
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

        # Add OOM annotations for this dataset
        oom_annotations = OOM_ANNOTATIONS.get(dataset_label, [])
        for oom_annot in oom_annotations:
            series_name = oom_annot["series"]
            last_x = oom_annot["last_x"]
            extend_to = oom_annot["extend_to"]
            trend_multiplier = oom_annot.get("trend_multiplier", 2.0)
            annot_config = oom_annot.get("annotation", {})

            # Get the last valid data point for this series
            if series_name in data.frame.columns:
                series_data = data.frame[[data.x, series_name]].dropna()
                if not series_data.empty:
                    last_row = series_data[series_data[data.x] == last_x]
                    if not last_row.empty:
                        last_y = float(last_row[series_name].iloc[0])
                        # Calculate projected end point (upward trend in log scale)
                        end_y = last_y * trend_multiplier

                        # Get line color from the plotted series
                        for line in ax.get_lines():
                            if line.get_label() == LEGEND_NAMES.get(series_name, series_name):
                                line_color = line.get_color()

                                # Draw dashed arrow showing upward trend
                                ax.annotate(
                                    "",
                                    xy=(extend_to, end_y),
                                    xytext=(last_x, last_y),
                                    arrowprops=dict(
                                        arrowstyle="->",
                                        linestyle="--",
                                        linewidth=LINE_WIDTH * 0.8,
                                        color=line_color,
                                        alpha=0.6,
                                        mutation_scale=5,
                                    ),
                                    zorder=1,
                                )

                                # Add annotation text below the arrow
                                if annot_config:
                                    text = annot_config.get("text", "OOM")
                                    x_offset = annot_config.get("x_offset", 0.2)
                                    y_offset = annot_config.get("y_offset", 0.7)

                                    # Calculate midpoint of the arrow for text placement
                                    mid_x = (last_x + extend_to) / 2
                                    mid_y = (last_y + end_y) / 2

                                    ax.text(
                                        mid_x * 1.05,
                                        mid_y * 0.5,  # Position below the arrow
                                        text,
                                        fontsize=3.8,
                                        ha="center",
                                        va="top",
                                        color=line_color,
                                        style="italic",
                                    )
                                break

        fig.subplots_adjust(left=0.24, right=0.94, bottom=0.22, top=0.56)
        ensure_output_dir(output_path.parent)
        fig.savefig(output_path, bbox_inches="tight", pad_inches=0.01, facecolor="white")
        plt.close(fig)

    try:
        pretty_path = output_path.relative_to(Path.cwd())
    except ValueError:
        pretty_path = output_path

    print(f"[keyword_wildcards[{dataset_label}]] Wrote figure to {pretty_path}")


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
