"""Compute detection metrics from the matrix runner's results.csv.

Metrics computed per (mode, level) and per attack class:
  DR   — Detection Rate  = TP / (TP + FN)   [attack turns only]
  FPR  — False Positive Rate = FP / (FP + TN) [benign scenarios]
  BR   — Block Rate = blocks / attack turns   [action=="block"]
  ΔDR  — Session advantage = DR(session) - DR(stateless)

Confidence intervals use the Wilson score interval (good for small n).

Usage:
    uv run python eval/metrics.py [--csv eval/results/results.csv]
    uv run python eval/metrics.py --table   # print the paper table
    uv run python eval/metrics.py --figures # write figures/ (requires matplotlib)
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

RESULTS_CSV = Path(__file__).parent / "results" / "results.csv"
RESULTS_DIR = Path(__file__).parent / "results"
ATTACK_CLASSES = ["direct_exfil", "delayed_exfil", "mcp_pivot", "rag_poison"]
MODES = ["stateless", "session"]
LEVELS = ["L0", "L1", "L2", "L3"]
NON_ALLOW = {"route-hardened", "strip-tools", "block"}


# ---------------------------------------------------------------------------
# Wilson score confidence interval
# ---------------------------------------------------------------------------


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion p = successes/n."""
    if n == 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    spread = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return max(0.0, centre - spread), min(1.0, centre + spread)


# ---------------------------------------------------------------------------
# Load + classify rows
# ---------------------------------------------------------------------------


def load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open() as fh:
        return list(csv.DictReader(fh))


def classify_row(row: dict) -> str:
    """Return TP/FN/TN/FP/SKIP for one row.

    Only attack turns of attack scenarios contribute to DR (TP/FN).
    All turns of benign scenarios contribute to FPR (TN/FP).
    Non-attack turns of attack scenarios are SKIPped for DR/FPR.
    """
    label = row["scenario_label"]
    is_attack_turn = row["is_attack_turn"].lower() == "true"
    action = row["action"]
    detected = action in NON_ALLOW

    if label == "attack" and is_attack_turn:
        return "TP" if detected else "FN"
    if label == "benign":
        return "FP" if detected else "TN"
    return "SKIP"


# ---------------------------------------------------------------------------
# Aggregate counters
# ---------------------------------------------------------------------------


def build_counters(rows: list[dict]) -> dict:
    """Return nested dict [mode][level][class] → {TP,FN,FP,TN,blocks,total_attack_ms,total_benign_ms,...}"""
    counters: dict = defaultdict(
        lambda: defaultdict(
            lambda: defaultdict(
                lambda: {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "blocks": 0, "latencies": []}
            )
        )
    )
    for row in rows:
        mode = row["mode"]
        level = row["level"]
        cls = row["scenario_class"]
        verdict = classify_row(row)
        c = counters[mode][level][cls]
        if verdict != "SKIP":
            c[verdict] += 1
        if row["action"] == "block":
            c["blocks"] += 1
        try:
            c["latencies"].append(float(row["latency_ms"]))
        except ValueError:
            pass
    return counters


def compute_metrics(counters: dict) -> list[dict]:
    rows_out = []
    for mode in MODES:
        for level in LEVELS:
            for cls in ATTACK_CLASSES + ["ALL"]:
                if cls == "ALL":
                    # Aggregate across classes
                    agg = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "blocks": 0, "latencies": []}
                    for c in ATTACK_CLASSES:
                        sub = counters[mode][level][c]
                        for k in ("TP", "FN", "FP", "TN", "blocks"):
                            agg[k] += sub[k]
                        agg["latencies"].extend(sub["latencies"])
                    c_data = agg
                else:
                    c_data = counters[mode][level][cls]

                tp, fn, fp, tn = c_data["TP"], c_data["FN"], c_data["FP"], c_data["TN"]
                n_attack = tp + fn
                n_benign = fp + tn
                dr = tp / n_attack if n_attack else None
                fpr = fp / n_benign if n_benign else None
                br = c_data["blocks"] / n_attack if n_attack else None
                dr_lo, dr_hi = wilson_ci(tp, n_attack) if n_attack else (None, None)
                fpr_lo, fpr_hi = wilson_ci(fp, n_benign) if n_benign else (None, None)
                lats = c_data["latencies"]
                p50 = sorted(lats)[len(lats) // 2] if lats else None
                p95 = sorted(lats)[int(len(lats) * 0.95)] if lats else None

                rows_out.append(
                    {
                        "mode": mode,
                        "level": level,
                        "class": cls,
                        "TP": tp,
                        "FN": fn,
                        "FP": fp,
                        "TN": tn,
                        "n_attack": n_attack,
                        "n_benign": n_benign,
                        "DR": round(dr, 4) if dr is not None else None,
                        "DR_lo": round(dr_lo, 4) if dr_lo is not None else None,
                        "DR_hi": round(dr_hi, 4) if dr_hi is not None else None,
                        "FPR": round(fpr, 4) if fpr is not None else None,
                        "FPR_lo": round(fpr_lo, 4) if fpr_lo is not None else None,
                        "FPR_hi": round(fpr_hi, 4) if fpr_hi is not None else None,
                        "BR": round(br, 4) if br is not None else None,
                        "p50_ms": round(p50, 2) if p50 is not None else None,
                        "p95_ms": round(p95, 2) if p95 is not None else None,
                    }
                )
    return rows_out


def compute_session_advantage(metrics: list[dict]) -> list[dict]:
    """Compute ΔDR = DR(session) - DR(stateless) per (level, class)."""
    idx: dict = {}
    for row in metrics:
        idx[(row["mode"], row["level"], row["class"])] = row

    deltas = []
    for level in LEVELS:
        for cls in ATTACK_CLASSES + ["ALL"]:
            s = idx.get(("stateless", level, cls))
            sess = idx.get(("session", level, cls))
            if s and sess and s["DR"] is not None and sess["DR"] is not None:
                delta = round(sess["DR"] - s["DR"], 4)
                deltas.append(
                    {
                        "level": level,
                        "class": cls,
                        "delta_DR": delta,
                        "DR_stateless": s["DR"],
                        "DR_session": sess["DR"],
                        "FPR_stateless": s["FPR"],
                        "FPR_session": sess["FPR"],
                    }
                )
    return deltas


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _pct(v) -> str:
    return f"{v * 100:.1f}%" if v is not None else "  —  "


def print_table(metrics: list[dict]) -> None:
    """Print the paper's central 2×4 detection table (ALL class only)."""
    print("\n== Detection Rate (ALL classes) ==")
    header = f"{'':12s}" + "".join(f"  {lvl:>6s}" for lvl in LEVELS)
    print(header)
    for mode in MODES:
        dr_row = [
            next(
                r
                for r in metrics
                if r["mode"] == mode and r["level"] == lvl and r["class"] == "ALL"
            )
            for lvl in LEVELS
        ]
        print(f"{'DR ':12s}" + "".join(f"  {_pct(r['DR']):>6s}" for r in dr_row) + f"  [{mode}]")
    print()

    print("== False Positive Rate (ALL classes) ==")
    print(header)
    for mode in MODES:
        fpr_row = [
            next(
                r
                for r in metrics
                if r["mode"] == mode and r["level"] == lvl and r["class"] == "ALL"
            )
            for lvl in LEVELS
        ]
        print(f"{'FPR ':12s}" + "".join(f"  {_pct(r['FPR']):>6s}" for r in fpr_row) + f"  [{mode}]")
    print()

    print("== Session Advantage (ΔDR = session - stateless) ==")
    deltas = compute_session_advantage(metrics)
    print(f"  {'class':20s}" + "".join(f"  {lvl:>6s}" for lvl in LEVELS))
    for cls in ATTACK_CLASSES + ["ALL"]:
        row_vals = [
            next((d for d in deltas if d["level"] == lvl and d["class"] == cls), None)
            for lvl in LEVELS
        ]
        vals = "".join(f"  {_pct(d['delta_DR']) if d else '  —  ':>6s}" for d in row_vals)
        print(f"  {cls:20s}{vals}")
    print()


def write_json(metrics: list[dict], path: Path) -> None:
    path.write_text(json.dumps(metrics, indent=2))
    print(f"Metrics JSON written to {path}")


def write_csv(metrics: list[dict], path: Path) -> None:
    if not metrics:
        return
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(metrics[0].keys()))
        writer.writeheader()
        writer.writerows(metrics)
    print(f"Metrics CSV written to {path}")


def write_figures(metrics: list[dict], out_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed — skipping figures (pip install matplotlib)")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    x = np.arange(len(LEVELS))
    width = 0.35

    # DR bar chart
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, metric_key, title in [
        (axes[0], "DR", "Detection Rate"),
        (axes[1], "FPR", "False Positive Rate"),
    ]:
        for i, mode in enumerate(MODES):
            vals = [
                next(
                    r[metric_key] or 0
                    for r in metrics
                    if r["mode"] == mode and r["level"] == lvl and r["class"] == "ALL"
                )
                for lvl in LEVELS
            ]
            lo = [
                next(
                    (r[metric_key] or 0) - (r.get(f"{metric_key}_lo") or 0)
                    for r in metrics
                    if r["mode"] == mode and r["level"] == lvl and r["class"] == "ALL"
                )
                for lvl in LEVELS
            ]
            hi = [
                next(
                    (r.get(f"{metric_key}_hi") or 0) - (r[metric_key] or 0)
                    for r in metrics
                    if r["mode"] == mode and r["level"] == lvl and r["class"] == "ALL"
                )
                for lvl in LEVELS
            ]
            ax.bar(x + i * width, vals, width, label=mode, yerr=[lo, hi], capsize=4)
        ax.set_xticks(x + width / 2)
        ax.set_xticklabels(LEVELS)
        ax.set_ylim(0, 1.05)
        ax.set_title(title)
        ax.set_ylabel("Rate")
        ax.legend()

    plt.tight_layout()
    fig_path = out_dir / "dr_fpr.png"
    plt.savefig(fig_path, dpi=150)
    plt.close()
    print(f"Figure written to {fig_path}")

    # Per-class DR heatmap
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, mode in zip(axes, MODES):
        data = np.zeros((len(ATTACK_CLASSES), len(LEVELS)))
        for i, cls in enumerate(ATTACK_CLASSES):
            for j, level in enumerate(LEVELS):
                r = next(
                    (
                        r
                        for r in metrics
                        if r["mode"] == mode and r["level"] == level and r["class"] == cls
                    ),
                    None,
                )
                data[i, j] = r["DR"] if r and r["DR"] is not None else 0.0
        im = ax.imshow(data, vmin=0, vmax=1, cmap="RdYlGn")
        ax.set_xticks(range(len(LEVELS)))
        ax.set_xticklabels(LEVELS)
        ax.set_yticks(range(len(ATTACK_CLASSES)))
        ax.set_yticklabels(ATTACK_CLASSES)
        ax.set_title(f"DR — {mode}")
        for i in range(len(ATTACK_CLASSES)):
            for j in range(len(LEVELS)):
                ax.text(j, i, f"{data[i, j]:.0%}", ha="center", va="center", fontsize=9)
        fig.colorbar(im, ax=ax)
    plt.tight_layout()
    heatmap_path = out_dir / "dr_heatmap.png"
    plt.savefig(heatmap_path, dpi=150)
    plt.close()
    print(f"Heatmap written to {heatmap_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default=str(RESULTS_CSV))
    parser.add_argument("--table", action="store_true", help="print paper table to stdout")
    parser.add_argument("--figures", action="store_true", help="write PNG figures")
    parser.add_argument("--json", action="store_true", help="write metrics.json")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise SystemExit(f"Results CSV not found: {csv_path}\nRun 'make eval' first.")

    rows = load_rows(csv_path)
    counters = build_counters(rows)
    metrics = compute_metrics(counters)

    write_csv(metrics, RESULTS_DIR / "metrics.csv")
    if args.json:
        write_json(metrics, RESULTS_DIR / "metrics.json")
    if args.table or not args.figures:
        print_table(metrics)
    if args.figures:
        write_figures(metrics, RESULTS_DIR / "figures")
