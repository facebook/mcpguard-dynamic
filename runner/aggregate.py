#!/usr/bin/env python3
"""
MCPGuard Results Aggregator.

Aggregates results across configurations and produces the comparison table
for the paper.

Usage:
  python3 runner/aggregate.py
  python3 runner/aggregate.py --run-id run1
  python3 runner/aggregate.py --format latex
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent

CONFIGS_ORDER = ["C0", "C-AB", "C-app", "C-ebpf", "C-full", "C-AB+ebpf"]

CATEGORY_LABELS = {
    "file_read": "File Read",
    "exfiltration": "Exfiltration",
    "env_leak": "Env Leak",
    "sandbox_escape": "Sandbox Escape",
    "priv_escalation": "Priv. Escalation",
    "cross_language": "Cross-Language",
    "benign": "Benign (FP)",
}


def load_results(
    results_dir: Path,
    run_id: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Load results for all configs. Returns {config: result_data}."""
    all_results = {}
    for config_dir in sorted(results_dir.iterdir()):
        if not config_dir.is_dir():
            continue
        config = config_dir.name
        if config not in CONFIGS_ORDER:
            continue

        # Find the result file
        if run_id:
            result_file = config_dir / f"{run_id}.json"
            if result_file.exists():
                data = json.loads(result_file.read_text(encoding="utf-8"))
                all_results[config] = data
        else:
            # Use the latest result file
            result_files = sorted(config_dir.glob("*.json"))
            if result_files:
                data = json.loads(result_files[-1].read_text(encoding="utf-8"))
                all_results[config] = data

    return all_results


def compute_metrics(
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute metrics for a set of results."""
    attack_cases = [r for r in results if r["category"] != "benign"]
    benign_cases = [r for r in results if r["category"] == "benign"]

    metrics = {
        "total_attack": len(attack_cases),
        "total_benign": len(benign_cases),
        "attacks_prevented": sum(1 for r in attack_cases if r["attack_prevented"]),
        "attacks_succeeded": sum(1 for r in attack_cases if r["attack_succeeded"]),
        "false_positives": sum(1 for r in benign_cases if r["attack_prevented"]),
        "true_negatives": sum(1 for r in benign_cases if not r["attack_prevented"]),
        "errors": sum(1 for r in results if r.get("error")),
        "avg_latency_ms": (
            sum(r["latency_ms"] for r in results) / max(len(results), 1)
        ),
    }

    # Prevention rate (for attack cases)
    if metrics["total_attack"] > 0:
        metrics["prevention_rate"] = (
            metrics["attacks_prevented"] / metrics["total_attack"]
        )
    else:
        metrics["prevention_rate"] = 0.0

    # False positive rate (for benign cases)
    if metrics["total_benign"] > 0:
        metrics["false_positive_rate"] = (
            metrics["false_positives"] / metrics["total_benign"]
        )
    else:
        metrics["false_positive_rate"] = 0.0

    return metrics


def compute_per_category(
    results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Compute per-category metrics."""
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)

    per_cat = {}
    for cat, cat_results in categories.items():
        if cat == "benign":
            blocked = sum(1 for r in cat_results if r["attack_prevented"])
            per_cat[cat] = {
                "total": len(cat_results),
                "blocked": blocked,
                "rate": blocked / max(len(cat_results), 1),
            }
        else:
            prevented = sum(1 for r in cat_results if r["attack_prevented"])
            per_cat[cat] = {
                "total": len(cat_results),
                "prevented": prevented,
                "rate": prevented / max(len(cat_results), 1),
            }

    return per_cat


def print_comparison_table(
    all_results: Dict[str, Dict[str, Any]],
    output_format: str = "text",
) -> None:
    """Print the comparison table across configurations."""
    if not all_results:
        print("No results found.", file=sys.stderr)
        return

    # Compute metrics for each config
    config_metrics = {}
    config_per_cat = {}
    for config in CONFIGS_ORDER:
        if config not in all_results:
            continue
        results = all_results[config]["results"]
        config_metrics[config] = compute_metrics(results)
        config_per_cat[config] = compute_per_category(results)

    if output_format == "latex":
        _print_latex_table(config_metrics, config_per_cat)
    else:
        _print_text_table(config_metrics, config_per_cat)


def _print_text_table(
    config_metrics: Dict[str, Dict[str, Any]],
    config_per_cat: Dict[str, Dict[str, Dict[str, Any]]],
) -> None:
    """Print a text-format comparison table."""
    configs = [c for c in CONFIGS_ORDER if c in config_metrics]

    # Header
    header = f"{'Metric':<25}"
    for config in configs:
        header += f" {config:>12}"
    print(header)
    print("=" * len(header))

    # Overall prevention rate
    row = f"{'Prevention Rate':<25}"
    for config in configs:
        rate = config_metrics[config]["prevention_rate"]
        row += f" {rate:>11.1%}"
    print(row)

    # False positive rate
    row = f"{'False Positive Rate':<25}"
    for config in configs:
        rate = config_metrics[config]["false_positive_rate"]
        row += f" {rate:>11.1%}"
    print(row)

    # Average latency
    row = f"{'Avg Latency (ms)':<25}"
    for config in configs:
        latency = config_metrics[config]["avg_latency_ms"]
        row += f" {latency:>11.2f}"
    print(row)

    print()

    # Per-category breakdown
    print("Per-Category Prevention Rates:")
    print("-" * 60)

    categories_list = [
        "file_read",
        "exfiltration",
        "env_leak",
        "sandbox_escape",
        "priv_escalation",
        "cross_language",
        "benign",
    ]
    for cat in categories_list:
        label = CATEGORY_LABELS.get(cat, cat)
        row = f"  {label:<23}"
        for config in configs:
            per_cat = config_per_cat.get(config, {})
            if cat in per_cat:
                rate = per_cat[cat]["rate"]
                total = per_cat[cat]["total"]
                if cat == "benign":
                    blocked = per_cat[cat].get("blocked", 0)
                    row += f" {blocked}/{total:>3}"
                else:
                    prevented = per_cat[cat].get("prevented", 0)
                    row += f" {prevented}/{total:>3}"
            else:
                row += f" {'N/A':>5}"
        print(row)


def _print_latex_table(
    config_metrics: Dict[str, Dict[str, Any]],
    config_per_cat: Dict[str, Dict[str, Dict[str, Any]]],
) -> None:
    """Print a LaTeX-format comparison table."""
    configs = [c for c in CONFIGS_ORDER if c in config_metrics]
    n = len(configs)

    print(r"\begin{table}[t]")
    print(r"\centering")
    print(r"\caption{MCPGuard evaluation results across configurations}")
    print(r"\label{tab:results}")
    print(r"\begin{tabular}{l" + "r" * n + "}")
    print(r"\toprule")

    # Header
    header = r"\textbf{Metric}"
    for config in configs:
        header += rf" & \textbf{{{config}}}"
    header += r" \\"
    print(header)
    print(r"\midrule")

    # Prevention rate
    row = "Prevention Rate"
    for config in configs:
        rate = config_metrics[config]["prevention_rate"]
        row += f" & {rate:.1%}"
    row += r" \\"
    print(row)

    # FP rate
    row = "False Positive Rate"
    for config in configs:
        rate = config_metrics[config]["false_positive_rate"]
        row += f" & {rate:.1%}"
    row += r" \\"
    print(row)

    # Latency
    row = "Avg Latency (ms)"
    for config in configs:
        latency = config_metrics[config]["avg_latency_ms"]
        row += f" & {latency:.2f}"
    row += r" \\"
    print(row)

    print(r"\midrule")

    # Per-category
    categories_list = [
        "file_read",
        "exfiltration",
        "env_leak",
        "sandbox_escape",
        "priv_escalation",
    ]
    for cat in categories_list:
        label = CATEGORY_LABELS.get(cat, cat)
        row = f"\\quad {label}"
        for config in configs:
            per_cat = config_per_cat.get(config, {})
            if cat in per_cat:
                prevented = per_cat[cat].get("prevented", 0)
                total = per_cat[cat]["total"]
                row += f" & {prevented}/{total}"
            else:
                row += " & --"
        row += r" \\"
        print(row)

    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate MCPGuard evaluation results",
    )
    parser.add_argument(
        "--run-id",
        help="Specific run ID to aggregate (default: latest)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "latex"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--results-dir",
        default=str(EXPERIMENTS_ROOT / "results"),
        help="Results directory",
    )

    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    all_results = load_results(results_dir, args.run_id)

    if not all_results:
        print("No results found. Run evaluate.py first.", file=sys.stderr)
        sys.exit(1)

    print_comparison_table(all_results, args.format)


if __name__ == "__main__":
    main()
