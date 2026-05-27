#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCPGuard Results Aggregator.

Aggregates results across configurations and produces the comparison table
for the paper.

Usage:
  python3 runner/aggregate.py
  python3 runner/aggregate.py --run-id run1
  python3 runner/aggregate.py --canonical
  python3 runner/aggregate.py --run-id run1 --show-intrinsic-failures
  python3 runner/aggregate.py --format latex
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent

CONFIGS_ORDER = ["C0", "C-AB", "C-app", "C-ebpf", "C-full", "C-AB+ebpf"]
CANONICAL_MANIFEST = EXPERIMENTS_ROOT / "results" / "manifest.json"

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
                print(
                    f"Warning: missing result file for {config}: {result_file}",
                    file=sys.stderr,
                )
        else:
            # Use the latest result file by mtime. Lexicographic ordering is
            # unsafe because run names like final3, run8, and crosslang do not
            # encode chronology.
            result_files = sorted(
                config_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
            )
            if result_files:
                data = json.loads(result_files[-1].read_text(encoding="utf-8"))
                all_results[config] = data

    return all_results


def load_canonical_run_id(manifest_path: Path = CANONICAL_MANIFEST) -> str:
    """Load the paper's canonical run ID from a machine-readable manifest."""
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Canonical manifest not found: {manifest_path}. "
            "Create results/manifest.json or pass --run-id."
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_id = manifest.get("paper_run_id")
    if not run_id:
        raise ValueError(f"Manifest {manifest_path} is missing paper_run_id")
    return str(run_id)


def compute_metrics(
    results: List[Dict[str, Any]],
    viable_attack_ids: Optional[set[str]] = None,
) -> Dict[str, Any]:
    """Compute metrics for a set of results."""
    attack_cases = [r for r in results if r["category"] != "benign"]
    benign_cases = [r for r in results if r["category"] == "benign"]
    viable_attack_cases = [
        r
        for r in attack_cases
        if viable_attack_ids is not None and r["case_id"] in viable_attack_ids
    ]

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
        "avg_benign_latency_ms": (
            sum(r["latency_ms"] for r in benign_cases) / max(len(benign_cases), 1)
        ),
    }

    if viable_attack_ids is not None:
        metrics["total_viable_attack"] = len(viable_attack_cases)
        metrics["viable_attacks_prevented"] = sum(
            1 for r in viable_attack_cases if r["attack_prevented"]
        )
        metrics["viable_attacks_succeeded"] = sum(
            1 for r in viable_attack_cases if r["attack_succeeded"]
        )
    else:
        metrics["total_viable_attack"] = 0
        metrics["viable_attacks_prevented"] = 0
        metrics["viable_attacks_succeeded"] = 0

    # Prevention rate (for attack cases)
    if metrics["total_attack"] > 0:
        metrics["prevention_rate"] = (
            metrics["attacks_prevented"] / metrics["total_attack"]
        )
    else:
        metrics["prevention_rate"] = 0.0

    if metrics["total_viable_attack"] > 0:
        metrics["viable_prevention_rate"] = (
            metrics["viable_attacks_prevented"] / metrics["total_viable_attack"]
        )
    else:
        metrics["viable_prevention_rate"] = 0.0

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
    viable_attack_ids: Optional[set[str]] = None,
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
            viable_results = [
                r
                for r in cat_results
                if viable_attack_ids is not None and r["case_id"] in viable_attack_ids
            ]
            viable_prevented = sum(1 for r in viable_results if r["attack_prevented"])
            per_cat[cat] = {
                "total": len(cat_results),
                "prevented": prevented,
                "rate": prevented / max(len(cat_results), 1),
                "viable_total": len(viable_results),
                "viable_prevented": viable_prevented,
                "viable_rate": (
                    viable_prevented / len(viable_results) if viable_results else 0.0
                ),
            }

    return per_cat


def compute_viable_attack_ids(
    all_results: Dict[str, Dict[str, Any]],
) -> set[str]:
    """Use C0 to identify attacks that actually succeed without defense."""
    c0 = all_results.get("C0")
    if not c0:
        return set()
    viable_ids = set()
    for result in c0.get("results", []):
        if result.get("category") == "benign":
            continue
        if result.get("attack_succeeded"):
            viable_ids.add(result["case_id"])
    return viable_ids


def get_intrinsic_failures(
    all_results: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return attack cases that did not succeed under C0."""
    c0 = all_results.get("C0")
    if not c0:
        return []
    failures = []
    for result in c0.get("results", []):
        if result.get("category") == "benign":
            continue
        if not result.get("attack_succeeded"):
            failures.append(result)
    return failures


def print_comparison_table(
    all_results: Dict[str, Dict[str, Any]],
    output_format: str = "text",
) -> None:
    """Print the comparison table across configurations."""
    if not all_results:
        print("No results found.", file=sys.stderr)
        return

    viable_attack_ids = compute_viable_attack_ids(all_results)

    # Compute metrics for each config
    config_metrics = {}
    config_per_cat = {}
    for config in CONFIGS_ORDER:
        if config not in all_results:
            continue
        results = all_results[config]["results"]
        config_metrics[config] = compute_metrics(results, viable_attack_ids)
        config_per_cat[config] = compute_per_category(results, viable_attack_ids)

    if output_format == "latex":
        _print_latex_table(config_metrics, config_per_cat, len(viable_attack_ids))
    else:
        _print_text_table(config_metrics, config_per_cat, len(viable_attack_ids))


def _print_text_table(
    config_metrics: Dict[str, Dict[str, Any]],
    config_per_cat: Dict[str, Dict[str, Dict[str, Any]]],
    viable_attack_count: int,
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

    # Viable attack prevention rate
    row = f"{'Viable Prevention Rate':<25}"
    for config in configs:
        rate = config_metrics[config]["viable_prevention_rate"]
        row += f" {rate:>11.1%}"
    print(row)

    row = f"{'Viable Attacks':<25}"
    for config in configs:
        prevented = config_metrics[config]["viable_attacks_prevented"]
        row += f" {prevented:>5}/{viable_attack_count:<5}"
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

    row = f"{'Benign Latency (ms)':<25}"
    for config in configs:
        latency = config_metrics[config]["avg_benign_latency_ms"]
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
                    viable_total = per_cat[cat].get("viable_total", 0)
                    viable_prevented = per_cat[cat].get("viable_prevented", 0)
                    row += (
                        f" {prevented}/{total:>3} ({viable_prevented}/{viable_total}v)"
                    )
            else:
                row += f" {'N/A':>5}"
        print(row)


def _print_latex_table(
    config_metrics: Dict[str, Dict[str, Any]],
    config_per_cat: Dict[str, Dict[str, Dict[str, Any]]],
    viable_attack_count: int,
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

    row = "Viable Prevention Rate"
    for config in configs:
        rate = config_metrics[config]["viable_prevention_rate"]
        row += f" & {rate:.1%}"
    row += r" \\"
    print(row)

    row = "Viable Attacks Prevented"
    for config in configs:
        prevented = config_metrics[config]["viable_attacks_prevented"]
        row += f" & {prevented}/{viable_attack_count}"
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

    row = "Benign Latency (ms)"
    for config in configs:
        latency = config_metrics[config]["avg_benign_latency_ms"]
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
                viable_prevented = per_cat[cat].get("viable_prevented", 0)
                viable_total = per_cat[cat].get("viable_total", 0)
                row += f" & {prevented}/{total} ({viable_prevented}/{viable_total}v)"
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
        "--canonical",
        action="store_true",
        help="Use results/manifest.json to select the paper run",
    )
    parser.add_argument(
        "--show-intrinsic-failures",
        action="store_true",
        help="List C0 attack cases that did not succeed without defense",
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
    run_id = args.run_id
    if args.canonical:
        run_id = load_canonical_run_id()

    all_results = load_results(results_dir, run_id)

    if not all_results:
        print("No results found. Run evaluate.py first.", file=sys.stderr)
        sys.exit(1)

    print_comparison_table(all_results, args.format)

    if args.show_intrinsic_failures:
        failures = get_intrinsic_failures(all_results)
        print("\nC0 Intrinsic Failures:")
        print("-" * 80)
        if not failures:
            print("None")
        for result in failures:
            print(
                f"{result['case_id']}: {result['category']} "
                f"{result['server']}.{result['tool']} -- "
                f"{result.get('evidence') or result.get('error')}"
            )


if __name__ == "__main__":
    main()
