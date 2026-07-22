#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Aggregate process-sandbox baseline results into APR / V-APR / FPR, computed
consistently with the MCPGuard configs, plus per-case catch/miss/break detail.

Viability ("viable" attack) is defined as an attack case whose indicator is
observed under C0 (i.e., the attack actually succeeds with no defense). V-APR
uses viable attacks as the denominator.

Usage:
  python3 runner/aggregate_baselines.py \
      --c0 results/C0/baseline_ref.json \
      --result results/C-seccomp/baselines.json \
      --result results/C-bwrap/baselines.json \
      --result results/C-gvisor/baselines.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _is_benign(rec: dict[str, Any]) -> bool:
    return rec["category"] == "benign"


def _categorize_results(
    recs: list[dict[str, Any]], viable_ids: set[str]
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Split results into: attacks, benign, apr_prevented, viable_here,
    viable_prevented, viable_missed, fp, skipped."""
    considered = [r for r in recs if not r.get("skipped")]
    skipped = [r for r in recs if r.get("skipped")]
    attacks = [r for r in considered if not _is_benign(r)]
    benign = [r for r in considered if _is_benign(r)]
    apr_prevented = [r for r in attacks if r["attack_prevented"]]
    viable_here = [r for r in attacks if r["case_id"] in viable_ids]
    viable_prevented = [r for r in viable_here if r["attack_prevented"]]
    viable_missed = [r for r in viable_here if not r["attack_prevented"]]
    fp = [r for r in benign if r["attack_prevented"]]
    return (
        attacks,
        benign,
        apr_prevented,
        viable_here,
        viable_prevented,
        viable_missed,
        fp,
        skipped,
    )


def _analyze_config(data: dict[str, Any], viable_ids: set[str]) -> dict[str, Any]:
    """Compute APR/V-APR/FPR metrics for a single config result."""
    (
        attacks,
        benign,
        apr_prevented,
        viable_here,
        viable_prevented,
        viable_missed,
        fp,
        skipped,
    ) = _categorize_results(data["results"], viable_ids)

    return {
        "attacks_total": len(attacks),
        "attacks_prevented": len(apr_prevented),
        "apr": pct(len(apr_prevented), len(attacks)),
        "viable_total": len(viable_here),
        "viable_prevented": len(viable_prevented),
        "vapr": pct(len(viable_prevented), len(viable_here)),
        "benign_total": len(benign),
        "false_positives": len(fp),
        "fpr": pct(len(fp), len(benign)),
        "skipped": [r["case_id"] for r in skipped],
        "viable_missed_ids": sorted(r["case_id"] for r in viable_missed),
        "viable_caught_ids": sorted(r["case_id"] for r in viable_prevented),
        "false_positive_ids": sorted(r["case_id"] for r in fp),
    }


def compute(c0_path: str, result_paths: list[str]) -> dict[str, Any]:
    c0 = _load(c0_path)

    # Viable attacks = attacks whose indicator is observed under C0.
    viable_ids = {
        r["case_id"]
        for r in c0["results"]
        if not _is_benign(r) and r.get("indicator_observed")
    }

    summary: dict[str, Any] = {"viable_total": len(viable_ids), "configs": {}}

    for path in result_paths:
        data = _load(path)
        config = data["config"]
        summary["configs"][config] = _analyze_config(data, viable_ids)

    return summary


def pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1) if den else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate baseline results")
    parser.add_argument("--c0", required=True, help="C0 result JSON for viability")
    parser.add_argument(
        "--result",
        action="append",
        default=[],
        help="Baseline result JSON (repeatable)",
    )
    args = parser.parse_args()
    summary = compute(args.c0, args.result)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
