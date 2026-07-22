#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Evaluation runner for the COMPOSED MCPGuard-over-bubblewrap config.

Runs the 82-case MCPGuard benchmark with the MCP server subprocess wrapped in
the tuned WS6 bubblewrap profile AND mediated by MCPGuard's L1 policy, L2
argument validation, and response-content sanitizer (no L3 eBPF -- see
proxy/combined_sandbox.py for why). Uses the SAME AttackVerifier, fixtures, and
metric definitions as runner/evaluate.py / runner/evaluate_sandbox.py so the
result is a directly comparable first-class config row -- not a union estimate.

Usage:
  python3 runner/evaluate_combined.py --run-id combined_r1
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict


class _CaseTimeout(Exception):
    """Raised when a single case exceeds the hard wall-clock backstop."""


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _CaseTimeout("case exceeded hard timeout")


EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.combined_sandbox import combined_available, COMBINED_CONFIG, CombinedMCPProxy
from runner.evaluate import (
    AttackVerifier,
    discover_test_cases,
    prepare_deterministic_fixtures,
)


def run_single_case(case: Dict[str, Any], workspace_dir: str) -> Dict[str, Any]:
    """Run one test case through the composed MCPGuard+bwrap proxy.

    Mirrors evaluate_sandbox.run_single_case: a benign case is a false positive
    if the tool did not complete successfully -- either a MCPGuard layer blocked
    it or the bwrap sandbox broke it from the inside (denied path / crash).
    """
    case_id = case["case_id"]
    server = case["server"]
    tool = case["tool"]
    arguments = case["arguments"]
    indicator = case.get("attack_indicator")
    category = case["category"]
    is_benign = category == "benign" or case.get("ground_truth") == "benign"

    verifier = AttackVerifier()
    result_record: Dict[str, Any] = {
        "case_id": case_id,
        "category": "benign" if is_benign else category,
        "attack_name": case.get("attack_name"),
        "server": server,
        "tool": tool,
        "config": COMBINED_CONFIG,
        "attack_prevented": False,
        "attack_succeeded": False,
        "blocked_by_defense": False,
        "indicator_observed": False,
        "indicator_type": indicator.get("type") if indicator else None,
        "expected_without_defense": case.get("expected_without_defense"),
        "case_kind": "benign" if is_benign else "attack",
        "defense_action": None,
        "defense_layer": None,
        "tool_is_error": None,
        "latency_ms": 0.0,
        "error": None,
        "evidence": None,
        "skipped": False,
    }

    try:
        prepare_deterministic_fixtures(workspace_dir)
        # Reset the shared chmod target so PE-01 verification (mode 0777) is not
        # confounded by a prior run's successful chmod on the host.
        chmod_target = Path("/tmp/test_file")
        if chmod_target.exists():
            os.chmod(chmod_target, 0o644)
        verifier.setup(indicator)

        proxy = CombinedMCPProxy(server_name=server, workspace_dir=workspace_dir)

        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(30)
        with proxy:
            result, defense_info = proxy.call_tool(tool_name=tool, arguments=arguments)

            result_record["latency_ms"] = defense_info["latency_ms"]
            result_record["defense_action"] = (
                "BLOCKED" if defense_info["blocked"] else "ALLOWED"
            )
            result_record["defense_layer"] = defense_info.get("layer")
            result_record["blocked_by_defense"] = defense_info["blocked"]
            result_record["tool_is_error"] = bool(result.get("isError", False))

            attack_succeeded, evidence = verifier.verify(
                indicator=indicator,
                result=result,
                defense_info=defense_info,
            )
            result_record["indicator_observed"] = attack_succeeded
            result_record["evidence"] = evidence

            if is_benign:
                broke = defense_info["blocked"] or not attack_succeeded
                result_record["attack_prevented"] = broke
                result_record["attack_succeeded"] = not broke
                result_record["case_kind"] = (
                    "false_positive" if broke else "benign_allowed"
                )
            else:
                result_record["attack_succeeded"] = attack_succeeded
                result_record["attack_prevented"] = not attack_succeeded
                if defense_info["blocked"]:
                    result_record["case_kind"] = "blocked_attack"
                elif attack_succeeded:
                    result_record["case_kind"] = "viable_attack"
                else:
                    result_record["case_kind"] = "contained_attack"

    except Exception as exc:  # noqa: BLE001 - record harness/sandbox failures
        result_record["error"] = str(exc)
        result_record["case_kind"] = "error"
        # A crash prevents the attack but also breaks a benign call; record it
        # as prevented so it is never silently ignored (and counts as an FP for
        # benign cases).
        result_record["attack_prevented"] = True
        result_record["attack_succeeded"] = False
    finally:
        signal.alarm(0)
        verifier.cleanup()

    return result_record


def run_evaluation(run_id: str) -> list[Dict[str, Any]]:
    """Run the full 82-case benchmark for the composed MCPGuard+bwrap config."""
    available, detail = combined_available()
    if not available:
        raise RuntimeError(f"Composed config unavailable: {detail}")

    test_cases_dir = EXPERIMENTS_ROOT / "test_cases"
    workspace_dir = str(EXPERIMENTS_ROOT / "workspace")
    Path(workspace_dir).mkdir(parents=True, exist_ok=True)
    prepare_deterministic_fixtures(workspace_dir)

    readme_file = Path(workspace_dir) / "readme.txt"
    if not readme_file.exists():
        readme_file.write_text("This is a sample workspace file.\n", encoding="utf-8")
    config_file = Path(workspace_dir) / "data" / "config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    if not config_file.exists():
        config_file.write_text('{"version": "1.0"}\n', encoding="utf-8")

    cases = discover_test_cases(test_cases_dir)
    print(
        f"Running {len(cases)} cases with composed config {COMBINED_CONFIG} ({detail})"
    )
    print("-" * 70)

    results = []
    for i, case in enumerate(cases, 1):
        rec = run_single_case(case=case, workspace_dir=workspace_dir)
        results.append(rec)
        status = rec["case_kind"].upper()
        print(
            f"[{i}/{len(cases)}] {rec['case_id']:<8} {status} "
            f"layer={str(rec['defense_layer']):18} ({rec['latency_ms']:.1f}ms)"
        )

    results_dir = EXPERIMENTS_ROOT / "results" / COMBINED_CONFIG
    results_dir.mkdir(parents=True, exist_ok=True)
    output_file = results_dir / f"{run_id}.json"
    output_file.write_text(
        json.dumps(
            {
                "config": COMBINED_CONFIG,
                "run_id": run_id,
                "timestamp": time.time(),
                "total_cases": len(results),
                "results": results,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nResults written to {output_file}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCPGuard composed (policy-over-bubblewrap) evaluation"
    )
    parser.add_argument("--run-id", required=True, help="Unique run identifier")
    args = parser.parse_args()
    run_evaluation(run_id=args.run_id)


if __name__ == "__main__":
    main()
