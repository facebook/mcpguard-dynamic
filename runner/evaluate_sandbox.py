#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Evaluation runner for the process-level sandbox baselines.

Runs the 82-case MCPGuard benchmark against an MCP-unaware process sandbox
(seccomp / bwrap / gvisor) wrapping the server subprocess, using the same
AttackVerifier and fixtures as runner/evaluate.py so results are directly
comparable to the C0..C-full MCPGuard configs.

Usage:
  python3 runner/evaluate_sandbox.py --sandbox seccomp --run-id baselines
  python3 runner/evaluate_sandbox.py --sandbox bwrap   --run-id baselines
  python3 runner/evaluate_sandbox.py --sandbox gvisor  --run-id baselines
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any


class _CaseTimeout(Exception):
    """Raised when a single case exceeds the hard wall-clock backstop."""


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _CaseTimeout("case exceeded hard timeout")


EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.process_sandbox import sandbox_available, SANDBOX_CONFIGS, SandboxedMCPProxy
from proxy.proxy_base import SERVER_SCRIPTS
from runner.evaluate import (
    AttackVerifier,
    discover_test_cases,
    prepare_deterministic_fixtures,
)


def _is_js_server(server_name: str) -> bool:
    return SERVER_SCRIPTS.get(server_name, "").endswith(".js")


def run_single_case(
    case: dict[str, Any],
    sandbox_type: str,
    workspace_dir: str,
    runsc_path: str,
) -> dict[str, Any]:
    """Run one test case through a sandboxed proxy. Mirrors evaluate.run_single_case."""
    case_id = case["case_id"]
    server = case["server"]
    tool = case["tool"]
    arguments = case["arguments"]
    indicator = case.get("attack_indicator")
    category = case["category"]
    is_benign = category == "benign" or case.get("ground_truth") == "benign"
    config = f"C-{sandbox_type}"

    verifier = AttackVerifier()
    result_record: dict[str, Any] = {
        "case_id": case_id,
        "category": "benign" if is_benign else category,
        "attack_name": case.get("attack_name"),
        "server": server,
        "tool": tool,
        "config": config,
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

    # seccomp baseline is Python-only.
    if sandbox_type == "seccomp" and _is_js_server(server):
        result_record["skipped"] = True
        result_record["case_kind"] = "skipped"
        result_record["error"] = "seccomp baseline is Python-only (JS server)"
        return result_record

    try:
        prepare_deterministic_fixtures(workspace_dir)
        # Reset the shared chmod target to a known mode so PE-01 verification
        # (which checks for mode 0777) cannot be confounded by a 0777 mode left
        # behind on the host by an earlier run's successful chmod attack.
        chmod_target = Path("/tmp/test_file")
        if chmod_target.exists():
            os.chmod(chmod_target, 0o644)
        verifier.setup(indicator)

        proxy = SandboxedMCPProxy(
            server_name=server,
            sandbox_type=sandbox_type,
            workspace_dir=workspace_dir,
            runsc_path=runsc_path,
        )

        # Hard wall-clock backstop per case, above the proxy's own read timeout,
        # so no single case can stall the whole run.
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
                # A benign case is a false positive if the sandbox prevented the
                # tool from completing successfully: either the proxy blocked it
                # (never happens here) or the tool returned an error because a
                # syscall it needs was denied / a required path was unavailable.
                broke = defense_info["blocked"] or not attack_succeeded
                result_record["attack_prevented"] = broke
                result_record["attack_succeeded"] = not broke
                result_record["case_kind"] = (
                    "false_positive" if broke else "benign_allowed"
                )
            else:
                result_record["attack_succeeded"] = attack_succeeded
                result_record["attack_prevented"] = not attack_succeeded
                if attack_succeeded:
                    result_record["case_kind"] = "viable_attack"
                else:
                    result_record["case_kind"] = "blocked_attack"

    except Exception as exc:  # noqa: BLE001 - record harness/sandbox failures
        result_record["error"] = str(exc)
        result_record["case_kind"] = "error"
        # A sandbox that crashes the server prevents the attack but also breaks
        # a benign call; record it as prevented so it is not silently ignored.
        result_record["attack_prevented"] = True
        result_record["attack_succeeded"] = False
    finally:
        signal.alarm(0)
        verifier.cleanup()

    return result_record


def run_evaluation(
    sandbox_type: str, run_id: str, runsc_path: str
) -> list[dict[str, Any]]:
    """Run the full benchmark for one sandbox baseline."""
    config = f"C-{sandbox_type}"
    available, detail = sandbox_available(sandbox_type, runsc_path)
    if not available:
        raise RuntimeError(f"Sandbox '{sandbox_type}' unavailable: {detail}")

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
    print(f"Running {len(cases)} cases with sandbox '{sandbox_type}' ({detail})")
    print("-" * 70)

    results = []
    for i, case in enumerate(cases, 1):
        rec = run_single_case(
            case=case,
            sandbox_type=sandbox_type,
            workspace_dir=workspace_dir,
            runsc_path=runsc_path,
        )
        results.append(rec)
        status = rec["case_kind"].upper()
        print(
            f"[{i}/{len(cases)}] {rec['case_id']:<8} {status} ({rec['latency_ms']:.1f}ms)"
        )

    results_dir = EXPERIMENTS_ROOT / "results" / config
    results_dir.mkdir(parents=True, exist_ok=True)
    output_file = results_dir / f"{run_id}.json"
    output_file.write_text(
        json.dumps(
            {
                "config": config,
                "sandbox_type": sandbox_type,
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
    parser = argparse.ArgumentParser(description="MCPGuard process-sandbox baselines")
    parser.add_argument(
        "--sandbox",
        required=True,
        choices=sorted(set(SANDBOX_CONFIGS.values())),
        help="Process sandbox baseline to evaluate",
    )
    parser.add_argument("--run-id", required=True, help="Unique run identifier")
    parser.add_argument(
        "--runsc-path",
        default="/tmp/runsc",
        help="Path to the gVisor runsc binary",
    )
    args = parser.parse_args()
    run_evaluation(
        sandbox_type=args.sandbox,
        run_id=args.run_id,
        runsc_path=args.runsc_path,
    )


if __name__ == "__main__":
    main()
