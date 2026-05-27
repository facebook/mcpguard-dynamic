#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCPGuard Smoke Test.

Runs 3 representative cases (FR-05, EX-03, PE-01) across C0 and C-app to
validate the non-root harness path.

Usage:
  python3 runner/smoke_test.py
"""

import json
import sys
import time
from pathlib import Path

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from runner.evaluate import discover_test_cases, run_single_case


SMOKE_CASES = ["FR-05", "EX-03", "PE-01"]
SMOKE_CONFIGS = ["C0", "C-app"]


def run_smoke_test() -> bool:
    """Run smoke tests and return True if all pass."""
    test_cases_dir = EXPERIMENTS_ROOT / "test_cases"
    workspace_dir = str(EXPERIMENTS_ROOT / "workspace")

    # Ensure workspace exists
    Path(workspace_dir).mkdir(parents=True, exist_ok=True)
    (Path(workspace_dir) / "readme.txt").write_text(
        "Smoke test workspace file.\n", encoding="utf-8"
    )

    # Ensure notes_data exists with test notes
    notes_dir = EXPERIMENTS_ROOT / "notes_data"
    notes_dir.mkdir(parents=True, exist_ok=True)
    test_notes = {
        "test001.json": {
            "id": "test001",
            "title": "Test Note",
            "content": "This is a test note for evaluation.",
            "created_at": time.time(),
        },
        "note-1.json": {
            "id": "note-1",
            "title": "Project Planning",
            "content": "Review the project milestones and deliverables.",
            "created_at": time.time(),
        },
    }
    for filename, note_data in test_notes.items():
        note_file = notes_dir / filename
        if not note_file.exists():
            note_file.write_text(json.dumps(note_data, indent=2), encoding="utf-8")

    # Load all test cases
    all_cases = discover_test_cases(test_cases_dir)
    case_map = {c["case_id"]: c for c in all_cases}

    # Verify requested cases exist
    missing = [cid for cid in SMOKE_CASES if cid not in case_map]
    if missing:
        print(f"ERROR: Missing test cases: {missing}", file=sys.stderr)
        return False

    print("MCPGuard Smoke Test")
    print("=" * 70)
    print(f"Cases: {SMOKE_CASES}")
    print(f"Configs: {SMOKE_CONFIGS}")
    print()

    all_passed = True
    results_summary = []

    for config in SMOKE_CONFIGS:
        print(f"--- Config: {config} ---")
        for case_id in SMOKE_CASES:
            case = case_map[case_id]
            print(f"  {case_id} ({case.get('attack_name', 'benign')})...", end=" ")
            sys.stdout.flush()

            try:
                result = run_single_case(
                    case=case,
                    config=config,
                    workspace_dir=workspace_dir,
                )

                status = result["defense_action"] or "N/A"
                latency = result["latency_ms"]
                error = result.get("error")

                if error:
                    print(f"ERROR: {error}")
                    all_passed = False
                else:
                    prevented = result["attack_prevented"]
                    print(f"{status} (prevented={prevented}, {latency:.1f}ms)")

                results_summary.append(result)

            except Exception as exc:
                print(f"EXCEPTION: {exc}")
                all_passed = False

        print()

    # Validate expectations
    print("Validation:")
    print("-" * 40)

    # C0 should not prevent any attacks
    c0_results = [r for r in results_summary if r["config"] == "C0"]
    c0_prevented = sum(1 for r in c0_results if r["attack_prevented"])
    c0_ok = c0_prevented == 0
    print(
        f"  C0 prevents 0 attacks: {'PASS' if c0_ok else 'FAIL'} (prevented {c0_prevented})"
    )
    if not c0_ok:
        all_passed = False

    # C-app should prevent at least some attacks via policy/argval
    capp_results = [r for r in results_summary if r["config"] == "C-app"]
    capp_prevented = sum(1 for r in capp_results if r["attack_prevented"])
    capp_ok = capp_prevented > 0
    print(
        f"  C-app prevents >0 attacks: {'PASS' if capp_ok else 'FAIL'} (prevented {capp_prevented})"
    )
    if not capp_ok:
        all_passed = False

    print()
    print(
        f"Overall: {'ALL SMOKE TESTS PASSED' if all_passed else 'SOME SMOKE TESTS FAILED'}"
    )

    # Write smoke test results
    results_dir = EXPERIMENTS_ROOT / "results" / "smoke"
    results_dir.mkdir(parents=True, exist_ok=True)
    output_file = results_dir / f"smoke_{int(time.time())}.json"
    output_file.write_text(
        json.dumps(
            {
                "passed": all_passed,
                "timestamp": time.time(),
                "results": results_summary,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Results written to {output_file}")

    return all_passed


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
