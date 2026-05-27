#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Audit and override workflow demonstration.

The full benchmark has 0/21 benign false positives, so this script constructs a
controlled false-positive scenario with an intentionally too-strict policy,
records the audit event, applies a scoped operator override, and verifies that
the same benign call is allowed.
"""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.proxy_base import MCPProxy
from runner.evaluate import prepare_deterministic_fixtures


def _prepare_workspace() -> Path:
    workspace_dir = EXPERIMENTS_ROOT / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    prepare_deterministic_fixtures(str(workspace_dir))
    (workspace_dir / "readme.txt").write_text(
        "This is a sample workspace file.\n",
        encoding="utf-8",
    )
    return workspace_dir


def _prepare_demo_policies(policy_root: Path) -> Dict[str, str]:
    if policy_root.exists():
        shutil.rmtree(policy_root)

    defaults_dir = policy_root / "defaults"
    override_dir = policy_root / "overrides" / "filesystem_server"
    defaults_dir.mkdir(parents=True, exist_ok=True)
    override_dir.mkdir(parents=True, exist_ok=True)

    source_policy = (
        EXPERIMENTS_ROOT / "policies" / "defaults" / "filesystem_server.json"
    )
    strict_policy = json.loads(source_policy.read_text(encoding="utf-8"))
    strict_policy["tools"]["read_file"]["filesystem"]["read"] = []
    strict_policy_path = defaults_dir / "filesystem_server.json"
    strict_policy_path.write_text(
        json.dumps(strict_policy, indent=2) + "\n",
        encoding="utf-8",
    )

    override = {
        "tool": "read_file",
        "capabilities": {
            "filesystem": {
                "read": ["./workspace/**"],
            },
        },
        "description": "Allow benign workspace reads observed in the audit log.",
    }
    override_path = override_dir / "read_file.json"
    override_path.write_text(json.dumps(override, indent=2) + "\n", encoding="utf-8")

    return {
        "defaults_dir": str(defaults_dir),
        "strict_policy": str(strict_policy_path),
        "override": str(override_path),
    }


def _run_call(
    *,
    policy_dir: Path,
    audit_log_path: Path,
    workspace_dir: Path,
) -> Dict[str, Any]:
    if audit_log_path.exists():
        audit_log_path.unlink()

    proxy = MCPProxy(
        server_name="filesystem_server",
        config="C-app",
        policy_dir=str(policy_dir),
        workspace_dir=str(workspace_dir),
        audit_log_path=str(audit_log_path),
    )
    with proxy:
        result, defense_info = proxy.call_tool(
            tool_name="read_file",
            arguments={"path": "readme.txt"},
        )
    return {
        "result": result,
        "defense_info": defense_info,
        "blocked": defense_info.get("blocked", False),
        "audit_log": str(audit_log_path),
    }


def _read_audit_events(audit_log_path: Path) -> list[Dict[str, Any]]:
    if not audit_log_path.exists():
        return []
    events = []
    for line in audit_log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _write_markdown(output_json: Path, results: Dict[str, Any]) -> Path:
    output_md = output_json.with_suffix(".md")
    strict = results["strict_run"]
    override = results["override_run"]
    lines = [
        "# MCPGuard Audit Override Workflow",
        "",
        f"- Run ID: `{results['run_id']}`",
        "- Scenario: intentionally strict `filesystem_server.read_file` policy denies benign `BN-01`, then a scoped override restores the workspace read permission.",
        "",
        "| Step | Action | Layer | Reason |",
        "| --- | --- | --- | --- |",
        (
            "| Strict policy | "
            f"{'BLOCKED' if strict['blocked'] else 'ALLOWED'} | "
            f"{strict['defense_info'].get('layer')} | "
            f"{strict['defense_info'].get('reason')} |"
        ),
        (
            "| After override | "
            f"{'BLOCKED' if override['blocked'] else 'ALLOWED'} | "
            f"{override['defense_info'].get('layer')} | "
            f"{override['defense_info'].get('reason')} |"
        ),
        "",
        "Generated artifacts:",
        f"- Strict policy: `{results['policies']['strict_policy']}`",
        f"- Override: `{results['policies']['override']}`",
        f"- Strict audit log: `{strict['audit_log']}`",
        f"- Override audit log: `{override['audit_log']}`",
        "",
    ]
    output_md.write_text("\n".join(lines), encoding="utf-8")
    return output_md


def run_workflow(run_id: str) -> Dict[str, Any]:
    output_dir = EXPERIMENTS_ROOT / "results" / "audit"
    output_dir.mkdir(parents=True, exist_ok=True)
    policy_root = output_dir / f"{run_id}_policies"
    policies = _prepare_demo_policies(policy_root)
    workspace_dir = _prepare_workspace()

    strict_audit = output_dir / f"{run_id}_strict.jsonl"
    override_audit = output_dir / f"{run_id}_override.jsonl"

    # First run without the override directory present in the policy root.
    override_dir = policy_root / "overrides"
    saved_override_dir = policy_root / "_overrides_pending"
    override_dir.rename(saved_override_dir)
    strict_run = _run_call(
        policy_dir=policy_root / "defaults",
        audit_log_path=strict_audit,
        workspace_dir=workspace_dir,
    )
    saved_override_dir.rename(override_dir)

    override_run = _run_call(
        policy_dir=policy_root / "defaults",
        audit_log_path=override_audit,
        workspace_dir=workspace_dir,
    )

    results: Dict[str, Any] = {
        "run_id": run_id,
        "timestamp": time.time(),
        "case": {
            "case_id": "BN-01",
            "server": "filesystem_server",
            "tool": "read_file",
            "arguments": {"path": "readme.txt"},
        },
        "policies": policies,
        "strict_run": strict_run,
        "override_run": override_run,
        "strict_audit_events": _read_audit_events(strict_audit),
        "override_audit_events": _read_audit_events(override_audit),
        "passed": strict_run["blocked"] and not override_run["blocked"],
    }

    output_json = output_dir / f"{run_id}.json"
    output_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    output_md = _write_markdown(output_json, results)
    print(f"Results written to {output_json}")
    print(f"Summary written to {output_md}")

    if not results["passed"]:
        raise RuntimeError("Override workflow did not block-then-allow as expected")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the audit/override workflow demonstration.",
    )
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    run_workflow(args.run_id)


if __name__ == "__main__":
    main()
