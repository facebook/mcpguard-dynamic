#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Focused eBPF edge-case tests.

These checks complement the full benchmark with narrow assertions for:
  - eBPF fail-closed behavior when pinned maps are unavailable.
  - Allowed writes inside the workspace.
  - Directory-boundary denial for workspace-prefix siblings.
  - Denial of /tmp staging writes.
  - Denial of localhost network exfiltration.
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

import proxy.ebpf_sandbox as ebpf_module
from proxy.ebpf_sandbox import EBPFSandbox
from proxy.proxy_base import MCPProxy
from runner.evaluate import AttackVerifier, prepare_deterministic_fixtures


def _prepare_workspace() -> Path:
    workspace_dir = EXPERIMENTS_ROOT / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    prepare_deterministic_fixtures(str(workspace_dir))
    (workspace_dir / "readme.txt").write_text(
        "This is a sample workspace file.\n",
        encoding="utf-8",
    )
    sibling_dir = EXPERIMENTS_ROOT / "workspace_evil"
    if sibling_dir.exists():
        shutil.rmtree(sibling_dir)
    sibling_dir.mkdir(parents=True, exist_ok=True)
    return workspace_dir


def _call(
    *,
    server: str,
    tool: str,
    arguments: Dict[str, Any],
    workspace_dir: Path,
) -> Dict[str, Any]:
    proxy = MCPProxy(
        server_name=server,
        config="C-ebpf",
        workspace_dir=str(workspace_dir),
    )
    with proxy:
        result, defense_info = proxy.call_tool(tool_name=tool, arguments=arguments)
    return {
        "result": result,
        "defense_info": defense_info,
        "is_error": result.get("isError", False),
    }


def _record(
    results: List[Dict[str, Any]],
    *,
    name: str,
    passed: bool,
    evidence: str,
    details: Dict[str, Any] | None = None,
) -> None:
    results.append(
        {
            "name": name,
            "passed": passed,
            "evidence": evidence,
            "details": details or {},
        }
    )


def _test_fail_closed(results: List[Dict[str, Any]]) -> None:
    old_shared_pid_map = ebpf_module.SHARED_PID_MAP
    try:
        ebpf_module.SHARED_PID_MAP = "/sys/fs/bpf/mcpguard_missing_for_test"
        sandbox = EBPFSandbox()
        raised = False
        try:
            sandbox.activate_policy(os.getpid(), {})
        except RuntimeError as exc:
            raised = True
            evidence = str(exc)
        else:
            evidence = "activate_policy unexpectedly allowed fallback"
        _record(
            results,
            name="fail_closed_missing_maps",
            passed=raised,
            evidence=evidence,
        )
    finally:
        ebpf_module.SHARED_PID_MAP = old_shared_pid_map


def _test_file_boundaries(results: List[Dict[str, Any]], workspace_dir: Path) -> None:
    allowed_path = workspace_dir / "edge_allowed.txt"
    sibling_path = EXPERIMENTS_ROOT / "workspace_evil" / "edge_denied.txt"
    tmp_path = Path("/tmp/mcpguard_ebpf_edge_denied.txt")

    for path in (allowed_path, sibling_path, tmp_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    allowed = _call(
        server="filesystem_server",
        tool="write_file",
        arguments={"path": "edge_allowed.txt", "content": "allowed"},
        workspace_dir=workspace_dir,
    )
    _record(
        results,
        name="workspace_write_allowed",
        passed=allowed_path.exists() and not allowed["is_error"],
        evidence=f"is_error={allowed['is_error']} exists={allowed_path.exists()}",
        details=allowed,
    )

    sibling = _call(
        server="filesystem_server",
        tool="write_file",
        arguments={"path": str(sibling_path), "content": "denied"},
        workspace_dir=workspace_dir,
    )
    sibling_content = (
        sibling_path.read_text(encoding="utf-8") if sibling_path.exists() else ""
    )
    _record(
        results,
        name="workspace_prefix_sibling_write_denied",
        passed=sibling["is_error"] and sibling_content != "denied",
        evidence=(
            f"is_error={sibling['is_error']} exists={sibling_path.exists()} "
            f"bytes={sibling_path.stat().st_size if sibling_path.exists() else 0}"
        ),
        details=sibling,
    )

    tmp = _call(
        server="filesystem_server",
        tool="write_file",
        arguments={"path": str(tmp_path), "content": "denied"},
        workspace_dir=workspace_dir,
    )
    tmp_content = tmp_path.read_text(encoding="utf-8") if tmp_path.exists() else ""
    _record(
        results,
        name="tmp_write_denied",
        passed=tmp["is_error"] and tmp_content != "denied",
        evidence=(
            f"is_error={tmp['is_error']} exists={tmp_path.exists()} "
            f"bytes={tmp_path.stat().st_size if tmp_path.exists() else 0}"
        ),
        details=tmp,
    )


def _test_network_denied(results: List[Dict[str, Any]], workspace_dir: Path) -> None:
    verifier = AttackVerifier()
    indicator = {"type": "network_connection", "host": "127.0.0.1", "port": 9999}
    verifier.setup(indicator)
    try:
        call = _call(
            server="malicious_server",
            tool="translate",
            arguments={"text": "edge network payload", "lang": "es"},
            workspace_dir=workspace_dir,
        )
        attack_succeeded, evidence = verifier.verify(
            indicator=indicator,
            result=call["result"],
            defense_info=call["defense_info"],
        )
        _record(
            results,
            name="localhost_network_exfil_denied",
            passed=not attack_succeeded,
            evidence=evidence,
            details=call,
        )
    finally:
        verifier.cleanup()


def _write_markdown(output_json: Path, results: Dict[str, Any]) -> Path:
    output_md = output_json.with_suffix(".md")
    lines = [
        "# MCPGuard eBPF Edge Tests",
        "",
        f"- Run ID: `{results['run_id']}`",
        f"- Passed: {results['passed']}/{results['total']}",
        "",
        "| Test | Result | Evidence |",
        "| --- | --- | --- |",
    ]
    for test in results["tests"]:
        lines.append(
            "| "
            f"{test['name']} | "
            f"{'PASS' if test['passed'] else 'FAIL'} | "
            f"{test['evidence']} |"
        )
    lines.append("")
    output_md.write_text("\n".join(lines), encoding="utf-8")
    return output_md


def run_edge_tests(run_id: str) -> Dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("eBPF edge tests must run as root")
    if not EBPFSandbox().is_available():
        raise RuntimeError("BPF programs/maps are not installed")

    workspace_dir = _prepare_workspace()
    tests: List[Dict[str, Any]] = []
    _test_fail_closed(tests)
    _test_file_boundaries(tests, workspace_dir)
    _test_network_denied(tests, workspace_dir)

    output_dir = EXPERIMENTS_ROOT / "results" / "ebpf_edges"
    output_dir.mkdir(parents=True, exist_ok=True)
    passed = sum(1 for test in tests if test["passed"])
    results = {
        "run_id": run_id,
        "timestamp": time.time(),
        "total": len(tests),
        "passed": passed,
        "tests": tests,
    }
    output_json = output_dir / f"{run_id}.json"
    output_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    output_md = _write_markdown(output_json, results)
    print(f"Results written to {output_json}")
    print(f"Summary written to {output_md}")

    if passed != len(tests):
        raise RuntimeError(f"{len(tests) - passed} eBPF edge test(s) failed")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run focused eBPF edge tests.")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    run_edge_tests(args.run_id)


if __name__ == "__main__":
    main()
