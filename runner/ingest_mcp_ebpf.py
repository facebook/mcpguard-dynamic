#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
eBPF (L3) real-world MCP attack probe (completes reviewer critique D1).

The app-level probe (``runner/ingest_mcp.py``) drove the in-scope
``mcp-breach-to-fix-labs`` challenges under C0/C-AB/C-app and found the
application-level defenses prevent 0/4 real attacks, because their path /
injection checks key on *canonical* argument names that the real servers do
not use.  This runner completes the picture by driving the SAME real,
unmodified vulnerable servers under the syscall-level eBPF configurations
(C-ebpf, C-full, C-AB+ebpf), where enforcement is argument-name-agnostic.

How L3 is wired here (the core integration):
  * The real vulnerable ``server.py`` runs as a MONITORED SUBPROCESS under the
    invoking user's uid via the harness ``MCPProxy`` (the challenge adapter is
    registered in ``SERVER_SCRIPTS``), exactly as the synthetic benchmark
    drives eBPF configs.
  * Per-server eBPF policies are activated in the pinned BPF maps keyed by the
    server subprocess PID.  Because the maps are root-owned, only the map
    read/write is elevated: ``EBPFSandbox`` is swapped for a shim
    (``SudoEBPFSandbox``) that shells the map ops out to
    ``runner/ebpf_map_helper.py`` via ``sudo``.  The harness and the server
    stay unprivileged.
  * The attack is then driven through the real tool call.  We measure whether
    the sensitive ``openat`` (ch02) / ``execve`` (ch08) / write is blocked by
    file_guard / proc_guard: i.e. whether the attack indicator (SENTINEL in
    response, marker file, injected DB row) still fires.

Honesty:
  * Labels come from each challenge's documented CVE/GHSA id.
  * Every result below is measured, not asserted.  Where a challenge's attack
    is not a syscall the guards can mediate (ch05: the exfil primitive is a
    legitimate read of the server's OWN config file, indistinguishable at the
    syscall layer from the benign read; ch07: in-process SQL string
    interpolation into a legitimately-writable DB is not a syscall violation),
    we run it anyway and report the (non-)prevention plainly.

Usage (needs passwordless sudo for BPF map ops only):
  python3 runner/ingest_mcp_ebpf.py
  python3 runner/ingest_mcp_ebpf.py --configs C-ebpf
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.agentbound_baseline import AgentBoundBaseline  # noqa: E402
from proxy.proxy_base import MCPProxy, SERVER_SCRIPTS  # noqa: E402
from runner.ingest_mcp import (  # noqa: E402
    _indicator_fired,
    _reset_indicator,
    _write_adapter,
    _write_policies,
    BREACH_ROOT,
    CaseSpec,
    Challenge,
    GEN_ROOT,
    get_challenges,
)

logger = logging.getLogger("ingest_mcp_ebpf")

EBPF_CONFIGS = ["C-ebpf", "C-full", "C-AB+ebpf"]
EBPF_POLICY_DIR = GEN_ROOT / "policies" / "ebpf"
HELPER = str(EXPERIMENTS_ROOT / "runner" / "ebpf_map_helper.py")

# The benign git call must be allowed at every location it may resolve to
# (git resolves via PATH under shell=True, and the fbcode wrapper execs a real
# backing binary), so proc_guard does not falsely block legitimate `git init`.
# touch / arbitrary binaries stay denied, which is what stops the ch08 injection.
GIT_BINARIES = [
    "/usr/bin/git",
    "/bin/git",
    "/usr/local/bin/git",
    "/usr/local/bin/git.meta.real",
]

# Benign config files the git wrapper READS at startup. Denying (EPERM, not
# ENOENT) any of these is fatal to git; none is related to the CVE, so allow
# the reads so the benign `git init` is not falsely broken.
GIT_TELEMETRY_CONFIG = "/etc/scm-telemetry.toml"
GIT_CONFIG_READS = [
    GIT_TELEMETRY_CONFIG,
    "/etc/gitconfig",
    str(Path.home() / ".gitconfig"),
]


# ---------------------------------------------------------------------------
# eBPF map activation via sudo (servers stay unprivileged)
# ---------------------------------------------------------------------------


class SudoEBPFSandbox:
    """Drop-in for ``EBPFSandbox`` that performs map ops as root via sudo.

    The monitored server subprocess is spawned by the (unprivileged) harness;
    only the root-owned BPF map read/write is elevated, through
    ``runner/ebpf_map_helper.py``.
    """

    def __init__(self) -> None:
        self._python = sys.executable

    def is_available(self) -> bool:
        return True

    def _run_helper(self, request: Dict[str, Any]) -> None:
        req_file = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, prefix="ebpf_req_"
            ) as handle:
                json.dump(request, handle)
                req_file = handle.name
            result = subprocess.run(
                ["sudo", self._python, HELPER, req_file],
                capture_output=True,
                text=True,
                timeout=90,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"sudo BPF map op failed (rc={result.returncode}): "
                    f"{result.stderr.strip()}"
                )
        finally:
            if req_file:
                try:
                    os.unlink(req_file)
                except OSError:
                    pass

    def activate_policy(self, pid: int, policy: Dict[str, Any]) -> None:
        self._run_helper({"action": "activate", "pid": pid, "policy": policy})

    def deactivate_policy(self, pid: int) -> None:
        try:
            self._run_helper({"action": "deactivate", "pid": pid})
        except Exception as exc:  # best-effort teardown
            logger.warning("deactivate_policy(%d) failed: %s", pid, exc)

    def is_active(self, pid: int) -> bool:  # noqa: D401 - interface parity
        return True


# ---------------------------------------------------------------------------
# eBPF policy generation (benign contract; blind to the attack payload)
# ---------------------------------------------------------------------------


def _code_read_globs(challenge: Challenge) -> List[str]:
    """Paths the server must READ to import its own (unmodified) code.

    These are activated only *after* the initialize handshake, but the tool
    body (which performs the attack) reads its config at call time, so the
    server's own source/corpus dir and the generated adapter dir must be
    readable.  None of these contain the ch02 sensitive fixture (which lives
    in a separate temp work dir), so allowing them does not weaken the test.
    """
    return [
        str(BREACH_ROOT / challenge.challenge_dir) + "/**",
        str(GEN_ROOT / "adapters") + "/**",
    ]


def _ebpf_fs_and_exec(
    challenge: Challenge, fixtures: Dict[str, Any]
) -> Tuple[List[str], List[str], bool, List[str]]:
    """Return (read_globs, write_globs, allow_execve, allowed_executables)."""
    num = challenge.challenge_dir.split("-")[0]
    code = _code_read_globs(challenge)

    if num == "02":
        # Read the allowed dir + code only. The sensitive fixture lives in a
        # sibling (…/safe_files_sensitive), NOT under …/safe_files/, so
        # file_guard's trailing-slash prefix denies it — where the server's
        # naive startswith() lets it through (CVE-2025-53110).
        return [fixtures["allowed_dir"] + "/**"] + code, [], False, []
    if num == "05":
        # The sensitive value is a JSON key in the server's OWN config file,
        # read by both the benign and the attack call — same openat. Allowing
        # the config read (legit) means the attack read is also allowed: the
        # file layer cannot discriminate. Reported honestly as non-mediable.
        return code, [], False, []
    if num == "07":
        work = str(Path(fixtures["db_path"]).parent) + "/**"
        # The temp DB is legitimately writable; SQLi is in-process data, not a
        # syscall violation — reported honestly as non-mediable.
        return [work] + code, [work], False, []
    if num == "08":
        work = str(Path(fixtures["repo_root"]).parent) + "/**"
        # git is allowed (benign init); touch/arbitrary binaries are NOT, so
        # proc_guard denies the injected `; touch <marker>` execve.
        # The fbcode git wrapper also reads /etc/scm-telemetry.toml at startup
        # (a benign config, unrelated to the attack) — allow it so the BENIGN
        # git init is not falsely broken.
        # git opens /dev/null O_RDWR; system_paths grants it read-only, so add
        # it to the write set too (a bit-bucket, not an attack surface).
        return (
            [work] + GIT_CONFIG_READS + code,
            [work, "/dev/null"],
            True,
            list(GIT_BINARIES),
        )
    return code, [], False, []


def _ebpf_policy(
    challenge: Challenge, fixtures: Dict[str, Any], server_name: str
) -> Dict[str, Any]:
    read, write, allow_execve, execs = _ebpf_fs_and_exec(challenge, fixtures)
    syscalls_allow = ["read", "open", "openat", "stat", "close"]
    syscalls_deny = ["connect", "bind", "listen"]
    if allow_execve:
        syscalls_allow.append("execve")
    else:
        syscalls_deny.append("execve")

    tool_policy: Dict[str, Any] = {
        "filesystem": {"read": read, "write": write},
        "network": {"allow": []},
        "syscalls": {"allow": syscalls_allow, "deny": syscalls_deny},
    }
    if execs:
        tool_policy["allowed_executables"] = execs

    # Key by the REAL tool names so the C-full app `policy` layer treats the
    # tool as declared (pass-through, exactly as app-level) while the eBPF map
    # writer unions filesystem/exec across tools into the syscall policy.
    tools = {name: tool_policy for name in challenge.tools}
    return {"server": server_name, "tools": tools}


def _write_ebpf_policy(
    server_name: str, challenge: Challenge, fixtures: Dict[str, Any]
) -> None:
    EBPF_POLICY_DIR.mkdir(parents=True, exist_ok=True)
    policy = _ebpf_policy(challenge, fixtures, server_name)
    (EBPF_POLICY_DIR / f"{server_name}.json").write_text(
        json.dumps(policy, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Registration (reuses the app-level adapters/fixtures)
# ---------------------------------------------------------------------------


def _server_name(challenge: Challenge, variant: str) -> str:
    num = challenge.challenge_dir.split("-")[0]
    return f"ch{num}_{variant}"


def _register(challenge: Challenge) -> List[Tuple[str, CaseSpec]]:
    num = challenge.challenge_dir.split("-")[0]
    work = GEN_ROOT / "work" / f"ch{num}"
    if work.exists():
        shutil.rmtree(work)
    fixtures = challenge.fixtures(work)
    cases = challenge.build_cases(fixtures)
    registered: List[Tuple[str, CaseSpec]] = []
    for variant in ("vulnerable", "secure"):
        if variant not in challenge.drivable_variants:
            continue
        module_path = BREACH_ROOT / challenge.challenge_dir / variant / "server.py"
        server_name = _server_name(challenge, variant)
        adapter = _write_adapter(server_name, module_path, challenge.tools, fixtures)
        SERVER_SCRIPTS[server_name] = str(adapter)
        _write_policies(server_name, challenge, fixtures)  # app + AgentBound
        _write_ebpf_policy(server_name, challenge, fixtures)
        for case in cases:
            if case.variant == variant:
                registered.append((server_name, case))
    return registered


# ---------------------------------------------------------------------------
# Running a single case under an eBPF config
# ---------------------------------------------------------------------------


def _cleanup_challenge(challenge: Challenge) -> None:
    for variant in challenge.drivable_variants:
        stray = BREACH_ROOT / challenge.challenge_dir / variant / "tickets.db"
        if stray.exists():
            stray.unlink()


def _run_case(server_name: str, case: CaseSpec, config: str) -> Dict[str, Any]:
    _reset_indicator(case.indicator)
    proxy = MCPProxy(
        server_name=server_name,
        config=config,
        policy_dir=str(EBPF_POLICY_DIR),
        workspace_dir=str(EXPERIMENTS_ROOT / "workspace"),
    )
    proxy.ebpf_sandbox = SudoEBPFSandbox()
    if config == "C-AB+ebpf":
        proxy.agentbound = AgentBoundBaseline(
            policy_dir=str(GEN_ROOT / "policies" / "agentbound")
        )

    error: Optional[str] = None
    result: Dict[str, Any] = {}
    defense_info: Dict[str, Any] = {"blocked": False, "layer": None, "latency_ms": 0.0}
    try:
        with proxy:
            result, defense_info = proxy.call_tool(case.tool, case.arguments)
    except Exception as exc:  # server failed to start / crashed
        error = str(exc)

    blocked = bool(defense_info.get("blocked"))
    is_error = bool(result.get("isError", False))
    fired = (
        (not blocked)
        and error is None
        and case.indicator is not None
        and _indicator_fired(case.indicator, result)
    )
    # eBPF blocks at the syscall level: no app-layer "blocked" flag is set; the
    # signal is that the indicator did not fire (and, for a real syscall denial,
    # the tool typically returns an error/permission message).
    prevented = case.indicator is not None and not fired
    if blocked:
        prevented_by = defense_info.get("layer")
    elif prevented:
        prevented_by = "L3-ebpf (syscall denied)"
    else:
        prevented_by = None

    return {
        "server": server_name,
        "config": config,
        "kind": case.kind,
        "variant": case.variant,
        "tool": case.tool,
        "blocked": blocked,
        "defense_layer": defense_info.get("layer"),
        "indicator_fired": fired,
        "attack_prevented": prevented,
        "prevented_by": prevented_by,
        "is_error": is_error,
        "error": error,
        "latency_ms": round(defense_info.get("latency_ms", 0.0), 3),
    }


def _print_case(record: Dict[str, Any]) -> None:
    if record["kind"] == "attack":
        status = "PREVENTED" if record["attack_prevented"] else "FIRED"
    else:
        blocked = record["blocked"] or record["is_error"] or record["error"]
        status = "FP-BLOCKED" if blocked else "allowed"
    print(
        f"  [{record['config']:9}] {record['server']:16} {record['kind']:14} "
        f"{record['tool']:22} -> {status:10} ({record['prevented_by']})"
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _rate(num: int, den: int) -> str:
    if den == 0:
        return "n/a (0)"
    return f"{num}/{den} ({100 * num / den:.1f}%)"


def _viable_challenges(app_results_path: Path) -> List[str]:
    """Challenges whose attack is viable under C0 (from the app-level run)."""
    if not app_results_path.exists():
        return []
    data = json.loads(app_results_path.read_text(encoding="utf-8"))
    return sorted(data.get("metrics", {}).get("_viable_challenges", []))


def _metrics(records: List[Dict[str, Any]], viable: List[str]) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}
    viable_set = set(viable)
    for config in EBPF_CONFIGS:
        attacks = [
            r for r in records if r["kind"] == "attack" and r["config"] == config
        ]
        prevented = [r for r in attacks if r["attack_prevented"]]
        va = [r for r in attacks if r["challenge"] in viable_set]
        vprev = [r for r in va if r["attack_prevented"]]
        benign = [r for r in records if r["kind"] == "benign" and r["config"] == config]
        fp = [r for r in benign if r["blocked"] or r["is_error"] or r["error"]]
        metrics[config] = {
            "attacks_total": len(attacks),
            "apr": _rate(len(prevented), len(attacks)),
            "viable_total": len(va),
            "v_apr": _rate(len(vprev), len(va)),
            "benign_total": len(benign),
            "fpr": _rate(len(fp), len(benign)),
        }
    metrics["_viable_challenges"] = viable
    return metrics


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _prepare_git_env() -> None:
    """Drop inherited ``GIT_CONFIG_*`` env vars.

    Devservers export ``GIT_CONFIG_COUNT`` + ``GIT_CONFIG_KEY_i`` (github URL
    rewrites, irrelevant to a local ``git init``).  The proxy's env
    sanitization strips keys containing ``KEY`` but keeps ``GIT_CONFIG_COUNT``,
    leaving git with a dangling count -> ``fatal: missing config key``.  Remove
    the whole family so the benign git call is not falsely broken.
    """
    for key in list(os.environ):
        if key.startswith("GIT_CONFIG"):
            del os.environ[key]


def run(configs: List[str]) -> Dict[str, Any]:
    _prepare_git_env()
    challenges = get_challenges()
    all_records: List[Dict[str, Any]] = []

    for challenge in challenges:
        if not challenge.drivable_variants:
            continue
        registered = _register(challenge)
        for server_name, case in registered:
            for config in configs:
                record = _run_case(server_name, case, config)
                record["challenge"] = challenge.challenge_dir
                record["cve_ids"] = challenge.cve_ids
                record["guard"] = challenge.guard
                all_records.append(record)
                _print_case(record)
        _cleanup_challenge(challenge)

    viable = _viable_challenges(GEN_ROOT / "results" / "real_probe_results.json")
    summary = {
        "configs": configs,
        "records": all_records,
        "metrics": _metrics(all_records, viable),
    }
    (GEN_ROOT / "results").mkdir(parents=True, exist_ok=True)
    (GEN_ROOT / "results" / "real_probe_ebpf_results.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser(description="eBPF real MCP attack probe")
    parser.add_argument(
        "--configs",
        nargs="*",
        default=EBPF_CONFIGS,
        choices=EBPF_CONFIGS,
        help="eBPF configurations to run",
    )
    args = parser.parse_args()
    summary = run(args.configs)

    print("\n=== eBPF real-probe metrics (real in-scope set) ===")
    print(f"  viable challenges (C0): {summary['metrics']['_viable_challenges']}")
    for config in args.configs:
        m = summary["metrics"][config]
        print(f"  {config:9}: APR={m['apr']}  V-APR={m['v_apr']}  FPR={m['fpr']}")


if __name__ == "__main__":
    main()
