#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Static-implementation-scan safety demonstration (why we DON'T scan the server).

An obvious alternative to schema-based derivation is to statically scan the
server *implementation* -- collect its open()/read/write/urllib/socket/os.system/
os.environ calls -- and grant exactly what the code touches. Under MCPGuard's
threat model the server is UNTRUSTED, so this is unsafe: a malicious or trojaned
server would self-authorize its own hardcoded attack resources.

This script makes that concrete. It runs a lightweight literal scanner over each
server's source, builds an implementation-derived policy that grants every
hardcoded filesystem path / network host / env access the code references, and
then scores that policy against the SAME covert (planted-attack) ground truth
used in runner/policy_quality.py. The result: the implementation-scan policy
grants (self-authorizes) the covert capabilities, whereas the schema-derived and
AgentBound policies grant 0.

The scanner is deliberately simple (literal extraction), so its covert-grant
count is a LOWER bound on what a real implementation scanner would authorize
(e.g. it cannot resolve os.homedir()/expanduser joins that are assembled at
runtime).
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from derive_policy import SERVER_COMMANDS  # noqa: E402
from policy_quality import (  # noqa: E402
    _env_covered,
    _fs_covered,
    _host_covered,
    _load,
    GROUND_TRUTH_DIR,
)

STATIC_SCAN_DIR = EXPERIMENTS_ROOT / "policies" / "static_scan"

_SLASH_LITERAL = re.compile(r"""["']([^"'\s]*(?:/[^"'\s]*)+)["']""")
_URL_HOST = re.compile(r"https?://([^/\s\"']+)")
_SOCKET_HOST = re.compile(r"""connect\(\(\s*["']([\d.]+)["']\s*,\s*(\d+)""")
_JS_HOST = re.compile(r"""hostname:\s*["']([^"']+)["']""")
_EXEC = re.compile(
    r"os\.system\(|subprocess\.(?:run|Popen|call)|execSync|child_process"
)
_ENV = re.compile(
    r"os\.environ|os\.getenv|/proc/self/environ|process\.env|expanduser|os\.homedir"
)


def scan_source(text: str) -> Dict[str, Any]:
    """Extract hardcoded resources referenced by the implementation."""
    paths: Set[str] = set()
    for match in _SLASH_LITERAL.findall(text):
        if "://" in match:
            continue
        if match.startswith(("/", "~", "./", "../")):
            paths.add(match)

    hosts: Set[str] = set(_URL_HOST.findall(text))
    for host, port in _SOCKET_HOST.findall(text):
        hosts.add(f"{host}:{port}")
    hosts.update(_JS_HOST.findall(text))

    return {
        "paths": sorted(paths),
        "hosts": sorted(hosts),
        "env": bool(_ENV.search(text)),
        "execs": bool(_EXEC.search(text)),
    }


def build_impl_policy(server_name: str, scan: Dict[str, Any]) -> Dict[str, Any]:
    """A policy that grants everything the code touches (server-level)."""
    return {
        "server": server_name,
        "_source": "static-implementation-scan (UNSAFE under untrusted-server threat model)",
        "filesystem": {"read": scan["paths"], "write": scan["paths"]},
        "network": {"allow": scan["hosts"]},
        "env_vars": {"read": ["*"] if scan["env"] else []},
        "execs": scan["execs"],
    }


def _score_covert(covert: Dict[str, Any], policy: Dict[str, Any]) -> List[int]:
    """Return [total, granted] covert items for one tool under one policy."""
    fs = policy.get("filesystem", {}) or {}
    net = policy.get("network", {}) or {}
    env = policy.get("env_vars", {}) or {}
    total = 0
    granted = 0
    for res in (covert.get("filesystem", {}) or {}).get("read", []):
        total += 1
        granted += _fs_covered(res, fs.get("read", []))
    for res in (covert.get("filesystem", {}) or {}).get("write", []):
        total += 1
        granted += _fs_covered(res, fs.get("write", []))
    for host in (covert.get("network", {}) or {}).get("allow", []):
        total += 1
        granted += _host_covered(host, net.get("allow", []))
    for var in (covert.get("env_vars", {}) or {}).get("read", []):
        total += 1
        granted += _env_covered(var, env.get("read", []))
    return [total, int(granted)]


def main() -> None:
    STATIC_SCAN_DIR.mkdir(parents=True, exist_ok=True)

    covert_total = 0
    covert_granted = 0
    per_server: Dict[str, Dict[str, int]] = {}

    for server_name, command in sorted(SERVER_COMMANDS.items()):
        source_path = Path(command[-1])
        text = source_path.read_text(encoding="utf-8")
        scan = scan_source(text)
        policy = build_impl_policy(server_name, scan)
        (STATIC_SCAN_DIR / f"{server_name}.json").write_text(
            json.dumps(policy, indent=2) + "\n", encoding="utf-8"
        )

        gt_tools = _load(GROUND_TRUTH_DIR / f"{server_name}.json")["tools"]
        s_total = 0
        s_granted = 0
        for tool in gt_tools.values():
            covert = tool.get("covert") or {}
            if not covert:
                continue
            total, granted = _score_covert(covert, policy)
            s_total += total
            s_granted += granted
        covert_total += s_total
        covert_granted += s_granted
        if s_total:
            per_server[server_name] = {"covert_items": s_total, "granted": s_granted}

    print("=" * 78)
    print("STATIC-IMPLEMENTATION-SCAN SAFETY DEMONSTRATION")
    print("=" * 78)
    print(
        "An implementation-derived policy grants whatever the (untrusted) code "
        "touches,\nso it self-authorizes the server's hardcoded attack resources.\n"
    )
    print(f"{'server (has covert behavior)':<30}{'covert':>8}{'granted':>9}")
    for server_name, stats in per_server.items():
        print(f"{server_name:<30}{stats['covert_items']:>8}{stats['granted']:>9}")
    print("-" * 47)
    print(f"{'TOTAL':<30}{covert_total:>8}{covert_granted:>9}")
    print()
    frac = covert_granted / covert_total if covert_total else 0.0
    print(
        f"Static-impl-scan covert FALSE-ALLOW: {covert_granted}/{covert_total} "
        f"= {frac:.3f}"
    )
    print("Compare: schema-derived 0/34, AgentBound 0/34 (see policy_quality.py).")
    print(
        "=> Implementation-scanning is ruled out by the untrusted-server threat model."
    )
    print("=" * 78)

    out_path = EXPERIMENTS_ROOT / "results" / "policy_quality" / "static_scan.json"
    out_path.write_text(
        json.dumps(
            {
                "covert_items": covert_total,
                "covert_granted": covert_granted,
                "covert_false_allow_rate": round(frac, 4),
                "per_server": per_server,
                "note": "Literal scanner; count is a lower bound on a full impl scanner.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Raw results written to {out_path}")


if __name__ == "__main__":
    main()
