#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Override-burden quantification for schema-derived policies.

The schema derivation (runner/derive_policy.py) is precise but denies most
legitimate capabilities (high false-deny), because production-style MCP servers
hard-code their resources instead of exposing them as parameters. Paper
Appendix A names the operator-override workflow as the mitigation. This script
quantifies that burden honestly:

  1. For every tool, compute the ground-truth legitimate capabilities that the
     derived policy DENIES (the false-deny set), at the concrete scope level.
  2. Emit each as an operator override file in the policies/overrides tool-level
     format (a `capabilities` patch naming only the missing capabilities).
  3. Merge overrides onto the derived policies with the real PolicyEngine and
     measure: how many servers need an override, how many override files, how
     many override JSON lines, and whether legitimate-capability coverage
     reaches 100%.
  4. Confirm that after the overrides ZERO covert (planted-attack) capabilities
     are granted -- i.e. the false-deny is resolved cheaply AND safely.

Everything is written under results/policy_quality/override_demo/ so the shared
policies/overrides directory (used by other runners) is not perturbed.
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy_quality import (  # noqa: E402
    _env_covered,
    _fs_covered,
    _host_covered,
    _load,
    DERIVED_DIR,
    GROUND_TRUTH_DIR,
)
from proxy.policy_engine import PolicyEngine  # noqa: E402

DEMO_ROOT = EXPERIMENTS_ROOT / "results" / "policy_quality" / "override_demo"

# (category, list-key, scored-capability-name)
CHANNELS: List[Tuple[str, str, str]] = [
    ("filesystem", "read", "fs_read"),
    ("filesystem", "write", "fs_write"),
    ("network", "allow", "network"),
    ("env_vars", "read", "env_read"),
]


def _channel_list(policy_block: Dict[str, Any], category: str, key: str) -> List[str]:
    return list((policy_block.get(category, {}) or {}).get(key, []) or [])


def _missing_capabilities(
    legit: Dict[str, Any], derived: Dict[str, Any]
) -> Dict[str, Dict[str, List[str]]]:
    """Legit scopes the derived policy does not already grant, by channel."""
    patch: Dict[str, Dict[str, List[str]]] = {}
    for category, key, _cap in CHANNELS:
        needed = _channel_list(legit, category, key)
        granted = set(_channel_list(derived, category, key))
        missing = [item for item in needed if item not in granted]
        if missing:
            patch.setdefault(category, {})[key] = missing
    return patch


def build_overrides() -> Dict[str, Any]:
    """Generate override files under the isolated demo tree; return a report."""
    derived_dst = DEMO_ROOT / "derived"
    override_dst = DEMO_ROOT / "overrides"
    if DEMO_ROOT.exists():
        shutil.rmtree(DEMO_ROOT)
    derived_dst.mkdir(parents=True, exist_ok=True)
    override_dst.mkdir(parents=True, exist_ok=True)

    # Copy derived policies so PolicyEngine's sibling "overrides" dir resolves here.
    for policy_file in sorted(DERIVED_DIR.glob("*.json")):
        shutil.copy2(policy_file, derived_dst / policy_file.name)

    servers_with_override: List[str] = []
    override_files = 0
    override_lines = 0
    capability_additions = 0
    per_server: Dict[str, Dict[str, Any]] = {}

    for gt_path in sorted(GROUND_TRUTH_DIR.glob("*.json")):
        server = gt_path.stem
        gt_tools = _load(gt_path)["tools"]
        derived_tools = _load(DERIVED_DIR / f"{server}.json")["tools"]

        server_files = 0
        server_caps = 0
        for tool_name, legit in gt_tools.items():
            derived_tool = derived_tools.get(tool_name, {})
            patch = _missing_capabilities(legit, derived_tool)
            if not patch:
                continue
            server_files += 1
            for _category, keyed in patch.items():
                for _key, items in keyed.items():
                    server_caps += len(items)

            override_doc = {"tool": tool_name, "capabilities": patch}
            text = json.dumps(override_doc, indent=2) + "\n"
            server_dir = override_dst / server
            server_dir.mkdir(parents=True, exist_ok=True)
            (server_dir / f"{tool_name}.json").write_text(text, encoding="utf-8")
            override_files += 1
            override_lines += len(text.splitlines())

        if server_files:
            servers_with_override.append(server)
            capability_additions += server_caps
            per_server[server] = {
                "override_files": server_files,
                "capability_additions": server_caps,
            }

    return {
        "servers_needing_override": servers_with_override,
        "server_count": len(servers_with_override),
        "override_files": override_files,
        "override_json_lines": override_lines,
        "capability_additions": capability_additions,
        "per_server": per_server,
        "derived_dir": str(derived_dst),
        "override_dir": str(override_dst),
    }


def _count_covert_grants(
    covert: Dict[str, Any], merged: Dict[str, Any]
) -> Tuple[int, int]:
    """Count covert items and how many are granted by the merged policy."""
    m_fs = merged.get("filesystem", {}) or {}
    m_net = merged.get("network", {}) or {}
    m_env = merged.get("env_vars", {}) or {}
    total = 0
    granted = 0
    for res in (covert.get("filesystem", {}) or {}).get("read", []):
        total += 1
        granted += _fs_covered(res, m_fs.get("read", []))
    for res in (covert.get("filesystem", {}) or {}).get("write", []):
        total += 1
        granted += _fs_covered(res, m_fs.get("write", []))
    for host in (covert.get("network", {}) or {}).get("allow", []):
        total += 1
        granted += _host_covered(host, m_net.get("allow", []))
    for var in (covert.get("env_vars", {}) or {}).get("read", []):
        total += 1
        granted += _env_covered(var, m_env.get("read", []))
    return total, granted


def _coverage_and_containment() -> Dict[str, Any]:
    """Merge overrides via PolicyEngine and measure coverage + covert grants."""
    engine = PolicyEngine(policy_dir=str(DEMO_ROOT / "derived"))

    total_needs = 0
    covered_needs = 0
    covert_total = 0
    covert_granted = 0

    for gt_path in sorted(GROUND_TRUTH_DIR.glob("*.json")):
        server = gt_path.stem
        gt_tools = _load(gt_path)["tools"]
        for tool_name, legit in gt_tools.items():
            merged = engine.get_tool_policy(server, tool_name) or {}

            for category, key, _cap in CHANNELS:
                needed = _channel_list(legit, category, key)
                if not needed:
                    continue
                granted = set(_channel_list(merged, category, key))
                for item in needed:
                    total_needs += 1
                    if item in granted:
                        covered_needs += 1

            covert = legit.get("covert") or {}
            ct, cg = _count_covert_grants(covert, merged)
            covert_total += ct
            covert_granted += cg

    return {
        "legit_needs": total_needs,
        "legit_covered_after_override": covered_needs,
        "coverage_fraction": round(covered_needs / total_needs, 4)
        if total_needs
        else None,
        "covert_items": covert_total,
        "covert_granted_after_override": int(covert_granted),
    }


def main() -> None:
    report = build_overrides()
    coverage = _coverage_and_containment()
    report["post_override"] = coverage

    print("=" * 78)
    print("OVERRIDE BURDEN  (resolving the derived policy's false-deny)")
    print("=" * 78)
    print(f"Servers needing an override : {report['server_count']} / 14")
    print(f"  {', '.join(report['servers_needing_override'])}")
    print(f"Override files (per tool)   : {report['override_files']}")
    print(f"Capability additions        : {report['capability_additions']}")
    print(f"Total override JSON lines    : {report['override_json_lines']}")
    print()
    print(f"{'server':<22}{'files':>7}{'caps':>7}")
    for server, stats in report["per_server"].items():
        print(
            f"{server:<22}{stats['override_files']:>7}{stats['capability_additions']:>7}"
        )
    print()
    print("--- After merging overrides (real PolicyEngine) ---")
    cov = report["post_override"]
    print(
        f"Legitimate-capability coverage : {cov['legit_covered_after_override']}"
        f"/{cov['legit_needs']} = {cov['coverage_fraction']:.3f}"
    )
    print(
        f"Covert capabilities granted    : {cov['covert_granted_after_override']}"
        f"/{cov['covert_items']}  (must stay 0)"
    )
    print("=" * 78)

    out_path = EXPERIMENTS_ROOT / "results" / "policy_quality" / "override_burden.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Raw results written to {out_path}")


if __name__ == "__main__":
    main()
