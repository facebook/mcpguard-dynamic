#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Policy-derivation quality measurement.

Scores two policy sets against an independent, source-derived ground truth:

  * derived      -- per-tool policies emitted by runner/derive_policy.py
  * agentbound   -- the AgentBound-style per-server manifests
                    (policies/defaults/agentbound/*.json)

Ground truth (policies/ground_truth/*.json) records, per tool, the legitimate
least-privilege footprint read from the server source, plus a separate 'covert'
block for planted attack behavior that a least-privilege policy must deny.

For each capability type (filesystem read, filesystem write, network, env read)
we score presence per (tool, capability): does the policy grant that capability,
and does the tool legitimately need it? From the confusion counts we report:

  * precision / recall per capability type and overall (micro-averaged)
  * FALSE-ALLOW rate = grants that are not legitimately needed (over-broad;
    dangerous) = FP / (TP + FP)
  * FALSE-DENY rate  = legitimate needs that are denied (benign breakage /
    operator override burden) = FN / (TP + FN)

As a secondary security check we also report covert-capability containment:
the fraction of planted attack capabilities each policy set would GRANT
(lower is better).
"""

import argparse
import fnmatch
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = EXPERIMENTS_ROOT / "policies"
DERIVED_DIR = POLICIES_DIR / "derived"
GROUND_TRUTH_DIR = POLICIES_DIR / "ground_truth"
AGENTBOUND_DIR = POLICIES_DIR / "defaults" / "agentbound"

CAP_TYPES = ["fs_read", "fs_write", "network", "env_read"]
CAP_LABELS = {
    "fs_read": "filesystem read",
    "fs_write": "filesystem write",
    "network": "network",
    "env_read": "env read",
}

# AgentBound's paper reports 80.9% automatic policy-generation accuracy.
AGENTBOUND_REPORTED_ACCURACY = 0.809


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _grants(cap_block: Dict[str, Any]) -> Dict[str, bool]:
    """Presence of each capability type in a filesystem/network/env policy block."""
    fs = cap_block.get("filesystem", {}) or {}
    net = cap_block.get("network", {}) or {}
    env = cap_block.get("env_vars", {}) or {}
    return {
        "fs_read": bool(fs.get("read")),
        "fs_write": bool(fs.get("write")),
        "network": bool(net.get("allow")) or bool(net.get("needs_override")),
        "env_read": bool(env.get("read")),
    }


def _fs_covered(resource: str, patterns: List[str]) -> bool:
    """Whether a concrete resource path is covered by any allow glob."""
    for pattern in patterns:
        if fnmatch.fnmatch(resource, pattern.replace("**", "*")):
            return True
    return False


def _env_covered(var: str, allow: List[str]) -> bool:
    """Whether a covert env read is permitted by an env allow-list."""
    if var == "*":
        return bool(allow)
    return var in allow or "*" in allow


def _host_covered(host: str, allow: List[str]) -> bool:
    """Whether a covert network host is covered by an allow-list entry."""
    bare = host.split(":", 1)[0]
    for entry in allow:
        entry_bare = entry.split(":", 1)[0]
        if entry_bare in (host, bare) or bare == entry_bare:
            return True
    return False


class Confusion:
    """Per-capability-type confusion counters for one policy set."""

    def __init__(self) -> None:
        self.counts = {cap: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for cap in CAP_TYPES}

    def observe(self, cap: str, granted: bool, needed: bool) -> None:
        cell = self.counts[cap]
        if granted and needed:
            cell["tp"] += 1
        elif granted and not needed:
            cell["fp"] += 1
        elif not granted and needed:
            cell["fn"] += 1
        else:
            cell["tn"] += 1

    def per_type(self) -> Dict[str, Dict[str, Any]]:
        out = {}
        for cap in CAP_TYPES:
            c = self.counts[cap]
            out[cap] = {
                **c,
                "precision": _ratio(c["tp"], c["tp"] + c["fp"]),
                "recall": _ratio(c["tp"], c["tp"] + c["fn"]),
            }
        return out

    def totals(self) -> Dict[str, Any]:
        tp = sum(c["tp"] for c in self.counts.values())
        fp = sum(c["fp"] for c in self.counts.values())
        fn = sum(c["fn"] for c in self.counts.values())
        tn = sum(c["tn"] for c in self.counts.values())
        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "false_allow_rate": _ratio(fp, tp + fp),
            "false_deny_rate": _ratio(fn, tp + fn),
        }


def _ratio(num: int, den: int) -> Optional[float]:
    return round(num / den, 4) if den else None


def _score_covert(
    items: List[str],
    derived_allow: List[str],
    ab_allow: List[str],
    matcher: Callable[[str, List[str]], bool],
    result: Dict[str, int],
) -> None:
    """Tally covert items of one capability type against both policy sets."""
    for item in items:
        result["total"] += 1
        if matcher(item, derived_allow):
            result["granted_derived"] += 1
        if matcher(item, ab_allow):
            result["granted_agentbound"] += 1


def _covert_containment(
    ground_truth: Dict[str, Dict[str, Any]],
    derived: Dict[str, Dict[str, Any]],
    agentbound_block: Dict[str, Any],
) -> Dict[str, int]:
    """
    Count planted covert (tool, capability) items and how many each policy set
    would GRANT (fail to contain). Lower granted counts are better.
    """
    result = {"total": 0, "granted_derived": 0, "granted_agentbound": 0}
    ab_fs = agentbound_block.get("filesystem", {}) or {}
    ab_net = agentbound_block.get("network", {}) or {}
    ab_env = agentbound_block.get("env_vars", {}) or {}

    for tool_name, gt in ground_truth.items():
        covert = gt.get("covert") or {}
        if not covert:
            continue
        d_tool = derived.get(tool_name, {})
        d_fs = d_tool.get("filesystem", {}) or {}
        d_net = d_tool.get("network", {}) or {}
        d_env = d_tool.get("env_vars", {}) or {}
        c_fs = covert.get("filesystem", {}) or {}
        c_net = covert.get("network", {}) or {}
        c_env = covert.get("env_vars", {}) or {}

        _score_covert(
            c_fs.get("read", []),
            d_fs.get("read", []),
            ab_fs.get("read", []),
            _fs_covered,
            result,
        )
        _score_covert(
            c_fs.get("write", []),
            d_fs.get("write", []),
            ab_fs.get("write", []),
            _fs_covered,
            result,
        )
        _score_covert(
            c_net.get("allow", []),
            d_net.get("allow", []),
            ab_net.get("allow", []),
            _host_covered,
            result,
        )
        _score_covert(
            c_env.get("read", []),
            d_env.get("read", []),
            ab_env.get("read", []),
            _env_covered,
            result,
        )

    return result


def evaluate() -> Dict[str, Any]:
    """Score derived and AgentBound policies against ground truth."""
    derived_conf = Confusion()
    agentbound_conf = Confusion()
    covert = {"total": 0, "granted_derived": 0, "granted_agentbound": 0}
    tool_count = 0
    server_count = 0

    for gt_path in sorted(GROUND_TRUTH_DIR.glob("*.json")):
        server = gt_path.stem
        gt_doc = _load(gt_path)
        gt_tools = gt_doc["tools"]
        derived_tools = _load(DERIVED_DIR / f"{server}.json")["tools"]
        agentbound_block = _load(AGENTBOUND_DIR / f"{server}.json")
        ab_grants = _grants(agentbound_block)
        server_count += 1

        for tool_name, gt in gt_tools.items():
            tool_count += 1
            needed = _grants(gt)
            derived_granted = _grants(derived_tools.get(tool_name, {}))
            for cap in CAP_TYPES:
                derived_conf.observe(cap, derived_granted[cap], needed[cap])
                agentbound_conf.observe(cap, ab_grants[cap], needed[cap])

        server_covert = _covert_containment(gt_tools, derived_tools, agentbound_block)
        for key in covert:
            covert[key] += server_covert[key]

    return {
        "generated_at": time.time(),
        "servers": server_count,
        "tools": tool_count,
        "agentbound_reported_accuracy": AGENTBOUND_REPORTED_ACCURACY,
        "derived": {
            "per_type": derived_conf.per_type(),
            "overall": derived_conf.totals(),
        },
        "agentbound": {
            "per_type": agentbound_conf.per_type(),
            "overall": agentbound_conf.totals(),
        },
        "covert_containment": covert,
    }


def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _print_report(results: Dict[str, Any]) -> None:
    print()
    print("=" * 78)
    print("POLICY DERIVATION QUALITY  (derived vs AgentBound, vs source ground truth)")
    print("=" * 78)
    print(f"Servers: {results['servers']}   Tools: {results['tools']}")
    print()

    for approach in ("derived", "agentbound"):
        title = "DERIVED (schema-based, per-tool)"
        if approach == "agentbound":
            title = "AGENTBOUND (hand-authored, per-server)"
        print(f"--- {title} ---")
        header = f"{'capability':<18}{'precision':>11}{'recall':>9}"
        header += f"{'TP':>6}{'FP':>6}{'FN':>6}"
        print(header)
        per_type = results[approach]["per_type"]
        for cap in CAP_TYPES:
            row = per_type[cap]
            print(
                f"{CAP_LABELS[cap]:<18}"
                f"{_fmt(row['precision']):>11}{_fmt(row['recall']):>9}"
                f"{row['tp']:>6}{row['fp']:>6}{row['fn']:>6}"
            )
        overall = results[approach]["overall"]
        print(
            f"{'OVERALL (micro)':<18}"
            f"{_fmt(overall['precision']):>11}{_fmt(overall['recall']):>9}"
            f"{overall['tp']:>6}{overall['fp']:>6}{overall['fn']:>6}"
        )
        print(
            f"  false-allow rate (over-broad, DANGEROUS): "
            f"{_fmt(overall['false_allow_rate'])}"
        )
        print(
            f"  false-deny  rate (benign breakage)      : "
            f"{_fmt(overall['false_deny_rate'])}"
        )
        print()

    cov = results["covert_containment"]
    print(
        "--- COVERT-CAPABILITY CONTAINMENT (planted attacks; lower granted = better) ---"
    )
    print(f"  covert (tool,capability) items : {cov['total']}")
    print(f"  granted by derived             : {cov['granted_derived']}")
    print(f"  granted by AgentBound          : {cov['granted_agentbound']}")
    print()
    print(
        "AgentBound paper reports 80.9% automatic policy-generation accuracy; "
        "see POLICY_QUALITY.md for interpretation."
    )
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure policy derivation quality.")
    parser.add_argument(
        "--out",
        default=str(EXPERIMENTS_ROOT / "results" / "policy_quality" / "results.json"),
        help="Path to write raw results JSON.",
    )
    args = parser.parse_args()

    results = evaluate()
    _print_report(results)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"Raw results written to {out_path}")


if __name__ == "__main__":
    main()
