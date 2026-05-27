#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Repeated-call latency benchmark for MCPGuard configurations.

This runner measures a fixed benign tool call repeatedly so latency reporting is
not confounded by heterogeneous attack payloads that fail at different points.

Usage:
  python3 runner/latency_benchmark.py --run-id latency1
  python3 runner/latency_benchmark.py --run-id latency1 --iterations 100 --warmup 10
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.proxy_base import CONFIG_LAYERS, MCPProxy
from runner.evaluate import discover_test_cases, prepare_deterministic_fixtures


DEFAULT_CONFIGS = ["C0", "C-AB", "C-app", "C-ebpf", "C-full", "C-AB+ebpf"]


def _percentile(values: List[float], percentile: float) -> float:
    """Return nearest-rank percentile for a non-empty sorted sample."""
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = int(round((percentile / 100.0) * (len(sorted_values) - 1)))
    return sorted_values[index]


def _load_case(case_id: str) -> Dict[str, Any]:
    for case in discover_test_cases(EXPERIMENTS_ROOT / "test_cases"):
        if case.get("case_id") == case_id:
            return case
    raise ValueError(f"Unknown case id: {case_id}")


def _ensure_fixture_files(workspace_dir: Path) -> None:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    prepare_deterministic_fixtures(str(workspace_dir))
    readme_file = workspace_dir / "readme.txt"
    readme_file.write_text("This is a sample workspace file.\n", encoding="utf-8")
    (workspace_dir / "output").mkdir(parents=True, exist_ok=True)


def _stats(samples: List[float]) -> Dict[str, float]:
    if not samples:
        return {
            "count": 0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "stdev_ms": 0.0,
        }
    return {
        "count": len(samples),
        "mean_ms": statistics.fmean(samples),
        "median_ms": statistics.median(samples),
        "p95_ms": _percentile(samples, 95.0),
        "min_ms": min(samples),
        "max_ms": max(samples),
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
    }


def run_config(
    *,
    config: str,
    case: Dict[str, Any],
    iterations: int,
    warmup: int,
    workspace_dir: Path,
) -> Dict[str, Any]:
    """Run one config and return latency samples plus summary stats."""
    _ensure_fixture_files(workspace_dir)

    samples: List[float] = []
    warmup_samples: List[float] = []
    outer_samples: List[float] = []
    blocked = 0
    errors = 0

    proxy = MCPProxy(
        server_name=case["server"],
        config=config,
        workspace_dir=str(workspace_dir),
    )

    started_at = time.monotonic()
    startup_ms: Optional[float] = None
    try:
        proxy.start_server()
        startup_ms = (time.monotonic() - started_at) * 1000

        total_calls = warmup + iterations
        for i in range(total_calls):
            call_started = time.monotonic()
            result, defense_info = proxy.call_tool(
                tool_name=case["tool"],
                arguments=case["arguments"],
            )
            outer_ms = (time.monotonic() - call_started) * 1000
            latency_ms = defense_info["latency_ms"]

            if defense_info.get("blocked"):
                blocked += 1
            if result.get("isError"):
                errors += 1

            if i < warmup:
                warmup_samples.append(latency_ms)
            else:
                samples.append(latency_ms)
                outer_samples.append(outer_ms)
    finally:
        proxy.stop_server()

    return {
        "config": config,
        "layers": CONFIG_LAYERS.get(config, []),
        "startup_ms": startup_ms,
        "warmup": warmup,
        "iterations": iterations,
        "blocked_calls": blocked,
        "error_calls": errors,
        "latency_ms": samples,
        "outer_latency_ms": outer_samples,
        "warmup_latency_ms": warmup_samples,
        "stats": _stats(samples),
        "outer_stats": _stats(outer_samples),
    }


def _add_deltas(results: Dict[str, Any]) -> None:
    configs = results["configs"]
    c0 = configs.get("C0", {})
    c0_stats = c0.get("stats", {})
    c0_median = c0_stats.get("median_ms")
    c0_mean = c0_stats.get("mean_ms")
    if c0_median is None or c0_mean is None:
        return

    for config_result in configs.values():
        stats = config_result.get("stats", {})
        stats["delta_median_vs_c0_ms"] = stats.get("median_ms", 0.0) - c0_median
        stats["delta_mean_vs_c0_ms"] = stats.get("mean_ms", 0.0) - c0_mean


def _write_markdown(output_json: Path, results: Dict[str, Any]) -> Path:
    output_md = output_json.with_suffix(".md")
    lines = [
        "# MCPGuard Latency Benchmark",
        "",
        f"- Run ID: `{results['run_id']}`",
        f"- Case: `{results['case']['case_id']}` (`{results['case']['server']}.{results['case']['tool']}`)",
        f"- Iterations: {results['iterations']} measured + {results['warmup']} warmup per config",
        "",
        "| Config | Median ms | Mean ms | P95 ms | Delta median vs C0 | Blocked | Errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for config in DEFAULT_CONFIGS:
        config_result = results["configs"].get(config)
        if not config_result:
            continue
        if config_result.get("error"):
            lines.append(f"| {config} | error | error | error | error | 0 | 0 |")
            continue
        stats = config_result["stats"]
        lines.append(
            "| "
            f"{config} | "
            f"{stats['median_ms']:.3f} | "
            f"{stats['mean_ms']:.3f} | "
            f"{stats['p95_ms']:.3f} | "
            f"{stats.get('delta_median_vs_c0_ms', 0.0):+.3f} | "
            f"{config_result['blocked_calls']} | "
            f"{config_result['error_calls']} |"
        )
    lines.extend(
        [
            "",
            "Notes:",
            "- The benchmark starts one server per config, discards warmup calls, and times repeated benign calls through `MCPProxy.call_tool`.",
            "- These numbers measure steady-state proxy+server call latency, not server startup time.",
            "- eBPF configurations require BPF programs/maps to be installed before running this script.",
            "",
        ]
    )
    output_md.write_text("\n".join(lines), encoding="utf-8")
    return output_md


def run_latency_benchmark(
    *,
    run_id: str,
    case_id: str,
    configs: List[str],
    iterations: int,
    warmup: int,
) -> Dict[str, Any]:
    case = _load_case(case_id)
    workspace_dir = EXPERIMENTS_ROOT / "workspace"
    output_dir = EXPERIMENTS_ROOT / "results" / "latency"
    output_dir.mkdir(parents=True, exist_ok=True)

    results: Dict[str, Any] = {
        "run_id": run_id,
        "timestamp": time.time(),
        "case": {
            "case_id": case["case_id"],
            "server": case["server"],
            "tool": case["tool"],
            "arguments": case["arguments"],
        },
        "iterations": iterations,
        "warmup": warmup,
        "configs": {},
    }

    for config in configs:
        print(f"Running {config} latency benchmark...")
        try:
            config_result = run_config(
                config=config,
                case=case,
                iterations=iterations,
                warmup=warmup,
                workspace_dir=workspace_dir,
            )
            results["configs"][config] = config_result
            stats = config_result["stats"]
            print(
                f"  median={stats['median_ms']:.3f}ms "
                f"mean={stats['mean_ms']:.3f}ms p95={stats['p95_ms']:.3f}ms"
            )
        except Exception as exc:
            results["configs"][config] = {
                "config": config,
                "layers": CONFIG_LAYERS.get(config, []),
                "error": str(exc),
            }
            print(f"  ERROR: {exc}", file=sys.stderr)

    _add_deltas(results)

    output_json = output_dir / f"{run_id}.json"
    output_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    output_md = _write_markdown(output_json, results)
    print(f"\nResults written to {output_json}")
    print(f"Summary written to {output_md}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run repeated benign-call latency benchmark.",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case-id", default="BN-01")
    parser.add_argument(
        "--configs",
        nargs="*",
        default=DEFAULT_CONFIGS,
        choices=DEFAULT_CONFIGS,
    )
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--warmup", type=int, default=10)
    args = parser.parse_args()

    if args.iterations <= 0:
        raise ValueError("--iterations must be positive")
    if args.warmup < 0:
        raise ValueError("--warmup cannot be negative")

    run_latency_benchmark(
        run_id=args.run_id,
        case_id=args.case_id,
        configs=args.configs,
        iterations=args.iterations,
        warmup=args.warmup,
    )


if __name__ == "__main__":
    main()
