<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# MCPGuard-Dynamic

Kernel-level sandboxing for LLM agent tool calls made through the Model Context Protocol (MCP).

MCPGuard sits as a transparent proxy between an MCP client (the agent / runner) and an MCP server subprocess, applying three layered defenses to every tool invocation. The lowest layer is implemented in eBPF and enforces capability policies at the system-call boundary, so a malicious MCP server cannot bypass policy by hardcoding sensitive behavior inside its own implementation.

This repository contains the proxy, the eBPF programs, the 14-server / 82-case benchmark, and the evaluation harness used in the accompanying paper *Kernel-Level Sandboxing for LLM Agent Tool Calls via eBPF*.

## Architecture

| Layer | Component | Purpose |
|-------|-----------|---------|
| L1 | `proxy/policy_engine.py` | Per-server capability policy derived from each tool's MCP schema; allowlists for paths, network destinations, processes, env vars. |
| L2 | `proxy/argument_validator.py` | Application-level inspection of tool-call arguments: path canonicalization, URL validation, prompt-injection detection, env-leak / command-injection detection, sensitive-key scanning, response sanitization. |
| L3 | `ebpf/*.bpf.c` + `proxy/ebpf_sandbox.py` | OS-level enforcement: three BPF LSM programs (`file_guard`, `net_guard`, `proc_guard`) intercept `open()` / `connect()` / `execve()`, and one tracepoint program (`fork_guard`) tracks child processes via `sched_process_fork` so policy carries across forks. |

Six switchable defense configurations (`proxy/proxy_base.py`) cover the ablation space used in the paper: `C0` (passthrough), `C-AB` (AgentBound baseline), `C-app` (L1 + L2), `C-ebpf` (L3 only), `C-full` (L1 + L2 + L3), `C-AB+ebpf` (AgentBound + L3).

## Repository Layout

```
.
├── proxy/        L1 policy engine, L2 argument validator, L3 eBPF controller, AgentBound baseline
├── ebpf/         BPF C sources for file/net/proc/fork guards + Makefile + vmlinux.h
├── policies/     Per-server JSON capability policies (defaults + overrides)
├── servers/      14 MCP servers: 11 Python (filesystem, notes, weather, shell, sqlite, git, env + malicious/trojan variants) + 3 JavaScript (servers/js/)
├── test_cases/   82 benchmark scenarios across 7 categories (file_read, exfiltration, env_leak, sandbox_escape, priv_escalation, cross_language, benign)
├── notes_data/   170 valid synthetic notes JSON fixtures used by notes_server
├── runner/       evaluate.py, aggregate.py, agentbound_check.py, ebpf_edge_tests.py, latency_benchmark.py, override_workflow.py, smoke_test.py
└── EXECUTION_PLAN.md   Phase-by-phase reproduction instructions
```

## Requirements

- Linux kernel 6.x with BPF LSM enabled (`CONFIG_BPF_LSM=y`, `lsm=bpf` in kernel cmdline)
- `clang` 21 or newer with BPF target
- `bpftool` for loading BPF programs and maps
- Python 3.12 (standard library only — no third-party deps)
- Node.js 16+ (only for the JavaScript MCP servers under `servers/js/`)

## Quick Start

```bash
# Build the eBPF programs
cd ebpf && make && cd ..

# Smoke test (one server, a handful of cases)
python3 runner/smoke_test.py

# Full benchmark for one configuration
python3 runner/evaluate.py --config C-full --run-id trial

# Aggregate a reproduced run
python3 runner/aggregate.py --run-id trial

# Reproduce the steady-state latency table after installing eBPF
sudo python3 runner/latency_benchmark.py --run-id codex_20260523_latency --iterations 100 --warmup 20

# Reproduce the audit/override workflow
python3 runner/override_workflow.py --run-id codex_20260523_override

# Run focused eBPF edge tests after installing eBPF
sudo python3 runner/ebpf_edge_tests.py --run-id codex_20260523_ebpf_edges

# Run AgentBound-style baseline conformance checks
python3 runner/agentbound_check.py --run-id codex_20260523_agentbound
```

`C-ebpf`, `C-full`, and `C-AB+ebpf` now fail closed if the BPF LSM programs
and pinned maps are unavailable. Run them only after installing the eBPF layer
with root privileges.

## Headline Results

Attack Prevention Rate (APR), viable-attack APR (V-APR), and False Positive
Rate (FPR) for the single pinned run `codex_20260523_full` (14-server, 82-case
benchmark; this is the `fx_r` per-category profile — the paper's Table 1
reports N=5 means, so `C-app` here reads 13/48 vs the 12/48 mean):

| Config | APR | V-APR | Viable blocked | FPR |
|--------|-----|-------|----------------|-----|
| C0 | 21.3% | 0.0% | 0/48 | 0/21 |
| C-AB | 37.7% | 20.8% | 10/48 | 0/21 |
| C-app | 42.6% | 27.1% | 13/48 | 0/21 |
| C-ebpf | 60.7% | 50.0% | 24/48 | 0/21 |
| C-full | 68.9% | 60.4% | 29/48 | 0/21 |
| C-AB+ebpf | 67.2% | 58.3% | 28/48 | 0/21 |

APR includes attacks that fail intrinsically under C0. V-APR uses only attacks
that succeed under C0 as the denominator, which is the more conservative
measure of defense coverage.

The repeated benign-call latency benchmark is stored in the internal paper
workspace as `results/latency/codex_20260523_latency.md`. It measures `BN-01`
(`filesystem_server.read_file`) with 20 warmup calls and 100 measured calls per
configuration; C-full adds +0.488 ms median latency relative to C0 and remains
at 1.141 ms p95 for this fixed benign call. The public CodeSync tree excludes
`results/`, so external users regenerate this artifact with the command above.

The audit/override workflow is stored internally as
`results/audit/codex_20260523_override.md`. It demonstrates how a benign denial
is recorded as a structured audit event and resolved by adding a scoped
operator override under `policies/overrides`-compatible layout.

Focused eBPF edge tests are stored internally as
`results/ebpf_edges/codex_20260523_ebpf_edges.md`. They cover fail-closed map
availability, workspace write allow behavior, directory-prefix boundary denial,
`/tmp` staging denial, and localhost exfiltration denial.

The AgentBound-style baseline check is stored internally as
`results/agentbound/codex_20260523_agentbound.md`. It documents that `C-AB` is a
per-server, application-level reproduction and verifies the expected
argument-visible coverage and implementation-hidden blind spot.

## Threat Model

The MCP server is treated as untrusted. It may be benign-but-misconfigured, intentionally malicious, or a trojanized fork of a legitimate server. The agent / runner and the host OS are trusted. The eBPF layer assumes the kernel is uncompromised; in-kernel privilege escalations (CWE-269 in kernel modules) are out of scope.

## Citation

A BibTeX entry will be added here once the paper is published.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must sign Meta's CLA.

## Security

To report a security issue, see [SECURITY.md](SECURITY.md). Please do not file public GitHub issues for security reports.

## License

MIT — see [LICENSE](LICENSE).
