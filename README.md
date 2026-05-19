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
├── notes_data/   155 synthetic notes JSON fixtures used by notes_server
├── runner/       evaluate.py, aggregate.py, smoke_test.py
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
python3 -m runner.smoke_test

# Full benchmark for one configuration
python3 -m runner.evaluate --config C-full --output results/C-full

# Aggregate across all configurations
python3 -m runner.aggregate results/ > aggregate.json
```

## Headline Results

Attack Prevention Rate (APR) and False Positive Rate (FPR) across the 14-server, 82-case benchmark:

| Config        | APR    | FPR  |
|---------------|--------|------|
| C0            | 46.0%  | 0/19 |
| C-AB          | 55.6%  | 0/19 |
| C-app         | 52.4%  | 0/19 |
| C-ebpf        | 63.5%  | 0/19 |
| C-full        | 68.3%  | 0/19 |
| C-AB + ebpf   | 69.8%  | 0/19 |

eBPF marginal value: +15.9 pp (C-app → C-full), +14.2 pp (C-AB → C-AB+ebpf).

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
