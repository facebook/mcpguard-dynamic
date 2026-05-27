<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# MCPGuard Experiment Execution Plan

## Prerequisites

| Requirement | Phase 0-1 (app-level) | Phase 2-3 (eBPF) |
|-------------|----------------------|-------------------|
| Python 3.10+ | Required | Required |
| Root access (sudo) | **Not needed** | Required |
| Kernel 6.9 + BPF LSM | Not needed | Required |
| bpftool / clang | Not needed | Required |
| pip / npm | Not needed | Not needed |
| Network access | Not needed | Not needed |

**Phase 0 and Phase 1 require NO special permissions.** Everything runs as the current user using Python stdlib only. No root, no sudo, no external packages.

Phase 2-3 require root for loading eBPF programs into the kernel.

---

## Phase 0: Smoke Test

**Goal**: Verify the harness works before committing to full evaluation.

```bash
cd experiments
python3 runner/smoke_test.py
```

**What it runs**: 3 attack cases (FR-05, EX-03, PE-01) across 2 configs (C0, C-app).

| Case | Attack | C0 (no defense) | C-app (L1+L2) |
|------|--------|-----------------|---------------|
| FR-05 | Hidden SSH key read by malicious summarize | Should succeed | Should pass through (hidden implementation behavior) |
| EX-03 | Network exfiltration by malicious translate | Should succeed | Should pass through (hidden implementation behavior) |
| PE-01 | `chmod 777 /tmp/test_file` via shell | Should succeed | Should block |

**Estimated time**: 10-30 seconds. Each case spawns a server subprocess, sends one JSON-RPC request, and checks the result. No LLM calls, no network, no API costs.

**Permissions**: None. Runs as current user.

**Success criteria**:
- C0: all 3 smoke attacks succeed (no defense = no blocking)
- C-app: at least one argument-visible attack is blocked while hidden implementation behavior remains a known app-layer limitation

**If it fails**: Fix harness bugs before proceeding. Common issues:
- Server subprocess fails to start → check `python3 servers/weather_server.py` runs standalone
- JSON parsing error → check test case JSON syntax
- Import error → verify running from `experiments/` directory

---

## Phase 1: App-Level Baselines

**Goal**: Establish baseline attack success (C0) and measure app-level defense coverage (C-AB, C-app).

```bash
cd experiments
python3 runner/evaluate.py --config C0 --run-id run1
python3 runner/evaluate.py --config C-AB --run-id run1
python3 runner/evaluate.py --config C-app --run-id run1
python3 runner/aggregate.py --run-id run1 --show-intrinsic-failures
```

**What it runs**: All 82 cases (61 attack + 21 benign) across 3 configs.

**Estimated time**: 5-15 minutes total (~3-5 min per config). Each case takes ~1-3 seconds (subprocess spawn + JSON-RPC roundtrip).

**Permissions**: None. Runs as current user.

**Expected results**:

| Config | Raw APR | Viable APR | FPR |
|--------|---------|------------|-----|
| C0 | Intrinsic-failure dependent | 0% | 0% |
| C-AB | 35-45% | 20-30% | 0% |
| C-app | 40-50% | 25-35% | 0% |

**Decision gate**: Use `--show-intrinsic-failures` to inspect any C0 attacks
that do not execute. Re-run after fixture or verifier fixes before treating raw
APR as a defense result.

---

## Phase 2: eBPF Implementation

**Goal**: Compile and test the eBPF sandbox programs.

```bash
cd experiments/ebpf
# Verify BPF LSM is active
python3 -c 'print(open("/sys/kernel/security/lsm", encoding="utf-8").read())'

# Compile eBPF programs
make

# Install BPF programs and pinned maps
sudo make install

# Test file_guard on a single case
sudo python3 ../runner/evaluate.py --config C-ebpf --run-id smoke --categories sandbox_escape
```

**Estimated time**: 2-4 days (implementation + debugging).

**Permissions**: Root required (sudo) for:
- Loading BPF programs into kernel (`bpf()` syscall)
- Attaching LSM hooks
- Accessing `/sys/kernel/btf/vmlinux`

**Key implementation tasks**:
1. Compile BPF programs with clang (`make` in `ebpf/`)
2. Implement policy map updates in `proxy/ebpf_sandbox.py`
3. Test server-lifetime eBPF policy activation and fail-closed map updates
4. Verify file_guard blocks `open("/etc/passwd")` for monitored PIDs
5. Verify net_guard blocks `connect()` to unauthorized endpoints
6. Verify proc_guard blocks `execve()` for child process spawn

---

## Phase 3: Full Evaluation with eBPF

**Goal**: Run all configs including eBPF and produce final results.

```bash
cd experiments
cd ebpf && sudo make install && cd ..
sudo python3 runner/evaluate.py --config C-ebpf --run-id run1
sudo python3 runner/evaluate.py --config C-full --run-id run1
sudo python3 runner/evaluate.py --config C-AB+ebpf --run-id run1
python3 runner/aggregate.py --run-id run1
```

**What it runs**: All 82 cases across 3 eBPF-enabled configs.

The eBPF-enabled configurations fail closed if the BPF programs or pinned maps
are unavailable. A run that cannot activate L3 should be treated as invalid,
not as a fallback measurement.

**Estimated time**: 10-20 minutes total.

**Permissions**: Root required (eBPF program loading).

**Expected results**:

| Config | Raw APR | Viable APR | FPR | Latency (ms) |
|--------|---------|------------|-----|-------------|
| C-ebpf | 55-65% | 45-55% | 0% | 3-8 |
| C-full | 65-75% | 55-65% | 0% | 3-8 |
| C-AB+ebpf | 65-75% | 55-65% | 0% | 3-8 |

The main result is the viable-attack delta: eBPF substantially improves the
app-only and AgentBound-style baselines while preserving zero benign false
positives in the checked-in benchmark.

---

## Phase 4: Paper Results and Latency

**Goal**: Fill paper sections 5-9 with measured numbers and reproduce the steady-state latency table.

```bash
cd experiments
python3 runner/aggregate.py --canonical --format latex > results/table.tex
sudo python3 runner/latency_benchmark.py --run-id codex_20260523_latency --iterations 100 --warmup 20
python3 runner/override_workflow.py --run-id codex_20260523_override
sudo python3 runner/ebpf_edge_tests.py --run-id codex_20260523_ebpf_edges
python3 runner/agentbound_check.py --run-id codex_20260523_agentbound
```

The aggregate table does not need root. The latency benchmark should be run as
root when including eBPF configs because the eBPF controller checks that the
current process can update pinned BPF maps.

Pinned latency result:

| Config | Median | Mean | P95 | Delta median vs C0 |
|--------|-------:|-----:|----:|-------------------:|
| C0 | 0.362 ms | 0.377 ms | 0.487 ms | +0.000 ms |
| C-AB | 0.459 ms | 0.481 ms | 0.661 ms | +0.098 ms |
| C-app | 0.880 ms | 0.883 ms | 1.054 ms | +0.518 ms |
| C-ebpf | 0.520 ms | 0.559 ms | 0.823 ms | +0.159 ms |
| C-full | 0.850 ms | 0.938 ms | 1.141 ms | +0.488 ms |
| C-AB+ebpf | 0.740 ms | 0.714 ms | 0.920 ms | +0.379 ms |

Pinned audit/override result:

| Step | Result | Layer |
|------|--------|-------|
| Strict policy | Blocked benign `BN-01` read | L1-policy |
| After scoped override | Allowed benign `BN-01` read | none |

Pinned eBPF edge-test result:

| Check | Result |
|-------|--------|
| fail_closed_missing_maps | PASS |
| workspace_write_allowed | PASS |
| workspace_prefix_sibling_write_denied | PASS |
| tmp_write_denied | PASS |
| localhost_network_exfil_denied | PASS |

Pinned AgentBound-style check:

`codex_20260523_agentbound` passes 8/8 checks covering server-level path policy, command allowlists, URL denial, and the expected blind spot for implementation-hidden behavior.

---

## Quick Reference

| Phase | What | Time | Root needed? | Depends on |
|-------|------|------|-------------|-----------|
| 0 | Smoke test (3 cases × 2 configs) | 10-30 sec | No | Nothing |
| 1 | App-level baselines (82 cases × 3 configs) | 5-15 min | No | Phase 0 passes |
| 2 | eBPF implementation | 2-4 days | Yes | Phase 1 validates |
| 3 | Full eval with eBPF (82 cases × 3 configs) | 10-20 min | Yes | Phase 2 compiles |
| 4 | Paper results + latency | 1-2 days | Only for eBPF latency | Phase 3 completes |

**Total wall time (excluding Phase 2 implementation)**: ~1 hour of compute.
**Total calendar time**: ~8 days (mostly Phase 2 eBPF engineering).
