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

**What it runs**: 3 attack cases (FR-01, SE-01, EX-02) across 2 configs (C0, C-app).

| Case | Attack | C0 (no defense) | C-app (L1+L2) |
|------|--------|-----------------|---------------|
| FR-01 | Direct /etc/passwd read | Should succeed | Should block (path validation) |
| SE-01 | Reverse shell spawn | Should succeed | Should pass through (invisible to app-level) |
| EX-02 | DNS exfiltration | Should succeed | Should pass through (no URL in argument) |

**Estimated time**: 10-30 seconds. Each case spawns a server subprocess, sends one JSON-RPC request, and checks the result. No LLM calls, no network, no API costs.

**Permissions**: None. Runs as current user.

**Success criteria**:
- C0: all 3 attacks succeed (no defense = no blocking)
- C-app: FR-01 blocked (argument validation catches `/etc/passwd`), SE-01 and EX-02 pass through (app-level can't see direct syscalls)

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
python3 runner/aggregate.py
```

**What it runs**: All 50 cases (40 attack + 10 benign) across 3 configs.

**Estimated time**: 5-15 minutes total (~3-5 min per config). Each case takes ~1-3 seconds (subprocess spawn + JSON-RPC roundtrip).

**Permissions**: None. Runs as current user.

**Expected results**:

| Config | Overall APR | SE-APR | FPR |
|--------|-----------|--------|-----|
| C0 | ~0% | 0% | 0% |
| C-AB | 30-45% | 0% | 0% |
| C-app | 35-50% | 0% | 0% |

**Decision gate**: If C0 APR > 20% (attacks don't work), investigate why before proceeding. If C-AB blocks SE attacks (unexpected), re-examine the AgentBound implementation.

---

## Phase 2: eBPF Implementation

**Goal**: Compile and test the eBPF sandbox programs.

```bash
cd experiments/ebpf
# Verify BPF LSM is active
cat /sys/kernel/security/lsm | grep bpf

# Compile eBPF programs
make

# Test file_guard on a single case
sudo python3 ../runner/evaluate.py --config C-ebpf --run-id smoke --categories sandbox_escape --max-cases 1
```

**Estimated time**: 2-4 days (implementation + debugging).

**Permissions**: Root required (sudo) for:
- Loading BPF programs into kernel (`bpf()` syscall)
- Attaching LSM hooks
- Accessing `/sys/kernel/btf/vmlinux`

**Key implementation tasks**:
1. Compile BPF programs with clang (`make` in `ebpf/`)
2. Implement policy map updates in `proxy/ebpf_sandbox.py`
3. Test per-call policy switching (activate policy → forward call → deactivate)
4. Verify file_guard blocks `open("/etc/passwd")` for monitored PIDs
5. Verify net_guard blocks `connect()` to unauthorized endpoints
6. Verify proc_guard blocks `execve()` for child process spawn

---

## Phase 3: Full Evaluation with eBPF

**Goal**: Run all configs including eBPF and produce final results.

```bash
cd experiments
sudo python3 runner/evaluate.py --config C-ebpf --run-id run1
sudo python3 runner/evaluate.py --config C-full --run-id run1
sudo python3 runner/evaluate.py --config C-AB+ebpf --run-id run1
python3 runner/aggregate.py
```

**What it runs**: All 50 cases across 3 eBPF-enabled configs.

**Estimated time**: 10-20 minutes total.

**Permissions**: Root required (eBPF program loading).

**Expected results**:

| Config | Overall APR | SE-APR | FPR | Latency (ms) |
|--------|-----------|--------|-----|-------------|
| C-ebpf | 60-75% | 88-100% | 0% | 10-30 |
| C-full | 85-95% | 88-100% | <5% | 12-35 |
| C-AB+ebpf | 80-90% | 88-100% | <5% | 11-31 |

**The star result**: SE column — C-AB/C-app show 0%, C-full shows 88-100%.

---

## Phase 4: Paper Results

**Goal**: Fill paper sections 5-9 with measured numbers.

```bash
python3 runner/aggregate.py --format latex > results/table.tex
```

No special permissions needed. Uses results from Phases 1 and 3.

---

## Quick Reference

| Phase | What | Time | Root needed? | Depends on |
|-------|------|------|-------------|-----------|
| 0 | Smoke test (3 cases × 2 configs) | 10-30 sec | No | Nothing |
| 1 | App-level baselines (50 cases × 3 configs) | 5-15 min | No | Phase 0 passes |
| 2 | eBPF implementation | 2-4 days | Yes | Phase 1 validates |
| 3 | Full eval with eBPF (50 cases × 3 configs) | 10-20 min | Yes | Phase 2 compiles |
| 4 | Write paper results | 1-2 days | No | Phase 3 completes |

**Total wall time (excluding Phase 2 implementation)**: ~1 hour of compute.
**Total calendar time**: ~8 days (mostly Phase 2 eBPF engineering).
