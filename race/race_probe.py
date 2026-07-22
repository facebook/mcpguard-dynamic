# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Fork-to-policy-update race microbenchmark for the MCPGuard eBPF sandbox.

Addresses reviewer critique D4 (ACSAC 535A): "there is a brief window where a
new child process can perform harmful syscalls before the BPF policy map is
updated."

We distinguish two windows and measure each empirically:

  * SERVER-STARTUP window: the userspace proxy spawns the server process and
    only *afterwards* inserts the server PID into pid_policy_map via bpftool.
    Between exec and that insert the server runs UNMONITORED.

  * CHILD-FORK window: fork_guard is attached to the sched_process_fork
    tracepoint, which fires synchronously in the parent's fork path (inside
    copy_process, before the child is woken). The child PID is therefore
    inserted before the child executes its first userspace instruction.

The controller process NEVER inserts its own PID (a monitored process cannot
spawn `sudo bpftool` -- proc_guard denies the exec), so it forks the monitored
subjects and performs all map operations itself.

SAFETY: the denied target is a planted benign fixture containing "SENTINEL"
under a directory deliberately excluded from the policy allow-list. No
destructive or exfiltration behavior is performed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field

import race_bpf as rb

SENTINEL = b"SENTINEL"

# Result classifications for a single denied-op attempt by a subject process.
SLIPPED = "SLIPPED"  # open succeeded and returned the sentinel -> race hit
BLOCKED = "BLOCKED"  # open denied by the BPF LSM -> enforced
ERROR = "ERROR"  # unexpected failure


@dataclass
class Fixtures:
    root: str
    sentinel: str


def plant_fixtures() -> Fixtures:
    root = tempfile.mkdtemp(prefix="mcpg_race_")
    denied_dir = os.path.join(root, "denied")
    os.makedirs(denied_dir)
    sentinel = os.path.join(denied_dir, "secret.txt")
    with open(sentinel, "wb") as f:
        f.write(SENTINEL)
    return Fixtures(root=root, sentinel=sentinel)


def _attempt_open(path: str) -> str:
    """Attempt the denied op. Runs inside a subject process."""
    try:
        fd = os.open(path, os.O_RDONLY)
        data = os.read(fd, 64)
        os.close(fd)
        return SLIPPED if SENTINEL in data else ERROR
    except PermissionError:
        return BLOCKED
    except OSError:
        return ERROR


def _child_report(write_fd: int, status: str) -> None:
    """Write a single-line result over an already-open pipe fd, then _exit."""
    ts = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    os.write(write_fd, f"{status} {ts}\n".encode())
    os._exit(0)


# --------------------------------------------------------------------------
# Experiment 1: SERVER-STARTUP window
# --------------------------------------------------------------------------


@dataclass
class TrialTiming:
    statuses: dict[str, int] = field(default_factory=dict)
    install_us: list[float] = field(default_factory=list)
    op_latency_us: list[float] = field(default_factory=list)

    def record(self, status: str) -> None:
        self.statuses[status] = self.statuses.get(status, 0) + 1

    def total(self) -> int:
        return sum(self.statuses.values())

    def slip_rate(self) -> float:
        n = self.total()
        return (self.statuses.get(SLIPPED, 0) / n) if n else 0.0


def run_startup_trial(
    fx: Fixtures, policy_id: int, mitigate: bool
) -> tuple[str, float, float]:
    """One server-startup trial.

    Without mitigation: fork the "server", which immediately opens the
    sentinel, while the controller races to install the policy afterwards.

    With mitigation (pre-insertion via stop-before-exec): the server SIGSTOPs
    itself as its first action; the controller installs the policy while it is
    stopped, then SIGCONTs it. The server's first real op is thus monitored.
    """
    r, w = os.pipe()
    t_fork = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    pid = os.fork()
    if pid == 0:
        os.close(r)
        if mitigate:
            os.kill(os.getpid(), signal.SIGSTOP)
        _child_report(w, _attempt_open(fx.sentinel))
        return ("", 0.0, 0.0)  # unreachable

    os.close(w)
    t0 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    if mitigate:
        # Wait until the child has stopped itself, then pre-insert.
        os.waitpid(pid, os.WUNTRACED)
        rb.insert_pid(pid, policy_id)
        os.kill(pid, signal.SIGCONT)
    else:
        rb.insert_pid(pid, policy_id)
    t_install = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    line = os.read(r, 64).decode().strip()
    os.close(r)
    os.waitpid(pid, 0)
    rb.delete_pid(pid)

    status, ts_op = line.split()
    install_us = (t_install - t0) / 1000.0
    op_latency_us = (int(ts_op) - t_fork) / 1000.0
    return status, install_us, op_latency_us


def run_startup(fx: Fixtures, n: int, mitigate: bool) -> TrialTiming:
    tt = TrialTiming()
    base = os.getpid() * 100
    for i in range(n):
        status, install_us, op_us = run_startup_trial(fx, base + (i % 50) + 1, mitigate)
        tt.record(status)
        tt.install_us.append(install_us)
        tt.op_latency_us.append(op_us)
    return tt


# --------------------------------------------------------------------------
# Experiment 2: CHILD-FORK window (1 level and recursive/grandchild)
# --------------------------------------------------------------------------


def _anchor_main(
    read_fd: int, write_fd: int, sentinel: str, n: int, levels: int
) -> None:
    """Runs inside the steady-state monitored anchor process.

    Waits for 'go', then for each trial forks down `levels` generations; the
    deepest descendant performs the denied op as its first action.
    """
    os.read(read_fd, 8)  # block until controller confirms we are monitored
    for _ in range(n):
        cr, cw = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(cr)
            _fork_descend(cw, sentinel, levels - 1)
            os._exit(0)  # unreachable
        os.close(cw)
        line = os.read(cr, 64)
        os.close(cr)
        os.waitpid(pid, 0)
        os.write(write_fd, line if line else b"ERROR 0\n")
    os._exit(0)


def _fork_descend(write_fd: int, sentinel: str, remaining: int) -> None:
    """In a subject process: recurse `remaining` more forks, then do the op."""
    if remaining <= 0:
        _child_report(write_fd, _attempt_open(sentinel))
        return
    pid = os.fork()
    if pid == 0:
        _fork_descend(write_fd, sentinel, remaining - 1)
        os._exit(0)
    os.waitpid(pid, 0)
    os._exit(0)


def run_childfork(fx: Fixtures, n: int, levels: int) -> TrialTiming:
    """levels=1: monitored anchor -> child does op.
    levels=2: monitored anchor -> child -> grandchild does op (recursive)."""
    policy_id = os.getpid() * 100 + 7
    ctrl_r, anchor_w = os.pipe()  # anchor -> controller (results)
    anchor_r, ctrl_w = os.pipe()  # controller -> anchor (go signal)

    anchor = os.fork()
    if anchor == 0:
        os.close(ctrl_r)
        os.close(ctrl_w)
        _anchor_main(anchor_r, anchor_w, fx.sentinel, n, levels)
        os._exit(0)
    os.close(anchor_w)
    os.close(anchor_r)

    # Establish steady state: register the anchor and confirm it landed.
    # No file policy is installed: file_guard denies-by-default for a monitored
    # PID with no file_policy, so enforcement is keyed purely on membership in
    # pid_policy_map -- which is exactly the map the race concerns.
    rb.insert_pid(anchor, policy_id)
    for _ in range(100):
        if rb.pid_in_map(anchor):
            break
        time.sleep(0.005)
    os.write(ctrl_w, b"go\n")

    tt = TrialTiming()
    buf = b""
    while tt.total() < n:
        chunk = os.read(ctrl_r, 4096)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            tt.record(line.decode().split()[0])

    os.close(ctrl_r)
    os.close(ctrl_w)
    os.waitpid(anchor, 0)
    _cleanup_policy(anchor)
    return tt


def _cleanup_policy(anchor_pid: int) -> None:
    for pid in rb.map_pids():
        rb.delete_pid(pid)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _pctl(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    idx = min(len(s) - 1, int(q * len(s)))
    return s[idx]


def summarize(name: str, tt: TrialTiming) -> dict:
    return {
        "experiment": name,
        "n": tt.total(),
        "statuses": tt.statuses,
        "slip_rate": round(tt.slip_rate(), 6),
        "install_window_us": {
            "median": round(statistics.median(tt.install_us), 1)
            if tt.install_us
            else 0,
            "p95": round(_pctl(tt.install_us, 0.95), 1),
            "max": round(max(tt.install_us), 1) if tt.install_us else 0,
        },
        "op_latency_us": {
            "median": round(statistics.median(tt.op_latency_us), 1)
            if tt.op_latency_us
            else 0,
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=200)
    ap.add_argument("--out", type=str, default="")
    args = ap.parse_args()

    if os.geteuid() == 0:
        print(
            "Run as an ordinary uid (controller must NOT be monitored).",
            file=sys.stderr,
        )
        sys.exit(2)

    fx = plant_fixtures()
    results = []
    try:
        results.append(
            summarize("startup_baseline", run_startup(fx, args.n, mitigate=False))
        )
        results.append(
            summarize("startup_mitigated", run_startup(fx, args.n, mitigate=True))
        )
        results.append(
            summarize("childfork_1level", run_childfork(fx, args.n, levels=1))
        )
        results.append(
            summarize(
                "childfork_2level_grandchild", run_childfork(fx, args.n, levels=2)
            )
        )
    finally:
        shutil.rmtree(fx.root, ignore_errors=True)
        for pid in rb.map_pids():
            rb.delete_pid(pid)

    report = {"n": args.n, "kernel": os.uname().release, "results": results}
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
