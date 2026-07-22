# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Thin bpftool helpers for the fork-to-policy-update race microbenchmark.

These mirror the byte layout used by proxy/ebpf_sandbox.py (pid_policy_entry
and file_policy structs) but are standalone so the benchmark can run under an
ordinary uid, escalating with sudo only for the BPF map operations, exactly
as the task's safety rules require.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys

# Must match ebpf/common.h
MAX_PATH_LEN = 256
MAX_PATH_RULES = 32

PIN_PATH = "/sys/fs/bpf/mcpguard"
SHARED_PID_MAP = f"{PIN_PATH}/pid_policy_map"
FILE_POLICY_MAP = f"{PIN_PATH}/file/file_policy_map"

# System paths a Python process needs to keep functioning while monitored.
# Copied from proxy/ebpf_sandbox.py (deliberately excludes /tmp and /proc/self).
SYSTEM_PATHS: list[str] = [
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/lib/",
    "/usr/local/bin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/dev/null",
    "/dev/urandom",
    "/dev/pts/",
    "/etc/ld.so",
    "/etc/localtime",
    "/usr/local/fbcode/",
    "/usr/share/",
]


def _le(val: int, nbytes: int) -> list[str]:
    return [f"0x{b:02x}" for b in val.to_bytes(nbytes, "little")]


def _run(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sudo", "bpftool"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def build_file_policy_value(allowed_prefixes: list[str]) -> bytes:
    """Pack a file_policy struct: MAX_PATH_RULES rules + rule_count (u32)."""
    rule_count = min(len(allowed_prefixes), MAX_PATH_RULES)
    out = bytearray()
    for i in range(MAX_PATH_RULES):
        if i < rule_count:
            raw = allowed_prefixes[i].encode("utf-8")[:MAX_PATH_LEN]
            raw = raw + b"\x00" * (MAX_PATH_LEN - len(raw))
            out.extend(raw)
            out.extend(struct.pack("BBBB", 1, 0, 0, 0))  # read, write, exec, pad
        else:
            out.extend(b"\x00" * (MAX_PATH_LEN + 4))
    out.extend(struct.pack("<I", rule_count))
    return bytes(out)


def write_file_policy(policy_id: int, allowed_prefixes: list[str]) -> None:
    """Install a file_policy for policy_id (read-only allow-list).

    The file_policy struct is ~8KB. bpftool caps the hex-token count it will
    parse for one map update, so we delegate to mapwrite.py, which issues the
    bpf() syscall directly (value passed as a single hex-string argument).
    """
    value = build_file_policy_value(allowed_prefixes)
    helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mapwrite.py")
    res = subprocess.run(
        [
            "sudo",
            sys.executable,
            helper,
            FILE_POLICY_MAP,
            policy_id.to_bytes(4, "little").hex(),
            value.hex(),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if res.returncode != 0:
        raise RuntimeError(f"file_policy update failed: {res.stderr[:200]}")


def insert_pid(pid: int, policy_id: int) -> None:
    """Insert pid -> pid_policy_entry{policy_id, flags=0} into the shared map."""
    res = _run(
        ["map", "update", "pinned", SHARED_PID_MAP, "key"]
        + _le(pid, 4)
        + ["value"]
        + _le(policy_id, 4)
        + _le(0, 4)
    )
    if res.returncode != 0:
        raise RuntimeError(f"pid insert failed: {res.stderr[:200]}")


def delete_pid(pid: int) -> None:
    _run(["map", "delete", "pinned", SHARED_PID_MAP, "key"] + _le(pid, 4))


def pid_in_map(pid: int) -> bool:
    res = _run(["map", "lookup", "pinned", SHARED_PID_MAP, "key"] + _le(pid, 4))
    return res.returncode == 0 and "value" in res.stdout.lower()


def map_pids() -> list[int]:
    """Return the list of PIDs currently present in the shared map."""
    import json

    res = _run(["map", "dump", "pinned", SHARED_PID_MAP, "-j"])
    if res.returncode != 0:
        return []
    pids: list[int] = []
    for entry in json.loads(res.stdout or "[]"):
        key = entry.get("key", [])
        if isinstance(key, list) and len(key) >= 4:
            raw = bytes(int(b, 0) if isinstance(b, str) else b for b in key[:4])
            pids.append(int.from_bytes(raw, "little"))
    return pids
