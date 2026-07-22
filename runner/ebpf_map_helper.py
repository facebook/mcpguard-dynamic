#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Root helper for eBPF BPF-map operations (invoked via ``sudo``).

The MCPGuard eBPF real-probe runner runs the harness and the monitored MCP
server subprocess under the *invoking user's* uid.  The pinned BPF maps under
``/sys/fs/bpf/mcpguard`` are root-owned, so only the per-PID map read/write
operations need elevated privileges.  This helper is the *only* component that
runs as root: it receives a single JSON request describing which PID to
activate/deactivate and with which policy, then delegates to
``EBPFSandbox`` (which requires euid==0 to write the maps via the ``bpf()``
syscall).

Usage:
  sudo <python> runner/ebpf_map_helper.py <request.json>

Request schema:
  {"action": "activate", "pid": <int>, "policy": {<server policy dict>}}
  {"action": "deactivate", "pid": <int>}
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.ebpf_sandbox import EBPFSandbox  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: ebpf_map_helper.py <request.json>", file=sys.stderr)
        return 2

    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    action = request["action"]
    pid = int(request["pid"])

    sandbox = EBPFSandbox()
    if not sandbox.is_available():
        print(
            "eBPF programs/maps not available (need root + loaded BPF LSM)",
            file=sys.stderr,
        )
        return 3

    if action == "activate":
        sandbox.activate_policy(pid=pid, policy=request["policy"])
    elif action == "deactivate":
        sandbox.deactivate_policy(pid=pid)
    else:
        print(f"unknown action: {action}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
