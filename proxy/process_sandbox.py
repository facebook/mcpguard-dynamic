#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Process-level sandbox baselines for the MCPGuard-Dynamic benchmark.

These are MCP-UNAWARE process sandboxes evaluated as baselines against MCPGuard.
Each wraps the MCP server subprocess in an existing OS isolation primitive with
NO MCPGuard defense layers (no L1 policy, L2 argument validation, L3 eBPF, or
response sanitization). The goal is an honest head-to-head: process sandboxes
give coarse, container/kernel-level isolation but cannot express per-tool,
schema-derived policy and cannot inspect MCP response content.

Supported sandbox types:
  - "seccomp" : stdlib seccomp-BPF deny-list (execve/execveat/socket/connect).
                Python-only (see proxy/seccomp_wrapper.py).
  - "bwrap"   : bubblewrap namespace + filesystem restriction, no network.
  - "gvisor"  : gVisor runsc user-space kernel (runsc do, --network=none).

This module intentionally does NOT touch the eBPF layer or /sys/fs/bpf.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from proxy.proxy_base import _experiments_root, MCPProxy, SERVER_SCRIPTS

# Config name -> process sandbox type
SANDBOX_CONFIGS = {
    "C-seccomp": "seccomp",
    "C-bwrap": "bwrap",
    "C-gvisor": "gvisor",
}

_SECCOMP_WRAPPER = str(_experiments_root / "proxy" / "seccomp_wrapper.py")
_DEFAULT_RUNSC = os.environ.get("MCPGUARD_RUNSC", "/tmp/runsc")


def build_bwrap_command(
    experiments_root: Path,
    workspace_dir: str,
    script_path: str,
    interpreter: str,
) -> list[str]:
    """Build a bubblewrap command: minimal ro rootfs, rw workspace, no net.

    This is the tuned WS6 bwrap profile (0% FPR after manual per-server
    discovery): read-only /usr (with the usual /lib,/bin symlinks), a fresh
    /proc and /dev, a private tmpfs /tmp (so side-effect files never touch the
    host), the experiments tree read-only, and the two writable server data
    directories (workspace, notes_data) bind-mounted read-write. Host home is
    NOT exposed. Network namespace is unshared.

    /etc/passwd and /etc/group are bind-mounted read-only: without them the
    Node.js runtime aborts at startup (getpwuid on the unmapped uid). This is a
    per-runtime manual discovery -- the Python servers need no /etc at all, but
    the JS servers do -- illustrating the manual-configuration burden of a
    general-purpose namespace sandbox.
    """
    root = str(experiments_root)
    notes_dir = str(experiments_root / "notes_data")
    return [
        "bwrap",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--ro-bind",
        "/etc/passwd",
        "/etc/passwd",
        "--ro-bind",
        "/etc/group",
        "/etc/group",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        root,
        root,
        "--bind",
        workspace_dir,
        workspace_dir,
        "--bind",
        notes_dir,
        notes_dir,
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--chdir",
        root,
        interpreter,
        script_path,
    ]


class SandboxedMCPProxy(MCPProxy):
    """MCPProxy variant that wraps the server subprocess in a process sandbox.

    No MCPGuard defense layers are active: ``active_layers`` is empty, so
    ``call_tool`` (inherited) forwards every request unmodified and performs no
    response sanitization. All isolation comes from the wrapping sandbox.
    """

    def __init__(
        self,
        server_name: str,
        sandbox_type: str,
        workspace_dir: str | None = None,
        audit_log_path: str | None = None,
        runsc_path: str = _DEFAULT_RUNSC,
    ) -> None:
        self.server_name = server_name
        self.sandbox_type = sandbox_type
        self.config = f"C-{sandbox_type}"
        # No MCPGuard layers: the sandbox is the only defense.
        self.active_layers = []
        self._experiments_root = _experiments_root
        self.runsc_path = runsc_path

        if workspace_dir is None:
            workspace_dir = str(_experiments_root / "workspace")
        self.workspace_dir = workspace_dir

        self.audit_log_path = Path(audit_log_path) if audit_log_path else None
        if self.audit_log_path:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        self._server_proc: subprocess.Popen | None = None
        self._req_counter = 0
        # Max seconds to wait for a server response. gVisor's --network=none can
        # cause a raw socket connect() inside a server to hang past its own
        # timeout; a bounded read keeps the harness from blocking forever and
        # correctly treats an unresponsive server as a contained (failed) call.
        self._read_timeout_s = 8.0
        self._timed_out = False

    def _build_env(self, script_path: str) -> dict[str, str]:
        """Build the server environment, identical to the C0 passthrough env.

        No secret stripping is applied: unlike MCPGuard, a plain process sandbox
        does not scrub the environment, so /proc/self/environ and os.environ
        still expose the fake secrets.
        """
        env = dict(os.environ)
        env["MCP_WORKSPACE"] = self.workspace_dir
        env["MCP_NOTES_DIR"] = str(self._experiments_root / "notes_data")
        test_home = env.get("MCPGUARD_TEST_HOME")
        if test_home:
            env["HOME"] = test_home
        env.setdefault("AWS_SECRET_ACCESS_KEY", "MCPGUARD_TEST_SECRET")
        env.setdefault("MCPGUARD_API_TOKEN", "MCPGUARD_TEST_TOKEN")
        env.setdefault("SECRET_KEY", "MCPGUARD_TEST_SECRET_KEY")
        return env

    def _build_command(self, script_path: str, interpreter: str) -> list[str]:
        """Construct the sandboxed launch command for the MCP server."""
        if self.sandbox_type == "seccomp":
            if not script_path.endswith(".py"):
                raise NotImplementedError(
                    "seccomp baseline is Python-only (in-process runpy wrapper); "
                    f"cannot wrap non-Python server {script_path}"
                )
            return [sys.executable, _SECCOMP_WRAPPER, script_path]

        if self.sandbox_type == "bwrap":
            return self._build_bwrap_command(script_path, interpreter)

        if self.sandbox_type == "gvisor":
            return [
                self.runsc_path,
                "--rootless",
                "--network=none",
                "--platform=systrap",
                "--ignore-cgroups",
                "do",
                interpreter,
                script_path,
            ]

        raise ValueError(f"Unknown sandbox type: {self.sandbox_type}")

    def _build_bwrap_command(self, script_path: str, interpreter: str) -> list[str]:
        """Build a bubblewrap command: minimal ro rootfs, rw workspace, no net.

        Delegates to the module-level :func:`build_bwrap_command` so the exact
        WS6 bwrap profile is a single source of truth, reused by the composed
        MCPGuard+bwrap config (``proxy/combined_sandbox.py``).
        """
        return build_bwrap_command(
            experiments_root=self._experiments_root,
            workspace_dir=self.workspace_dir,
            script_path=script_path,
            interpreter=interpreter,
        )

    def start_server(self) -> None:
        """Spawn the MCP server subprocess inside the process sandbox."""
        script_rel = SERVER_SCRIPTS.get(self.server_name)
        if script_rel is None:
            raise ValueError(f"Unknown server: {self.server_name}")

        script_path = str(self._experiments_root / script_rel)
        interpreter = "node" if script_path.endswith(".js") else sys.executable
        env = self._build_env(script_path)
        command = self._build_command(script_path, interpreter)

        self._server_proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(self._experiments_root),
            # New session/process group so the whole sandbox subtree (e.g. the
            # runsc do parent plus its gofer/sandbox children) can be torn down
            # together; killing only the parent orphans the rest.
            start_new_session=True,
        )

        self._send_to_server(
            {
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 0,
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcpguard-sandbox-proxy",
                        "version": "1.0.0",
                    },
                },
            }
        )
        self._read_from_server()

    def _read_from_server(self) -> dict[str, Any]:
        """Read a JSON-RPC response, bounded by ``self._read_timeout_s``.

        On timeout the (hung) server is killed and a synthetic error response is
        returned so the tool call registers as a failed/contained call rather
        than blocking the harness indefinitely.
        """
        if self._server_proc is None or self._server_proc.stdout is None:
            raise RuntimeError("Server not started")
        ready, _, _ = select.select(
            [self._server_proc.stdout], [], [], self._read_timeout_s
        )
        if not ready:
            self._timed_out = True
            self._kill_process_tree()
            return {
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "Sandbox: server unresponsive within "
                                f"{self._read_timeout_s:.0f}s (call contained)"
                            ),
                        }
                    ],
                }
            }
        line = self._server_proc.stdout.readline()
        if not line:
            raise RuntimeError("Server closed stdout")
        return json.loads(line.decode("utf-8"))

    def _kill_process_tree(self) -> None:
        """Kill the server's entire process group (parent + sandbox children)."""
        if self._server_proc is None:
            return
        try:
            os.killpg(os.getpgid(self._server_proc.pid), signal.SIGKILL)
        except OSError:
            try:
                self._server_proc.kill()
            except OSError:
                pass

    def stop_server(self) -> None:
        """Stop the MCP server subprocess and its sandbox children."""
        if self._server_proc:
            try:
                if self._server_proc.stdin:
                    self._server_proc.stdin.close()
                self._server_proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                self._kill_process_tree()
                try:
                    self._server_proc.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            self._server_proc = None


def sandbox_available(
    sandbox_type: str, runsc_path: str = _DEFAULT_RUNSC
) -> tuple[bool, str]:
    """Return (available, detail) for a sandbox type on this host."""
    if sandbox_type == "seccomp":
        return True, "stdlib prctl seccomp-BPF (Python servers only)"
    if sandbox_type == "bwrap":
        found = _which("bwrap")
        return (found is not None), (found or "bwrap not installed")
    if sandbox_type == "gvisor":
        if os.path.exists(runsc_path) and os.access(runsc_path, os.X_OK):
            return True, runsc_path
        found = _which("runsc")
        return (found is not None), (found or "runsc not installed")
    return False, f"unknown sandbox type {sandbox_type}"


def _which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


if __name__ == "__main__":
    # Quick availability report.
    for _stype in ("seccomp", "bwrap", "gvisor"):
        _ok, _detail = sandbox_available(_stype)
        print(json.dumps({"sandbox": _stype, "available": _ok, "detail": _detail}))
