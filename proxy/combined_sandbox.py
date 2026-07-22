#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Composed defense: MCPGuard policy layers running OVER a bubblewrap sandbox.

This is the paper's "interchangeable isolation backend" thesis config, measured
as a first-class row rather than an analytical union. The MCP server subprocess
runs INSIDE the tuned WS6 bubblewrap profile (namespaces + read-only fs + no
network) AND every tool call is mediated by MCPGuard's application layers:

  * L1 policy engine (per-tool, schema-derived allow/deny)
  * L2 argument validator
  * response-content sanitizer (prompt-injection / SSH-key / env-value scan)

L3 eBPF is intentionally NOT part of this config. bubblewrap's ``--unshare-pid``
places the server in a fresh PID namespace as NSpid=2, while ``subprocess.Popen``
returns the host PID of the outer ``bwrap`` process. MCPGuard's eBPF per-PID
tracking keys ``pid_policy_map`` on the server's host PID and activates the
policy AFTER the initialize handshake -- i.e. after bwrap has already forked the
server -- so ``fork_guard`` cannot propagate the policy to the server's (distinct,
namespace-hidden) host PID. eBPF enforcement would therefore silently apply to
the wrong process. This was verified empirically (see BASELINES.md). Crucially,
eBPF also contributes no coverage the sandbox lacks: every viable attack that
MCPGuard-full catches but bubblewrap misses is caught by L1/L2/response-scanning
(all proxy-level, PID-independent), never by L3. Dropping eBPF here loses nothing
and avoids enforcing on the wrong PID.

The MCPGuard layers operate entirely in the (unprivileged) proxy process on the
JSON-RPC request/response stream, so they are agnostic to where or under which
PID namespace the server runs.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
from typing import Any, Dict, Optional

from proxy.process_sandbox import build_bwrap_command
from proxy.proxy_base import MCPProxy, SERVER_SCRIPTS

# Config name for the composed MCPGuard-over-bubblewrap defense.
COMBINED_CONFIG = "C-app+bwrap"


class CombinedMCPProxy(MCPProxy):
    """MCPProxy whose server subprocess runs inside a bubblewrap sandbox.

    Inherits the full MCPGuard ``call_tool`` pipeline (L1 policy, L2 argval,
    response sanitizer) from :class:`MCPProxy`; only server spawn/teardown is
    overridden to wrap the launch in bubblewrap. ``active_layers`` deliberately
    excludes ``ebpf`` (see module docstring).
    """

    def __init__(
        self,
        server_name: str,
        policy_dir: Optional[str] = None,
        workspace_dir: Optional[str] = None,
        audit_log_path: Optional[str] = None,
    ) -> None:
        super().__init__(
            server_name=server_name,
            config="C-app",  # L1 policy + L2 argval; response sanitizer is
            # active whenever active_layers is non-empty.
            policy_dir=policy_dir,
            workspace_dir=workspace_dir,
            audit_log_path=audit_log_path,
        )
        # Report the composed config name in audit events / defense_info.
        self.config = COMBINED_CONFIG
        # Bounded read: a sandboxed server should respond quickly (bwrap adds no
        # network hang), but a bound keeps a wedged server from stalling the run.
        self._read_timeout_s = 8.0
        self._timed_out = False

    def start_server(self) -> None:
        """Spawn the MCP server inside bubblewrap, then run the MCPGuard init.

        Mirrors :meth:`MCPProxy.start_server`'s environment handling (including
        MCPGuard's sensitive-env stripping, which is part of the policy layer's
        behavior) but wraps the launch command in the WS6 bubblewrap profile.
        No eBPF activation is performed.
        """
        script_rel = SERVER_SCRIPTS.get(self.server_name)
        if script_rel is None:
            raise ValueError(f"Unknown server: {self.server_name}")

        script_path = str(self._experiments_root / script_rel)
        env = dict(os.environ)
        env["MCP_WORKSPACE"] = self.workspace_dir
        env["MCP_NOTES_DIR"] = str(self._experiments_root / "notes_data")

        test_home = env.get("MCPGUARD_TEST_HOME")
        if test_home:
            env["HOME"] = test_home
        env.setdefault("AWS_SECRET_ACCESS_KEY", "MCPGUARD_TEST_SECRET")
        env.setdefault("MCPGUARD_API_TOKEN", "MCPGUARD_TEST_TOKEN")
        env.setdefault("SECRET_KEY", "MCPGUARD_TEST_SECRET_KEY")

        # MCPGuard environment sanitization (same as the app configs): strip
        # sensitive variables before the server starts so cached os.environ
        # reads cannot leak them.
        sensitive_patterns = (
            "SECRET",
            "TOKEN",
            "KEY",
            "PASSWORD",
            "CREDENTIAL",
            "API_KEY",
            "PRIVATE",
        )
        for key in list(env.keys()):
            if any(p in key.upper() for p in sensitive_patterns):
                del env[key]

        interpreter = "node" if script_path.endswith(".js") else sys.executable
        command = build_bwrap_command(
            experiments_root=self._experiments_root,
            workspace_dir=self.workspace_dir,
            script_path=script_path,
            interpreter=interpreter,
        )

        self._server_proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(self._experiments_root),
            # New session so the whole bwrap subtree can be torn down together.
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
                        "name": "mcpguard-combined-proxy",
                        "version": "1.0.0",
                    },
                },
            }
        )
        self._read_from_server()

    def _read_from_server(self) -> Dict[str, Any]:
        """Read a JSON-RPC response, bounded by ``self._read_timeout_s``.

        On timeout the (wedged) sandboxed server is killed and a synthetic error
        response is returned so the call registers as failed/contained rather
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
        """Kill the server's entire process group (bwrap parent + children)."""
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
        """Stop the sandboxed MCP server and its bwrap subtree.

        Overrides :meth:`MCPProxy.stop_server` to avoid any eBPF deactivation
        (no eBPF policy was ever activated) and to tear down the bwrap process
        group.
        """
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


def combined_available() -> tuple[bool, str]:
    """Return (available, detail): the composed config needs bwrap present."""
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, "bwrap")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True, candidate
    return False, "bwrap not installed"


if __name__ == "__main__":
    _ok, _detail = combined_available()
    print(
        json.dumps(
            {"config": COMBINED_CONFIG, "bwrap_available": _ok, "detail": _detail}
        )
    )
