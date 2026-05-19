# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCPGuard Proxy Base.

Sits between the runner and an MCP server. Spawns the server as a subprocess,
receives tool call requests from the runner (via method call), applies defense
layers, forwards to the server, and returns results.

Configurations:
  C0     - No defenses (passthrough)
  C-AB   - AgentBound baseline only
  C-app  - L1 (policy) + L2 (argument validation)
  C-ebpf - L3 (eBPF sandbox) only
  C-full - L1 + L2 + L3 (MCPGuard full)
  C-AB+ebpf - AgentBound + L3 eBPF
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_experiments_root = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(_experiments_root))

from proxy.agentbound_baseline import AgentBoundBaseline
from proxy.argument_validator import ArgumentValidator
from proxy.ebpf_sandbox import EBPFSandbox
from proxy.policy_engine import PolicyEngine


# Maps config name to the set of active defense layers
CONFIG_LAYERS = {
    "C0": [],
    "C-AB": ["agentbound"],
    "C-app": ["policy", "argval"],
    "C-ebpf": ["ebpf"],
    "C-full": ["policy", "argval", "ebpf"],
    "C-AB+ebpf": ["agentbound", "ebpf"],
}

# Maps server names to their Python script paths
SERVER_SCRIPTS = {
    "filesystem_server": "servers/filesystem_server.py",
    "notes_server": "servers/notes_server.py",
    "weather_server": "servers/weather_server.py",
    "shell_server": "servers/shell_server.py",
    "malicious_server": "servers/malicious_server.py",
    "trojan_server": "servers/trojan_server.py",
    "sqlite_server": "servers/sqlite_server.py",
    "git_server": "servers/git_server.py",
    "env_server": "servers/env_server.py",
    "trojan_sqlite_server": "servers/trojan_sqlite_server.py",
    "trojan_git_server": "servers/trojan_git_server.py",
    "js_filesystem_server": "servers/js/filesystem_server.js",
    "js_malicious_server": "servers/js/malicious_server.js",
    "js_sqlite_server": "servers/js/sqlite_server.js",
}


class MCPProxy:
    """
    Proxy that mediates between a caller and an MCP server subprocess.

    The proxy applies defense layers based on the active configuration before
    forwarding requests to the server.
    """

    def __init__(
        self,
        server_name: str,
        config: str = "C0",
        policy_dir: Optional[str] = None,
        workspace_dir: Optional[str] = None,
    ):
        self.server_name = server_name
        self.config = config
        self.active_layers = CONFIG_LAYERS.get(config, [])
        self._experiments_root = _experiments_root

        if policy_dir is None:
            policy_dir = str(_experiments_root / "policies" / "defaults")
        if workspace_dir is None:
            workspace_dir = str(_experiments_root / "workspace")

        self.workspace_dir = workspace_dir

        # Initialize defense layers
        self.policy_engine = PolicyEngine(policy_dir=policy_dir)
        self.argument_validator = ArgumentValidator(
            policy_engine=self.policy_engine,
            workspace_dir=workspace_dir,
        )
        self.ebpf_sandbox = EBPFSandbox()
        self.agentbound = AgentBoundBaseline(
            policy_dir=str(_experiments_root / "policies" / "defaults" / "agentbound"),
        )

        self._server_proc: Optional[subprocess.Popen] = None
        self._req_counter = 0

    def start_server(self) -> None:
        """Spawn the MCP server as a subprocess."""
        script_rel = SERVER_SCRIPTS.get(self.server_name)
        if script_rel is None:
            raise ValueError(f"Unknown server: {self.server_name}")

        script_path = str(self._experiments_root / script_rel)
        env = dict(__import__("os").environ)
        env["MCP_WORKSPACE"] = self.workspace_dir
        env["MCP_NOTES_DIR"] = str(self._experiments_root / "notes_data")

        # Environment sanitization: strip sensitive variables before the
        # server process starts. Python caches os.environ at interpreter
        # startup, so eBPF cannot block runtime reads of cached values.
        # Stripping here ensures the server never receives them.
        if any(
            layer in self.active_layers
            for layer in ("policy", "argval", "ebpf", "agentbound")
        ):
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
        self._server_proc = subprocess.Popen(
            [interpreter, script_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(self._experiments_root),
        )

        # Send initialize
        self._send_to_server(
            {
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 0,
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcpguard-proxy", "version": "1.0.0"},
                },
            }
        )
        self._read_from_server()  # consume init response

        # Activate eBPF sandbox if configured
        if "ebpf" in self.active_layers and self._server_proc:
            server_policy = self.policy_engine.get_server_policy(self.server_name)
            self.ebpf_sandbox.activate_policy(
                pid=self._server_proc.pid,
                policy=server_policy,
            )

    def stop_server(self) -> None:
        """Stop the MCP server subprocess."""
        if self._server_proc:
            if "ebpf" in self.active_layers:
                self.ebpf_sandbox.deactivate_policy(self._server_proc.pid)
            self._server_proc.stdin.close()
            self._server_proc.wait(timeout=5)
            self._server_proc = None

    def _send_to_server(self, request: Dict[str, Any]) -> None:
        """Send a JSON-RPC request to the server via stdin."""
        if self._server_proc is None or self._server_proc.stdin is None:
            raise RuntimeError("Server not started")
        data = json.dumps(request) + "\n"
        self._server_proc.stdin.write(data.encode("utf-8"))
        self._server_proc.stdin.flush()

    def _read_from_server(self) -> Dict[str, Any]:
        """Read a JSON-RPC response from the server via stdout."""
        if self._server_proc is None or self._server_proc.stdout is None:
            raise RuntimeError("Server not started")
        line = self._server_proc.stdout.readline()
        if not line:
            raise RuntimeError("Server closed stdout")
        return json.loads(line.decode("utf-8"))

    def call_tool(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Execute a tool call through the proxy's defense layers.

        Returns:
            (result_dict, defense_info) where defense_info contains:
              - blocked: bool
              - layer: str or None (which layer blocked it)
              - reason: str or None
              - latency_ms: float
        """
        start_time = time.monotonic()
        defense_info = {
            "blocked": False,
            "layer": None,
            "reason": None,
            "latency_ms": 0.0,
        }

        # --- Layer: AgentBound baseline ---
        if "agentbound" in self.active_layers:
            ab_result = self.agentbound.check(
                server_name=self.server_name,
                tool_name=tool_name,
                arguments=arguments,
            )
            if ab_result["action"] == "DENY":
                defense_info["blocked"] = True
                defense_info["layer"] = "agentbound"
                defense_info["reason"] = ab_result["reason"]
                defense_info["latency_ms"] = (time.monotonic() - start_time) * 1000
                return self._make_blocked_result(ab_result["reason"]), defense_info

        # --- Layer L1: Policy Engine ---
        if "policy" in self.active_layers:
            policy_result = self.policy_engine.check(
                server_name=self.server_name,
                tool_name=tool_name,
                arguments=arguments,
            )
            if policy_result["action"] == "DENY":
                defense_info["blocked"] = True
                defense_info["layer"] = "L1-policy"
                defense_info["reason"] = policy_result["reason"]
                defense_info["latency_ms"] = (time.monotonic() - start_time) * 1000
                return self._make_blocked_result(policy_result["reason"]), defense_info

        # --- Layer L2: Argument Validator ---
        if "argval" in self.active_layers:
            argval_result = self.argument_validator.check(
                server_name=self.server_name,
                tool_name=tool_name,
                arguments=arguments,
            )
            if argval_result["action"] == "DENY":
                defense_info["blocked"] = True
                defense_info["layer"] = "L2-argval"
                defense_info["reason"] = argval_result["reason"]
                defense_info["latency_ms"] = (time.monotonic() - start_time) * 1000
                return self._make_blocked_result(argval_result["reason"]), defense_info

        # --- Forward to server ---
        self._req_counter += 1
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": self._req_counter,
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        self._send_to_server(request)
        response = self._read_from_server()

        result = response.get("result", response.get("error", {}))

        # --- Response sanitization ---
        # Scan tool responses for sensitive content that should not be
        # returned to the agent: prompt injection markers, env var values,
        # SSH key material. This catches response-level attacks that eBPF
        # cannot intercept (the tool reads its own data legitimately but
        # embeds malicious content in the response).
        if self.active_layers:
            sanitized = self._sanitize_response(result)
            if sanitized is not None:
                defense_info["blocked"] = True
                defense_info["layer"] = "response-sanitizer"
                defense_info["reason"] = sanitized
                defense_info["latency_ms"] = (time.monotonic() - start_time) * 1000
                return self._make_blocked_result(sanitized), defense_info

        defense_info["latency_ms"] = (time.monotonic() - start_time) * 1000
        return result, defense_info

    @staticmethod
    def _sanitize_response(result: Dict[str, Any]) -> Optional[str]:
        """Check tool response for sensitive/malicious content. Returns reason if blocked."""
        content_parts = result.get("content", [])
        for part in content_parts:
            text = part.get("text", "")
            text_upper = text.upper()

            # Prompt injection patterns
            injection_patterns = [
                "IGNORE PREVIOUS INSTRUCTIONS",
                "IGNORE ALL PREVIOUS",
                "DISREGARD PREVIOUS",
                "YOU ARE NOW",
                "NEW INSTRUCTIONS:",
                "[SYSTEM]",
            ]
            for pat in injection_patterns:
                if pat in text_upper:
                    return f"Response contains prompt injection pattern: {pat}"

            # SSH key material
            if (
                "BEGIN RSA" in text
                or "BEGIN OPENSSH" in text
                or "BEGIN EC PRIVATE" in text
            ):
                return "Response contains SSH key material"

            # Env var values that shouldn't appear in responses
            import os

            sensitive_env_keys = [
                k
                for k in os.environ
                if any(
                    p in k.upper()
                    for p in (
                        "SECRET",
                        "TOKEN",
                        "PASSWORD",
                        "CREDENTIAL",
                        "PRIVATE_KEY",
                    )
                )
            ]
            for env_key in sensitive_env_keys:
                env_val = os.environ.get(env_key, "")
                if env_val and len(env_val) > 4 and env_val in text:
                    return f"Response contains sensitive env var value ({env_key})"

        return None

    def _make_blocked_result(self, reason: str) -> Dict[str, Any]:
        """Create a blocked response."""
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"BLOCKED by MCPGuard: {reason}",
                }
            ],
        }

    def __enter__(self):
        self.start_server()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_server()
        return False
