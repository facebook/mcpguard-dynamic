# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCPGuard Layer 1: Policy Engine.

Loads JSON policy files from the policies directory and enforces per-tool
access control. For a given tool call, checks:
  - Is the tool allowed for this server?
  - Does the tool's declared capability match the request?
Returns ALLOW/DENY with reason.
"""

import fnmatch
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class PolicyEngine:
    """
    L1 defense layer that enforces declarative per-tool policies.

    Policy files define what each tool in a server is allowed to do:
    filesystem paths, network destinations, env vars, and syscalls.
    """

    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load all policy JSON files from the policy directory."""
        if not self.policy_dir.exists():
            return
        for policy_file in self.policy_dir.glob("*.json"):
            try:
                data = json.loads(policy_file.read_text(encoding="utf-8"))
                server_name = data.get("server", policy_file.stem)
                self._policies[server_name] = data
            except (json.JSONDecodeError, KeyError) as exc:
                print(
                    f"Warning: Failed to load policy {policy_file}: {exc}",
                    file=__import__("sys").stderr,
                )

    def get_server_policy(self, server_name: str) -> Dict[str, Any]:
        """Get the full policy dict for a server."""
        return self._policies.get(server_name, {})

    def get_tool_policy(
        self, server_name: str, tool_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get the policy for a specific tool on a server."""
        server_policy = self._policies.get(server_name, {})
        tools = server_policy.get("tools", {})
        return tools.get(tool_name)

    def check(  # noqa: C901
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Check whether a tool call is allowed by policy.

        Returns:
            {"action": "ALLOW"/"DENY", "reason": str}
        """
        server_policy = self._policies.get(server_name)
        if server_policy is None:
            return {
                "action": "DENY",
                "reason": f"No policy found for server '{server_name}'",
            }

        tool_policy = server_policy.get("tools", {}).get(tool_name)
        if tool_policy is None:
            return {
                "action": "DENY",
                "reason": f"Tool '{tool_name}' not declared in policy for server '{server_name}'",
            }

        # Check filesystem read access for path arguments
        fs_policy = tool_policy.get("filesystem", {})
        read_patterns = fs_policy.get("read", [])
        write_patterns = fs_policy.get("write", [])

        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                continue

            # Check if argument looks like a file path
            if arg_name in ("path", "file", "filepath", "filename", "directory"):
                # Determine if this is a read or write operation based on tool name
                if any(w in tool_name for w in ("read", "list", "get", "search")):
                    if not self._path_matches_patterns(arg_value, read_patterns):
                        return {
                            "action": "DENY",
                            "reason": (
                                f"Path '{arg_value}' not allowed for read by tool "
                                f"'{tool_name}' (allowed: {read_patterns})"
                            ),
                        }
                elif any(
                    w in tool_name for w in ("write", "create", "update", "delete")
                ):
                    if not self._path_matches_patterns(arg_value, write_patterns):
                        return {
                            "action": "DENY",
                            "reason": (
                                f"Path '{arg_value}' not allowed for write by tool "
                                f"'{tool_name}' (allowed: {write_patterns})"
                            ),
                        }

        # Check network policy for URL arguments
        net_policy = tool_policy.get("network", {})
        allowed_net = net_policy.get("allow", [])
        for _arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                continue
            if arg_value.startswith(("http://", "https://", "ftp://")):
                if not allowed_net:
                    return {
                        "action": "DENY",
                        "reason": f"Network access not allowed for tool '{tool_name}'",
                    }

        # Check for denied syscalls in command arguments
        syscall_policy = tool_policy.get("syscalls", {})
        denied_syscalls = syscall_policy.get("deny", [])
        if "command" in arguments and isinstance(arguments["command"], str):
            cmd = arguments["command"]
            # Check if command would trigger denied syscalls
            if "execve" in denied_syscalls:
                return {
                    "action": "DENY",
                    "reason": (
                        f"Command execution blocked: 'execve' syscall denied "
                        f"for tool '{tool_name}'"
                    ),
                }
            if "connect" in denied_syscalls and any(
                net_cmd in cmd
                for net_cmd in ("curl", "wget", "nc", "netcat", "ssh", "scp")
            ):
                return {
                    "action": "DENY",
                    "reason": (
                        f"Network command blocked: 'connect' syscall denied "
                        f"for tool '{tool_name}'"
                    ),
                }

        return {"action": "ALLOW", "reason": "Policy check passed"}

    def _path_matches_patterns(self, path: str, patterns: List[str]) -> bool:
        """Check if a path matches any of the allowed patterns."""
        if not patterns:
            return False

        # Normalize path
        norm_path = path.replace("\\", "/")

        for pattern in patterns:
            norm_pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(norm_path, norm_pattern):
                return True
            # Also check if the path is under the pattern directory
            if norm_pattern.endswith("/**"):
                prefix = norm_pattern[:-3]  # Remove /**
                if norm_path.startswith(prefix) or norm_path.startswith(
                    prefix.lstrip("./")
                ):
                    return True
                # Tool arguments are relative to the server's working dir
                # (e.g., workspace). A non-absolute, non-traversal path
                # like "readme.txt" is implicitly under the workspace.
                # Check if prepending the prefix makes it match.
                if not norm_path.startswith("/") and not norm_path.startswith(".."):
                    prefixed = prefix.rstrip("/") + "/" + norm_path
                    if fnmatch.fnmatch(prefixed, norm_pattern):
                        return True
                    # Also match the raw relative path against the glob
                    # portion of the pattern
                    if fnmatch.fnmatch(norm_path, "**"):
                        return True

        return False
