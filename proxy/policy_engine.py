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

import json
import sys
from copy import deepcopy
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class PolicyEngine:
    """
    L1 defense layer that enforces declarative per-tool policies.

    Policy files define what each tool in a server is allowed to do:
    filesystem paths, network destinations, env vars, and syscalls.
    """

    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self.override_dir = self.policy_dir.parent / "overrides"
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._load_policies()
        self._load_overrides()

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
                    file=sys.stderr,
                )

    def _load_overrides(self) -> None:
        """Merge operator override JSON files into the loaded policies."""
        if not self.override_dir.exists():
            return

        for override_file in sorted(self.override_dir.glob("*.json")):
            self._load_server_override(override_file)

        for server_dir in sorted(self.override_dir.iterdir()):
            if not server_dir.is_dir():
                continue
            for override_file in sorted(server_dir.glob("*.json")):
                self._load_tool_override(server_dir.name, override_file)

    def _load_server_override(self, override_file: Path) -> None:
        try:
            data = json.loads(override_file.read_text(encoding="utf-8"))
            server_name = data.get("server", override_file.stem)
            base = self._policies.setdefault(
                server_name,
                {"server": server_name, "tools": {}},
            )
            self._policies[server_name] = self._merge_policy(base, data)
        except (json.JSONDecodeError, KeyError) as exc:
            print(
                f"Warning: Failed to load override {override_file}: {exc}",
                file=sys.stderr,
            )

    def _load_tool_override(self, server_name: str, override_file: Path) -> None:
        try:
            data = json.loads(override_file.read_text(encoding="utf-8"))
            tool_name = data.get("tool", override_file.stem)
            patch = data.get("capabilities", data)
            patch = {
                key: value
                for key, value in patch.items()
                if key not in ("server", "tool", "description")
            }
            server_policy = self._policies.setdefault(
                server_name,
                {"server": server_name, "tools": {}},
            )
            tools = server_policy.setdefault("tools", {})
            existing = tools.setdefault(tool_name, {})
            tools[tool_name] = self._merge_policy(existing, patch)
        except (json.JSONDecodeError, KeyError) as exc:
            print(
                f"Warning: Failed to load override {override_file}: {exc}",
                file=sys.stderr,
            )

    def _merge_policy(
        self, base: Dict[str, Any], patch: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Recursively merge policy overrides, unioning list values."""
        merged = deepcopy(base)
        for key, value in patch.items():
            if key == "server":
                merged[key] = value
            elif (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._merge_policy(merged[key], value)
            elif (
                key in merged
                and isinstance(merged[key], list)
                and isinstance(value, list)
            ):
                merged[key] = self._merge_lists(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged

    @staticmethod
    def _merge_lists(base: List[Any], patch: List[Any]) -> List[Any]:
        merged = list(base)
        for item in patch:
            if item not in merged:
                merged.append(item)
        return merged

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
                if not self._url_host_allowed(arg_value, allowed_net):
                    return {
                        "action": "DENY",
                        "reason": (
                            f"Network destination '{arg_value}' not in allowed "
                            f"list for tool '{tool_name}' (allowed: {allowed_net})"
                        ),
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
            if fnmatch(norm_path, norm_pattern):
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
                    if fnmatch(prefixed, norm_pattern):
                        return True
                    # Also match the raw relative path against the glob
                    # portion of the pattern
                    if fnmatch(norm_path, "**"):
                        return True

        return False

    @staticmethod
    def _url_host_allowed(url: str, allowed_net: List[str]) -> bool:
        """Check whether a URL's host matches the tool's network allow-list.

        Entries may be a bare host ("api.example.com"), "host:port", a
        wildcard ("*", "*:443", "0.0.0.0", "*.example.com"), or an IPv4
        address. A bare host entry also matches its subdomains, with the
        ``*.`` prefix restricting a wildcard to subdomains (not the apex).
        Malformed URLs fail closed.
        """
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            return False
        if not host:
            return False
        for entry in allowed_net:
            allowed_host = entry.split(":", 1)[0].strip()
            if allowed_host in ("*", "0.0.0.0", ""):
                return True
            if allowed_host.startswith("*."):
                if host.endswith(allowed_host[1:]):
                    return True
                continue
            if host == allowed_host or host.endswith("." + allowed_host):
                return True
        return False


if __name__ == "__main__":
    """Self-check for L1 network allow-list enforcement (regression test).

    Run with: python -m proxy.policy_engine
    """
    _root = Path(__file__).resolve().parent.parent
    _engine = PolicyEngine(str(_root / "policies" / "defaults"))
    _checks = [
        (
            "disallowed_host_denied",
            _engine.check(
                "malicious_server",
                "translate",
                {"text": "x", "url": "http://evil.com/exfil"},
            )["action"]
            == "DENY",
        ),
        (
            "allowed_host_allowed",
            _engine.check(
                "malicious_server",
                "translate",
                {"text": "x", "url": "http://api.translate.example.com/x"},
            )["action"]
            == "ALLOW",
        ),
        (
            "empty_allowlist_blocks_url",
            _engine.check(
                "shell_server",
                "run_command",
                {"command": "echo hi", "url": "http://a.com"},
            )["action"]
            == "DENY",
        ),
    ]
    _failed = [name for name, ok in _checks if not ok]
    for _name, _ok in _checks:
        print(f"{'PASS' if _ok else 'FAIL'} {_name}")
    if _failed:
        raise SystemExit(f"L1 network allow-list self-check failed: {_failed}")
    print("policy_engine self-check passed")
