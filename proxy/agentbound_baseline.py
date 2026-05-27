# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
AgentBound Baseline Reproduction.

Implements per-SERVER policy enforcement (not per-tool) as described in the
AgentBound paper. All tools within a server share the same policy.

Key differences from MCPGuard:
  - Per-server granularity (vs per-tool in MCPGuard)
  - Application-level enforcement only (no OS-level)
  - Checks arguments but does not use eBPF
  - Policy loaded from manifest files
"""

import fnmatch
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse


class AgentBoundBaseline:
    """
    AgentBound-style per-server policy enforcement.

    Loads a per-server manifest that declares allowed filesystem paths,
    network destinations, and environment access. All tools in the server
    are subject to the same policy.
    """

    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load AgentBound-style manifest files."""
        if not self.policy_dir.exists():
            return
        for manifest_file in self.policy_dir.glob("*.json"):
            try:
                data = json.loads(manifest_file.read_text(encoding="utf-8"))
                server_name = data.get("server", manifest_file.stem)
                self._policies[server_name] = data
            except (json.JSONDecodeError, KeyError) as exc:
                print(
                    f"Warning: Failed to load AgentBound manifest {manifest_file}: {exc}",
                    file=sys.stderr,
                )

    def check(  # noqa: C901
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Check whether a tool call is allowed by the AgentBound server policy.

        Note: tool_name is accepted but NOT used for policy lookup -
        this is the key difference from MCPGuard's per-tool policies.

        Returns:
            {"action": "ALLOW"/"DENY", "reason": str}
        """
        policy = self._policies.get(server_name)
        if policy is None:
            return {
                "action": "DENY",
                "reason": f"No AgentBound manifest for server '{server_name}'",
            }

        # Check filesystem access (server-level)
        fs_policy = policy.get("filesystem", {})
        allowed_read = fs_policy.get("read", [])
        allowed_write = fs_policy.get("write", [])
        all_allowed_paths = allowed_read + allowed_write

        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                continue

            # Path validation
            if arg_name in ("path", "file", "filepath", "filename", "directory"):
                if os.path.isabs(arg_value):
                    return {
                        "action": "DENY",
                        "reason": (
                            f"AgentBound: absolute path '{arg_value}' "
                            f"not allowed for server '{server_name}'"
                        ),
                    }
                if ".." in arg_value:
                    return {
                        "action": "DENY",
                        "reason": (
                            f"AgentBound: path traversal in '{arg_value}' "
                            f"for server '{server_name}'"
                        ),
                    }
                if not self._path_matches_patterns(arg_value, all_allowed_paths):
                    return {
                        "action": "DENY",
                        "reason": (
                            f"AgentBound: path '{arg_value}' not allowed "
                            f"for server '{server_name}'"
                        ),
                    }

            # URL validation
            if arg_value.startswith(("http://", "https://")):
                net_policy = policy.get("network", {})
                allowed_domains = net_policy.get("allow", [])
                if not allowed_domains:
                    return {
                        "action": "DENY",
                        "reason": (
                            f"AgentBound: network access not allowed "
                            f"for server '{server_name}'"
                        ),
                    }
                try:
                    parsed = urlparse(arg_value)
                    hostname = parsed.hostname or ""
                    if not any(
                        hostname == d or hostname.endswith("." + d)
                        for d in allowed_domains
                    ):
                        return {
                            "action": "DENY",
                            "reason": (
                                f"AgentBound: domain '{hostname}' not allowed "
                                f"for server '{server_name}'"
                            ),
                        }
                except ValueError:
                    return {
                        "action": "DENY",
                        "reason": f"AgentBound: malformed URL '{arg_value}'",
                    }

            # Command validation (basic blocklist)
            if arg_name in ("command", "cmd"):
                cmd_policy = policy.get("commands", {})
                allowed_cmds = cmd_policy.get("allow", [])
                denied_cmds = cmd_policy.get("deny", ["*"])

                if "*" in denied_cmds:
                    # Check if command starts with an allowed prefix
                    cmd_base = arg_value.strip().split()[0] if arg_value.strip() else ""
                    if not any(
                        fnmatch.fnmatch(cmd_base, pattern) for pattern in allowed_cmds
                    ):
                        return {
                            "action": "DENY",
                            "reason": (
                                f"AgentBound: command '{cmd_base}' not in "
                                f"allowed list for server '{server_name}'"
                            ),
                        }

        return {"action": "ALLOW", "reason": "AgentBound check passed"}

    def _path_matches_patterns(self, path: str, patterns: List[str]) -> bool:
        """Check a relative path argument against server-level manifest globs."""
        if not patterns:
            return False

        norm_path = path.replace("\\", "/")
        for pattern in patterns:
            norm_pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(norm_path, norm_pattern):
                return True
            if norm_pattern.endswith("/**"):
                prefix = norm_pattern[:-3].rstrip("/")
                if norm_path.startswith(prefix + "/"):
                    return True
                if not norm_path.startswith("/") and not norm_path.startswith(".."):
                    prefixed = prefix + "/" + norm_path
                    if fnmatch.fnmatch(prefixed, norm_pattern):
                        return True
                    if prefix in (".", "./workspace"):
                        return True
        return False
