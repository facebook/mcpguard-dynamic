# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCPGuard Layer 2: Argument Validator.

Validates tool call arguments before they reach the server:
  - validate_path: resolves to absolute, checks traversal, checks allowed patterns
  - validate_url: parses URL, checks domain/protocol
  - check_injection: checks for shell metacharacters, SQL patterns
Returns ALLOW/DENY with reason.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from proxy.policy_engine import PolicyEngine


# Shell metacharacters and dangerous patterns
_SHELL_METACHARACTERS = set("|;&$`(){}!<>")
_SHELL_INJECTION_PATTERNS = [
    r"\$\(",  # command substitution $(...)
    r"`[^`]+`",  # backtick command substitution
    r";\s*\w",  # command chaining
    r"\|\s*\w",  # piping
    r"&&\s*\w",  # logical AND chaining
    r"\|\|\s*\w",  # logical OR chaining
    r">\s*/",  # redirect to absolute path
    r">>\s*/",  # append to absolute path
]

_DANGEROUS_COMMAND_PATTERNS = [
    (r"^\s*sudo\b", "privileged sudo execution"),
    (r"^\s*su\b", "privileged user switch"),
    (r"\bchmod\s+(?:[0-7]{3,4}|[ugoas]*[+\-=])", "permission modification"),
    (r"\bchown\b", "ownership modification"),
    (r"\bchgrp\b", "group ownership modification"),
    (r"\bsetcap\b", "Linux capability modification"),
    (r"\bgit\s+config\s+(?:--global|--system)\b", "global git configuration change"),
]

# SQL injection patterns
_SQL_INJECTION_PATTERNS = [
    r"'\s*(?:OR|AND)\s+",
    r"^\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s+",
    r";\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s",
    r"UNION\s+(?:ALL\s+)?SELECT",
    r"--\s*$",
]

# Sensitive file paths that should never be accessed
_SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/maps",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/authorized_keys",
    ".aws/credentials",
    ".aws/config",
    ".env",
    ".bashrc",
    ".bash_history",
    ".zsh_history",
    "/tmp/exfil",
    "/tmp/evil_cron",
]

# Path traversal patterns
_TRAVERSAL_PATTERNS = [
    "..",
    "~",
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/root/",
    "/tmp/",
    "/var/",
]


class ArgumentValidator:
    """
    L2 defense layer that validates tool call arguments.

    Checks for path traversal, URL safety, and injection attacks before
    forwarding to the server.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        workspace_dir: str = "./workspace",
    ):
        self.policy_engine = policy_engine
        self.workspace_dir = Path(workspace_dir).resolve()

    def check(  # noqa: C901
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate all arguments of a tool call.

        Returns:
            {"action": "ALLOW"/"DENY", "reason": str}
        """
        tool_policy = self.policy_engine.get_tool_policy(server_name, tool_name)
        if tool_policy is None:
            # No policy means we can't validate - defer to L1
            return {
                "action": "ALLOW",
                "reason": "No tool policy for argument validation",
            }

        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                continue

            # Validate path arguments
            if arg_name in ("path", "file", "filepath", "filename", "directory"):
                result = self.validate_path(
                    path=arg_value,
                    tool_policy=tool_policy,
                    tool_name=tool_name,
                )
                if result["action"] == "DENY":
                    return result

            # Validate URL arguments
            if arg_value.startswith(("http://", "https://", "ftp://")):
                net_policy = tool_policy.get("network", {})
                allowed_domains = net_policy.get("allow", [])
                result = self.validate_url(
                    url=arg_value,
                    allowed_domains=allowed_domains,
                )
                if result["action"] == "DENY":
                    return result

            # Check for injection in command-like arguments
            if arg_name in ("command", "cmd", "query", "sql", "script"):
                result = self.check_injection(arg_value)
                if result["action"] == "DENY":
                    return result

            # Check for injection in all string values (lighter check)
            if arg_name == "content":
                result = self._check_content_injection(arg_value)
                if result["action"] == "DENY":
                    return result

            # Check config/key arguments for sensitive environment
            # variable names (e.g., get_config(key="AWS_SECRET_ACCESS_KEY")).
            if arg_name in ("key", "config_key", "env", "var"):
                result = self._check_sensitive_key(arg_value)
                if result["action"] == "DENY":
                    return result

        return {"action": "ALLOW", "reason": "Argument validation passed"}

    def validate_path(
        self,
        path: str,
        tool_policy: Dict[str, Any],
        tool_name: str,
    ) -> Dict[str, Any]:
        """
        Validate a file path argument.

        Checks:
          1. Path traversal attempts (.., ~, absolute paths to sensitive dirs)
          2. Sensitive file access
          3. Path within allowed patterns from policy
        """
        # Check for path traversal patterns
        normalized = os.path.normpath(path)
        for pattern in _TRAVERSAL_PATTERNS:
            if pattern in path or pattern in normalized:
                return {
                    "action": "DENY",
                    "reason": f"Path traversal detected: '{path}' contains '{pattern}'",
                }

        # Check for absolute paths outside workspace
        if os.path.isabs(path):
            return {
                "action": "DENY",
                "reason": f"Absolute path not allowed: '{path}'",
            }

        # Check sensitive file patterns
        for sensitive in _SENSITIVE_PATHS:
            if sensitive in path or sensitive in normalized:
                return {
                    "action": "DENY",
                    "reason": f"Access to sensitive path blocked: '{path}'",
                }

        # Resolve and check against workspace boundary
        try:
            resolved = (self.workspace_dir / path).resolve()
            if not str(resolved).startswith(str(self.workspace_dir)):
                return {
                    "action": "DENY",
                    "reason": (
                        f"Path escapes workspace: '{path}' resolves to "
                        f"'{resolved}' (workspace: '{self.workspace_dir}')"
                    ),
                }
        except (ValueError, OSError):
            return {
                "action": "DENY",
                "reason": f"Invalid path: '{path}'",
            }

        return {"action": "ALLOW", "reason": "Path validation passed"}

    def validate_url(
        self,
        url: str,
        allowed_domains: List[str],
    ) -> Dict[str, Any]:
        """
        Validate a URL argument.

        Checks:
          1. URL is well-formed
          2. Protocol is http or https
          3. Domain is in the allowed list
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return {
                "action": "DENY",
                "reason": f"Malformed URL: '{url}'",
            }

        if parsed.scheme not in ("http", "https"):
            return {
                "action": "DENY",
                "reason": f"Disallowed URL protocol: '{parsed.scheme}'",
            }

        if not allowed_domains:
            return {
                "action": "DENY",
                "reason": f"No domains allowed for this tool, got: '{url}'",
            }

        hostname = parsed.hostname or ""
        if not any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in allowed_domains
        ):
            return {
                "action": "DENY",
                "reason": f"Domain '{hostname}' not in allowed list: {allowed_domains}",
            }

        return {"action": "ALLOW", "reason": "URL validation passed"}

    def check_injection(self, value: str) -> Dict[str, Any]:
        """
        Check a value for shell and SQL injection patterns.

        Used for command-type arguments that will be executed.
        """
        # Check shell injection
        for pattern in _SHELL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return {
                    "action": "DENY",
                    "reason": f"Shell injection detected in value: pattern '{pattern}' matched",
                }

        for pattern, label in _DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return {
                    "action": "DENY",
                    "reason": f"Dangerous command blocked: {label}",
                }

        # Check for commands that leak environment variables.
        # Split on whitespace/pipes to find the base command.
        _ENV_LEAK_COMMANDS = [
            "printenv",
            "env",
            "/usr/bin/env",
            "/usr/bin/printenv",
        ]
        cmd_parts = re.split(r"[\s|;&]+", value.strip())
        for part in cmd_parts:
            if part in _ENV_LEAK_COMMANDS:
                return {
                    "action": "DENY",
                    "reason": (
                        f"Environment leak command blocked: "
                        f"'{part}' can expose sensitive variables"
                    ),
                }

        # Check for sensitive file reads in commands
        for sensitive in _SENSITIVE_PATHS:
            if sensitive in value:
                return {
                    "action": "DENY",
                    "reason": f"Command references sensitive path: '{sensitive}'",
                }

        # Check SQL injection
        for pattern in _SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return {
                    "action": "DENY",
                    "reason": f"SQL injection detected in value: pattern '{pattern}' matched",
                }

        return {"action": "ALLOW", "reason": "Injection check passed"}

    def _check_content_injection(self, value: str) -> Dict[str, Any]:
        """Lighter check for content fields - only checks for embedded commands."""
        # Check for prompt injection markers
        injection_markers = [
            "[SYSTEM]",
            "ignore previous instructions",
            "ignore all previous",
            "disregard previous",
            "override previous",
        ]
        value_lower = value.lower()
        for marker in injection_markers:
            if marker.lower() in value_lower:
                return {
                    "action": "DENY",
                    "reason": f"Prompt injection detected in content: '{marker}'",
                }

        return {"action": "ALLOW", "reason": "Content check passed"}

    def _check_sensitive_key(self, value: str) -> Dict[str, Any]:
        """Check if a key/config name refers to a sensitive env variable."""
        if any(marker in value for marker in ("..", "/", "\\")) or value.startswith(
            "~"
        ):
            return {
                "action": "DENY",
                "reason": f"Config key contains path traversal syntax: '{value}'",
            }

        sensitive_key_patterns = [
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "TOKEN",
            "PRIVATE_KEY",
            "ACCESS_KEY",
            "API_KEY",
            "AUTH",
            "CREDENTIAL",
        ]
        upper = value.upper()
        for pattern in sensitive_key_patterns:
            if pattern in upper:
                return {
                    "action": "DENY",
                    "reason": (
                        f"Sensitive key access blocked: "
                        f"'{value}' matches sensitive pattern '{pattern}'"
                    ),
                }
        return {"action": "ALLOW", "reason": "Key check passed"}
