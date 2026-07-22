#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Automatic capability-policy derivation from MCP tool schemas.

This is the derivation engine that the MCPGuard-Dynamic paper claims exists.
It obtains each server's advertised tool list + input schemas by invoking the
server's MCP ``tools/list`` method over stdio JSON-RPC (the same interface a
real client uses), then applies a fixed, server-agnostic rule set (paper
Appendix A) to emit a per-tool capability policy.

The rule set, applied per tool, per declared parameter:

  1. param named path|file|filepath|filename|directory (type string)
       -> filesystem READ scoped to ./workspace/**
  2. param whose *description* contains write|save|output|create
       -> extend filesystem to WRITE, same scope (./workspace/**)
  3. param named url|endpoint|webhook (type string)
       -> network egress to the host named in the description if one is
          declared, else an empty allow-list flagged needs_override
  4. param whose name/description references env vars (env_var|
     environment_variable)
       -> env READ for non-sensitive vars (HOME, USER, PATH, LANG);
          sensitive patterns (*_KEY, *_SECRET, *_TOKEN, *_PASSWORD,
          *_CREDENTIAL) are ALWAYS denied regardless of the schema
  5. all other params contribute nothing; a tool with no recognized param
     gets a minimal policy (no fs / net / env grants)

Output is written to policies/derived/<server>.json in the same structure as
policies/defaults/filesystem_server.json.

The derivation only ever consumes the *declared schema* (names, types,
descriptions). It never reads the server implementation, so it cannot recover
capabilities that a server hard-codes rather than exposing as a parameter --
that limitation is a measured result, not a bug (see runner/policy_quality.py).
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent

# Workspace scope every filesystem grant is pinned to (paper Appendix A).
WORKSPACE_SCOPE = "./workspace/**"

# Parameter names that imply a filesystem path (rule 1).
PATH_PARAM_NAMES = {"path", "file", "filepath", "filename", "directory"}

# Description keywords that imply a write (rule 2).
WRITE_KEYWORDS = ("write", "save", "output", "create")

# Parameter names that imply network egress (rule 3).
URL_PARAM_NAMES = {"url", "endpoint", "webhook"}

# Non-sensitive env vars that may be read when a param references the env (rule 4).
NON_SENSITIVE_ENV = ["HOME", "USER", "PATH", "LANG"]

# Sensitive env patterns that are ALWAYS denied regardless of schema (rule 4).
SENSITIVE_ENV_DENY = [
    "*_KEY",
    "*_SECRET",
    "*_TOKEN",
    "*_PASSWORD",
    "*_CREDENTIAL",
]

# Registry: server policy name -> command to launch it over stdio.
# 11 Python servers + 3 Node servers = 14 MCP servers.
_SERVERS_DIR = EXPERIMENTS_ROOT / "servers"
_JS_DIR = _SERVERS_DIR / "js"
SERVER_COMMANDS: Dict[str, List[str]] = {
    "filesystem_server": ["python3", str(_SERVERS_DIR / "filesystem_server.py")],
    "notes_server": ["python3", str(_SERVERS_DIR / "notes_server.py")],
    "weather_server": ["python3", str(_SERVERS_DIR / "weather_server.py")],
    "shell_server": ["python3", str(_SERVERS_DIR / "shell_server.py")],
    "sqlite_server": ["python3", str(_SERVERS_DIR / "sqlite_server.py")],
    "git_server": ["python3", str(_SERVERS_DIR / "git_server.py")],
    "env_server": ["python3", str(_SERVERS_DIR / "env_server.py")],
    "malicious_server": ["python3", str(_SERVERS_DIR / "malicious_server.py")],
    "trojan_server": ["python3", str(_SERVERS_DIR / "trojan_server.py")],
    "trojan_git_server": ["python3", str(_SERVERS_DIR / "trojan_git_server.py")],
    "trojan_sqlite_server": ["python3", str(_SERVERS_DIR / "trojan_sqlite_server.py")],
    "js_filesystem_server": ["node", str(_JS_DIR / "filesystem_server.js")],
    "js_malicious_server": ["node", str(_JS_DIR / "malicious_server.js")],
    "js_sqlite_server": ["node", str(_JS_DIR / "sqlite_server.js")],
}


def fetch_tool_schemas(server_name: str, command: List[str]) -> List[Dict[str, Any]]:
    """
    Launch an MCP server over stdio and return its advertised tool schemas.

    Sends the standard initialize / initialized / tools/list handshake and
    parses the tools/list result. Only the schema is read; no tool handler is
    invoked, so this is safe even for the malicious/trojan servers.
    """
    requests = (
        json.dumps({"jsonrpc": "2.0", "method": "initialize", "id": 1})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 2})
        + "\n"
    )
    proc = subprocess.run(
        command,
        input=requests,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(EXPERIMENTS_ROOT),
    )
    tools: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("id") == 2 and "result" in message:
            tools = message["result"].get("tools", [])
            break
    if not tools:
        raise RuntimeError(
            f"No tools/list response from {server_name}: stderr={proc.stderr[:500]!r}"
        )
    return tools


def _extract_host(description: str) -> Optional[str]:
    """Extract a hostname from a URL param description, if one is declared."""
    match = re.search(r"\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", description.lower())
    return match.group(1) if match else None


def _references_env(lname: str, pdesc: str) -> bool:
    """Check if a parameter references environment variables (rule 4)."""
    return (
        "env_var" in lname
        or "environment_variable" in lname
        or "env_var" in pdesc
        or "environment_variable" in pdesc
    )


def _apply_param_rules(
    lname: str,
    pspec: Dict[str, Any],
    pdesc: str,
    fs_read: List[str],
    fs_write: List[str],
    net_allow: List[str],
    env_read: List[str],
) -> bool:
    """Apply rules 1-4 to a single parameter. Returns True if net needs override."""
    ptype = pspec.get("type")
    net_needs_override = False

    # Rule 1: path-like string param -> filesystem read, workspace scope.
    if lname in PATH_PARAM_NAMES and ptype == "string":
        if WORKSPACE_SCOPE not in fs_read:
            fs_read.append(WORKSPACE_SCOPE)

    # Rule 2: write-implying description keyword -> filesystem write.
    if any(keyword in pdesc for keyword in WRITE_KEYWORDS):
        if WORKSPACE_SCOPE not in fs_write:
            fs_write.append(WORKSPACE_SCOPE)

    # Rule 3: url-like string param -> network egress.
    if lname in URL_PARAM_NAMES and ptype == "string":
        host = _extract_host(pspec.get("description") or "")
        if host:
            if host not in net_allow:
                net_allow.append(host)
        else:
            net_needs_override = True

    # Rule 4: env-referencing param -> non-sensitive env read only.
    if _references_env(lname, pdesc):
        for var in NON_SENSITIVE_ENV:
            if var not in env_read:
                env_read.append(var)

    return net_needs_override


def derive_tool_policy(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Apply the Appendix A rule set to a single tool schema."""
    properties = tool.get("inputSchema", {}).get("properties", {}) or {}

    fs_read: List[str] = []
    fs_write: List[str] = []
    net_allow: List[str] = []
    net_needs_override = False
    env_read: List[str] = []

    for pname, pspec in properties.items():
        pspec = pspec or {}
        lname = pname.lower()
        pdesc = (pspec.get("description") or "").lower()

        override = _apply_param_rules(
            lname, pspec, pdesc, fs_read, fs_write, net_allow, env_read
        )
        net_needs_override = net_needs_override or override

    return _assemble_policy(
        fs_read=fs_read,
        fs_write=fs_write,
        net_allow=net_allow,
        net_needs_override=net_needs_override,
        env_read=env_read,
    )


def _assemble_policy(
    fs_read: List[str],
    fs_write: List[str],
    net_allow: List[str],
    net_needs_override: bool,
    env_read: List[str],
) -> Dict[str, Any]:
    """Build the per-tool policy object (structure of filesystem_server.json)."""
    network: Dict[str, Any] = {"allow": net_allow}
    if net_needs_override:
        network["needs_override"] = True

    syscall_allow = ["read", "open", "openat", "close", "fstat", "stat", "lstat"]
    syscall_deny = ["execve", "bind", "listen", "accept"]
    if fs_read:
        syscall_allow.append("getdents")
    if fs_write:
        syscall_allow.extend(["write", "mkdir"])
    if net_allow or net_needs_override:
        syscall_allow.extend(["socket", "connect"])
    else:
        syscall_deny.append("connect")

    return {
        "filesystem": {"read": fs_read, "write": fs_write},
        "network": network,
        "env_vars": {"read": env_read, "deny": list(SENSITIVE_ENV_DENY)},
        "syscalls": {"allow": syscall_allow, "deny": syscall_deny},
    }


def derive_server_policy(server_name: str, command: List[str]) -> Dict[str, Any]:
    """Derive a full per-server policy document from the server's schemas."""
    tools = fetch_tool_schemas(server_name, command)
    tool_policies = {tool["name"]: derive_tool_policy(tool) for tool in tools}
    return {"server": server_name, "tools": tool_policies}


def _summarize(server_name: str, policy: Dict[str, Any]) -> str:
    """One-line summary of what fired for a server (for the console log)."""
    parts = []
    for tool_name, tp in policy["tools"].items():
        caps = []
        if tp["filesystem"]["read"]:
            caps.append("fs_r")
        if tp["filesystem"]["write"]:
            caps.append("fs_w")
        if tp["network"]["allow"] or tp["network"].get("needs_override"):
            caps.append("net")
        if tp["env_vars"]["read"]:
            caps.append("env")
        parts.append(f"{tool_name}[{','.join(caps) if caps else 'minimal'}]")
    return f"  {server_name}: " + ", ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Derive capability policies from MCP tool schemas.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(EXPERIMENTS_ROOT / "policies" / "derived"),
        help="Directory to write derived per-server policies into.",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Deriving policies for {len(SERVER_COMMANDS)} MCP servers from schemas...")
    for server_name, command in sorted(SERVER_COMMANDS.items()):
        policy = derive_server_policy(server_name, command)
        out_path = out_dir / f"{server_name}.json"
        out_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        print(_summarize(server_name, policy))
    print(f"Derived policies written to {out_dir}")


if __name__ == "__main__":
    main()
