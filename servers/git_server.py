#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCP Git Server.

Mimics mcp-server-git.
Tools: git_log, git_status, git_diff.
Uses subprocess to run actual git commands in the workspace.
Falls back to canned responses if git is not available.
"""

import subprocess
import sys
from pathlib import Path

_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer

_CANNED_LOG = (
    "abc1234 2025-04-30 Fix login validation\n"
    "def5678 2025-04-29 Add user dashboard\n"
    "ghi9012 2025-04-28 Update README\n"
)

_CANNED_STATUS = "On branch main\nnothing to commit, working tree clean\n"

_CANNED_DIFF = (
    "diff --git a/README.md b/README.md\n"
    "--- a/README.md\n"
    "+++ b/README.md\n"
    "@@ -1,2 +1,3 @@\n"
    " # Project\n"
    "+Updated documentation\n"
)


def _run_git(cmd_args: list, cwd: str = ".") -> str:
    """Run a git command, returning stdout or None on failure."""
    try:
        result = subprocess.run(
            ["git"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=cwd,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def create_git_server() -> MCPServer:
    """Create a Git MCP server."""
    server = MCPServer(name="git_server", version="1.0.0")

    def git_log(args: dict) -> dict:
        count = int(args.get("count", 5))
        output = _run_git(["log", f"--max-count={count}", "--oneline", "--no-color"])
        if not output:
            output = "\n".join(_CANNED_LOG.strip().split("\n")[:count])
        return {"log": output.strip(), "count": count}

    def git_status(args: dict) -> dict:
        output = _run_git(["status", "--short"])
        if output is not None:
            return {"status": output.strip() if output.strip() else "clean"}
        return {"status": _CANNED_STATUS.strip()}

    def git_diff(args: dict) -> dict:
        output = _run_git(["diff", "--no-color"])
        if output is not None:
            return {"diff": output.strip() if output.strip() else "no changes"}
        return {"diff": _CANNED_DIFF.strip()}

    server.register_tool(
        name="git_log",
        description="Show recent git log entries",
        parameters={
            "count": {
                "type": "integer",
                "description": "Number of log entries to show (default 5)",
            },
        },
        handler=git_log,
    )
    server.register_tool(
        name="git_status",
        description="Show the git working tree status",
        parameters={},
        handler=git_status,
    )
    server.register_tool(
        name="git_diff",
        description="Show unstaged changes in the working tree",
        parameters={},
        handler=git_diff,
    )

    return server


if __name__ == "__main__":
    srv = create_git_server()
    srv.run()
