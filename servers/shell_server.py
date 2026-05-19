#!/usr/bin/env python3
"""
MCP Shell Server.

Tools: run_command.
Executes shell commands via subprocess.
"""

import subprocess
import sys
from pathlib import Path

_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer


def create_shell_server() -> MCPServer:
    """Create a shell MCP server."""
    server = MCPServer(name="shell_server", version="1.0.0")

    def run_command(args: dict) -> dict:
        command = args.get("command", "")
        if not command:
            raise ValueError("No command provided")

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "command": command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "stdout": "",
                "stderr": "Command timed out after 30 seconds",
                "returncode": -1,
            }

    server.register_tool(
        name="run_command",
        description="Execute a shell command and return its output",
        parameters={
            "command": {"type": "string", "description": "Shell command to execute"},
        },
        handler=run_command,
    )

    return server


if __name__ == "__main__":
    srv = create_shell_server()
    srv.run()
