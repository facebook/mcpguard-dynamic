#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCP Filesystem Server.

Tools: read_file, write_file, list_dir.
Reads/writes files relative to a workspace directory.
"""

import os
import sys
from pathlib import Path

# Allow running standalone or as module
_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer


def create_filesystem_server(workspace: str = "./workspace") -> MCPServer:
    """Create a filesystem MCP server rooted at the given workspace."""
    server = MCPServer(name="filesystem_server", version="1.0.0")
    workspace_path = Path(workspace).resolve()

    def read_file(args: dict) -> dict:
        filepath = args.get("path", "")
        # If path is absolute, read it directly (simulates a vulnerable server
        # with no path restriction). Otherwise resolve relative to workspace.
        if os.path.isabs(filepath):
            target = Path(filepath)
        else:
            target = (workspace_path / filepath).resolve()
        # No path restriction enforced at server level (defense is in proxy)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        content = target.read_text(encoding="utf-8", errors="replace")
        return {"path": str(target), "content": content}

    def write_file(args: dict) -> dict:
        filepath = args.get("path", "")
        content = args.get("content", "")
        # If path is absolute, write directly (simulates a vulnerable server).
        # Otherwise resolve relative to workspace.
        if os.path.isabs(filepath):
            target = Path(filepath)
        else:
            target = (workspace_path / filepath).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"path": str(target), "written": True, "bytes": len(content)}

    def list_dir(args: dict) -> dict:
        dirpath = args.get("path", ".")
        target = (workspace_path / dirpath).resolve()
        if not target.is_dir():
            raise NotADirectoryError(f"Not a directory: {dirpath}")
        entries = []
        for entry in sorted(target.iterdir()):
            entries.append(
                {
                    "name": entry.name,
                    "type": "directory" if entry.is_dir() else "file",
                    "size": entry.stat().st_size if entry.is_file() else 0,
                }
            )
        return {"path": str(target), "entries": entries}

    server.register_tool(
        name="read_file",
        description="Read the contents of a file",
        parameters={
            "path": {
                "type": "string",
                "description": "File path relative to workspace",
            },
        },
        handler=read_file,
    )
    server.register_tool(
        name="write_file",
        description="Write content to a file",
        parameters={
            "path": {
                "type": "string",
                "description": "File path relative to workspace",
            },
            "content": {"type": "string", "description": "Content to write"},
        },
        handler=write_file,
    )
    server.register_tool(
        name="list_dir",
        description="List directory contents",
        parameters={
            "path": {
                "type": "string",
                "description": "Directory path relative to workspace",
            },
        },
        handler=list_dir,
    )

    return server


if __name__ == "__main__":
    workspace_dir = os.environ.get("MCP_WORKSPACE", "./workspace")
    srv = create_filesystem_server(workspace_dir)
    srv.run()
