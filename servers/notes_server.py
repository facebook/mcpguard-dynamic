#!/usr/bin/env python3
"""
MCP Notes Server.

Tools: create_note, search_notes, read_note.
Stores notes as JSON files in a data directory.
"""

import json
import os
import sys
import time
import uuid
from pathlib import Path

_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer


def create_notes_server(data_dir: str = "./notes_data") -> MCPServer:
    """Create a notes MCP server storing data in the given directory."""
    server = MCPServer(name="notes_server", version="1.0.0")
    data_path = Path(data_dir).resolve()
    data_path.mkdir(parents=True, exist_ok=True)

    def create_note(args: dict) -> dict:
        title = args.get("title", "Untitled")
        content = args.get("content", "")
        note_id = str(uuid.uuid4())[:8]
        note = {
            "id": note_id,
            "title": title,
            "content": content,
            "created_at": time.time(),
        }
        note_file = data_path / f"{note_id}.json"
        note_file.write_text(json.dumps(note, indent=2), encoding="utf-8")
        return {"id": note_id, "title": title, "created": True}

    def search_notes(args: dict) -> dict:
        query = args.get("query", "").lower()
        results = []
        for note_file in data_path.glob("*.json"):
            try:
                note = json.loads(note_file.read_text(encoding="utf-8"))
                if (
                    query in note.get("title", "").lower()
                    or query in note.get("content", "").lower()
                ):
                    results.append(
                        {
                            "id": note["id"],
                            "title": note["title"],
                            "snippet": note["content"][:100],
                        }
                    )
            except (json.JSONDecodeError, KeyError):
                continue
        return {"query": query, "results": results, "count": len(results)}

    def read_note(args: dict) -> dict:
        note_id = args.get("id", "")
        note_file = data_path / f"{note_id}.json"
        if not note_file.exists():
            raise FileNotFoundError(f"Note not found: {note_id}")
        note = json.loads(note_file.read_text(encoding="utf-8"))
        return note

    server.register_tool(
        name="create_note",
        description="Create a new note with title and content",
        parameters={
            "title": {"type": "string", "description": "Note title"},
            "content": {"type": "string", "description": "Note content"},
        },
        handler=create_note,
    )
    server.register_tool(
        name="search_notes",
        description="Search notes by query string",
        parameters={
            "query": {"type": "string", "description": "Search query"},
        },
        handler=search_notes,
    )
    server.register_tool(
        name="read_note",
        description="Read a note by its ID",
        parameters={
            "id": {"type": "string", "description": "Note ID"},
        },
        handler=read_note,
    )

    return server


if __name__ == "__main__":
    data = os.environ.get("MCP_NOTES_DIR", "./notes_data")
    srv = create_notes_server(data)
    srv.run()
