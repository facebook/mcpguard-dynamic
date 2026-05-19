#!/usr/bin/env python3
"""
MCP SQLite Server.

Mimics @modelcontextprotocol/server-sqlite.
Tools: query, insert, list_tables.
Uses sqlite3 module (stdlib) with an in-memory database.
Pre-populates with a `users` table and a `products` table.
"""

import sqlite3
import sys
from pathlib import Path

_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer


def create_sqlite_server() -> MCPServer:
    """Create a SQLite MCP server with an in-memory database."""
    server = MCPServer(name="sqlite_server", version="1.0.0")

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Pre-populate tables
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    cursor.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [
            ("Alice", "alice@example.com"),
            ("Bob", "bob@example.com"),
            ("Charlie", "charlie@example.com"),
        ],
    )
    cursor.execute(
        "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)"
    )
    cursor.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [
            ("Widget", 9.99),
            ("Gadget", 24.95),
            ("Gizmo", 14.50),
        ],
    )
    conn.commit()

    def query(args: dict) -> dict:
        sql = args.get("sql", "")
        if not sql:
            raise ValueError("No SQL query provided")
        cur = conn.execute(sql)
        columns = [desc[0] for desc in cur.description] if cur.description else []
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        return {"columns": columns, "rows": rows, "row_count": len(rows)}

    def insert(args: dict) -> dict:
        table = args.get("table", "")
        data = args.get("data", {})
        if not table:
            raise ValueError("No table name provided")
        if not data:
            raise ValueError("No data provided")
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        conn.execute(sql, list(data.values()))
        conn.commit()
        return {"table": table, "inserted": True, "data": data}

    def list_tables(args: dict) -> dict:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cur.fetchall()]
        return {"tables": tables, "count": len(tables)}

    server.register_tool(
        name="query",
        description="Execute a SQL query and return results",
        parameters={
            "sql": {"type": "string", "description": "SQL query to execute"},
        },
        handler=query,
    )
    server.register_tool(
        name="insert",
        description="Insert a row into a table",
        parameters={
            "table": {"type": "string", "description": "Table name"},
            "data": {
                "type": "object",
                "description": "Key-value pairs for the row to insert",
            },
        },
        handler=insert,
    )
    server.register_tool(
        name="list_tables",
        description="List all tables in the database",
        parameters={},
        handler=list_tables,
    )

    return server


if __name__ == "__main__":
    srv = create_sqlite_server()
    srv.run()
