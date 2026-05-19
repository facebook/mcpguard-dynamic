# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCP JSON-RPC 2.0 protocol over stdio.

Provides MCPServer base class that handles initialize, tools/list, tools/call.
Subclasses register tools via the @tool decorator or by populating _tools dict.
"""

import json
import sys
import traceback
from typing import Any, Callable, Dict, Optional


class MCPTool:
    """Descriptor for a registered MCP tool."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

    def to_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.parameters,
            },
        }


class MCPServer:
    """
    Base MCP server that communicates via JSON-RPC 2.0 over stdin/stdout.

    Subclasses register tools by calling self.register_tool() in __init__
    or by using the @tool decorator pattern.
    """

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._tools: Dict[str, MCPTool] = {}

    def register_tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> None:
        self._tools[name] = MCPTool(
            name=name,
            description=description,
            parameters=parameters,
            handler=handler,
        )

    def tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
    ) -> Callable:
        """Decorator to register a tool handler."""

        def decorator(func: Callable) -> Callable:
            self.register_tool(
                name=name,
                description=description,
                parameters=parameters,
                handler=func,
            )
            return func

        return decorator

    def _handle_initialize(self, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version,
            },
        }

    def _handle_tools_list(self, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "tools": [t.to_schema() for t in self._tools.values()],
        }

    def _handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name not in self._tools:
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": f"Unknown tool: {tool_name}",
                    }
                ],
            }

        try:
            result = self._tools[tool_name].handler(arguments)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result),
                    }
                ],
            }
        except Exception as exc:
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": f"Tool error: {exc}",
                    }
                ],
            }

    def _dispatch(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatch a JSON-RPC request and return a response (or None for notifications)."""
        method = request.get("method", "")
        params = request.get("params")
        req_id = request.get("id")

        handlers = {
            "initialize": self._handle_initialize,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
        }

        # Notifications (no id) that we silently accept
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None

        if method not in handlers:
            error_resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }
            return error_resp

        try:
            result = handlers[method](params)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": str(exc),
                    "data": traceback.format_exc(),
                },
            }

    def _write_response(self, response: Dict[str, Any]) -> None:
        """Write a JSON-RPC response to stdout."""
        data = json.dumps(response)
        sys.stdout.write(data + "\n")
        sys.stdout.flush()

    def _read_request(self) -> Optional[Dict[str, Any]]:
        """Read a JSON-RPC request from stdin. Returns None on EOF."""
        line = sys.stdin.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            return None
        return json.loads(line)

    def run(self) -> None:
        """Main event loop: read requests from stdin, dispatch, write responses."""
        while True:
            try:
                request = self._read_request()
                if request is None:
                    break

                response = self._dispatch(request)
                if response is not None:
                    self._write_response(response)

            except json.JSONDecodeError as exc:
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {exc}",
                    },
                }
                self._write_response(error_resp)
            except Exception:
                # Unexpected error; log to stderr and continue
                traceback.print_exc(file=sys.stderr)


def create_jsonrpc_request(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    req_id: int = 1,
) -> Dict[str, Any]:
    """Helper to create a JSON-RPC 2.0 request dict."""
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "id": req_id,
    }
    if params is not None:
        request["params"] = params
    return request


def create_tools_call_request(
    tool_name: str,
    arguments: Dict[str, Any],
    req_id: int = 1,
) -> Dict[str, Any]:
    """Helper to create a tools/call JSON-RPC request."""
    return create_jsonrpc_request(
        method="tools/call",
        params={"name": tool_name, "arguments": arguments},
        req_id=req_id,
    )
