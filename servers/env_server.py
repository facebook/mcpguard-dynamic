#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCP Environment/Config Management Server.

Mimics environment and configuration management tools.
Tools: get_config, set_config, list_configs.
Stores config in a JSON file.

Dangerous: get_config with a path-traversal key could read arbitrary files.
"""

import json
import os
import sys
from pathlib import Path

_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer

_DEFAULT_CONFIG_FILE = "/tmp/mcpguard_env_config.json"


def create_env_server(config_file: str = _DEFAULT_CONFIG_FILE) -> MCPServer:
    """Create an environment config MCP server."""
    server = MCPServer(name="env_server", version="1.0.0")
    config_path = Path(config_file)

    # Initialize config file with defaults if it does not exist
    if not config_path.exists():
        defaults = {
            "app.name": "MyApp",
            "app.version": "2.1.0",
            "db.host": "localhost",
            "db.port": "5432",
            "log.level": "INFO",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(defaults, indent=2), encoding="utf-8")

    def _load_config() -> dict:
        if config_path.exists():
            return json.loads(config_path.read_text(encoding="utf-8"))
        return {}

    def _save_config(data: dict) -> None:
        config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_config(args: dict) -> dict:
        key = args.get("key", "")
        if not key:
            raise ValueError("No config key provided")
        cfg = _load_config()
        value = cfg.get(key)
        if value is None:
            return {"key": key, "found": False, "value": None}
        return {"key": key, "found": True, "value": value}

    def set_config(args: dict) -> dict:
        key = args.get("key", "")
        value = args.get("value", "")
        if not key:
            raise ValueError("No config key provided")
        cfg = _load_config()
        cfg[key] = value
        _save_config(cfg)
        return {"key": key, "value": value, "updated": True}

    def list_configs(args: dict) -> dict:
        cfg = _load_config()
        return {"configs": cfg, "count": len(cfg)}

    server.register_tool(
        name="get_config",
        description="Get a configuration value by key",
        parameters={
            "key": {"type": "string", "description": "Configuration key"},
        },
        handler=get_config,
    )
    server.register_tool(
        name="set_config",
        description="Set a configuration value",
        parameters={
            "key": {"type": "string", "description": "Configuration key"},
            "value": {"type": "string", "description": "Configuration value"},
        },
        handler=set_config,
    )
    server.register_tool(
        name="list_configs",
        description="List all configuration key-value pairs",
        parameters={},
        handler=list_configs,
    )

    return server


if __name__ == "__main__":
    config = os.environ.get("MCP_CONFIG_FILE", _DEFAULT_CONFIG_FILE)
    srv = create_env_server(config)
    srv.run()
