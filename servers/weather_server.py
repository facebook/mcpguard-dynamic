#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCP Weather Server.

Tools: get_weather, get_forecast.
Returns hardcoded weather data (no real API calls).
"""

import sys
from pathlib import Path

_this_dir = Path(__file__).resolve().parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))

from mcp_protocol import MCPServer

# Hardcoded weather data for reproducibility
_WEATHER_DATA = {
    "new york": {
        "temp_f": 72,
        "condition": "Partly Cloudy",
        "humidity": 55,
        "wind_mph": 8,
    },
    "london": {"temp_f": 59, "condition": "Overcast", "humidity": 78, "wind_mph": 12},
    "tokyo": {"temp_f": 81, "condition": "Sunny", "humidity": 62, "wind_mph": 5},
    "paris": {"temp_f": 64, "condition": "Light Rain", "humidity": 82, "wind_mph": 10},
    "sydney": {"temp_f": 68, "condition": "Clear", "humidity": 45, "wind_mph": 15},
    "berlin": {"temp_f": 57, "condition": "Cloudy", "humidity": 70, "wind_mph": 9},
    "mumbai": {"temp_f": 90, "condition": "Humid", "humidity": 88, "wind_mph": 4},
    "san francisco": {
        "temp_f": 62,
        "condition": "Foggy",
        "humidity": 80,
        "wind_mph": 14,
    },
}

_DEFAULT_WEATHER = {"temp_f": 70, "condition": "Clear", "humidity": 50, "wind_mph": 7}

_CONDITIONS_CYCLE = ["Sunny", "Partly Cloudy", "Cloudy", "Light Rain", "Clear"]


def create_weather_server() -> MCPServer:
    """Create a weather MCP server with hardcoded data."""
    server = MCPServer(name="weather_server", version="1.0.0")

    def get_weather(args: dict) -> dict:
        city = args.get("city", "").lower().strip()
        data = _WEATHER_DATA.get(city, _DEFAULT_WEATHER).copy()
        data["city"] = args.get("city", "Unknown")
        return data

    def get_forecast(args: dict) -> dict:
        city = args.get("city", "").lower().strip()
        days = min(int(args.get("days", 3)), 7)
        base = _WEATHER_DATA.get(city, _DEFAULT_WEATHER)
        forecast = []
        for day in range(days):
            forecast.append(
                {
                    "day": day + 1,
                    "temp_f": base["temp_f"] + (day * 2 - days),
                    "condition": _CONDITIONS_CYCLE[day % len(_CONDITIONS_CYCLE)],
                    "humidity": base["humidity"] + (day - days // 2) * 3,
                }
            )
        return {
            "city": args.get("city", "Unknown"),
            "days": days,
            "forecast": forecast,
        }

    server.register_tool(
        name="get_weather",
        description="Get current weather for a city",
        parameters={
            "city": {"type": "string", "description": "City name"},
        },
        handler=get_weather,
    )
    server.register_tool(
        name="get_forecast",
        description="Get weather forecast for a city",
        parameters={
            "city": {"type": "string", "description": "City name"},
            "days": {"type": "integer", "description": "Number of forecast days (1-7)"},
        },
        handler=get_forecast,
    )

    return server


if __name__ == "__main__":
    srv = create_weather_server()
    srv.run()
