#!/usr/bin/env python3
"""
Parley-MCP Server Entry Point

Copyright (C) 2025 Garland Glessner (gglessner@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

Run this script to start the MCP server:
    python run_server.py

Or configure in .cursor/mcp.json:
    {
        "mcpServers": {
            "parley-mcp": {
                "command": "python",
                "args": ["run_server.py"],
                "cwd": "${workspaceFolder}"
            }
        }
    }
"""

import sys
import os

# Ensure the package is importable regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parley_mcp.server import main

if __name__ == "__main__":
    main()
