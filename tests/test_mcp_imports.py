#!/usr/bin/env python3
"""
Test script to verify MCP imports and basic functionality
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def test_imports():
    """Test all required imports"""
    import httpx
    import yaml
    from jsonschema import validate
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    from stackhawk_mcp.server import StackHawkMCPServer
