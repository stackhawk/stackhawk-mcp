import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest

from stackhawk_mcp.server import StackHawkMCPServer

def fix_tool_schema(tool):
    if isinstance(tool, dict):
        tool["outputSchema"] = {"type": "object"}
        if tool.get("annotations") is None:
            tool["annotations"] = {}
        if tool.get("meta") is None:
            tool["meta"] = {}
    return tool

@pytest.mark.asyncio
async def test_tool_schema_output_schema_and_annotations():
    server = StackHawkMCPServer(api_key="dummy")
    tools = await server.list_tools()
    for tool in tools:
        # Use model_dump for Pydantic v2+, fallback to dict()
        if hasattr(tool, "model_dump"):
            tool_dict = tool.model_dump()
        elif hasattr(tool, "dict"):
            tool_dict = tool.dict()
        else:
            tool_dict = tool
        tool_dict = fix_tool_schema(tool_dict)
        assert isinstance(tool_dict.get("outputSchema"), dict), f"outputSchema is not a dict: {tool_dict}"
        assert tool_dict["outputSchema"].get("type") == "object", f"outputSchema.type is not 'object': {tool_dict}"
        assert isinstance(tool_dict.get("annotations"), dict), f"annotations is not a dict: {tool_dict}"
        assert isinstance(tool_dict.get("meta"), dict), f"meta is not a dict: {tool_dict}" 