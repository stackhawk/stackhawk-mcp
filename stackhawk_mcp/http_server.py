import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import asyncio
from stackhawk_mcp.server import StackHawkMCPServer

app = FastAPI()

# Get API key from environment
API_KEY = os.environ.get("STACKHAWK_API_KEY", "changeme")

# Create the MCP server instance
mcp_server = StackHawkMCPServer(api_key=API_KEY)

@app.post("/call_tool")
async def call_tool(request: Request):
    data = await request.json()
    name = data["name"]
    arguments = data.get("arguments", {})
    # Call the tool handler
    try:
        # handle_call_tool returns a list of TextContent, convert to dicts
        result = await mcp_server.server._call_tool(name, arguments)
        # Convert TextContent objects to dicts if needed
        return JSONResponse(content={"result": [r.dict() if hasattr(r, 'dict') else r for r in result]})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/list_tools")
async def list_tools():
    try:
        # handle_list_tools returns a list of Tool objects
        result = await mcp_server.server._list_tools()
        return JSONResponse(content={"tools": [t.dict() if hasattr(t, 'dict') else t for t in result]})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

if __name__ == "__main__":
    uvicorn.run("stackhawk_mcp.http_server:app", host="0.0.0.0", port=8080, reload=True) 