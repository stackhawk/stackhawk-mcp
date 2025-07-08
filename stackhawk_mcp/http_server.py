import os
import json
import uuid
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio
from stackhawk_mcp.server import StackHawkMCPServer
from stackhawk_mcp import __version__

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get API key from environment
API_KEY = os.environ.get("STACKHAWK_API_KEY", "changeme")
BASE_URL = os.environ.get("STACKHAWK_BASE_URL", "https://api.stackhawk.com")

# Create the MCP server instance
mcp_server = StackHawkMCPServer(api_key=API_KEY, base_url=BASE_URL)

# Store active SSE connections
active_connections = {}

def create_jsonrpc_response(id_value, result=None, error=None):
    """Create a proper JSON-RPC 2.0 response"""
    response = {
        "jsonrpc": "2.0",
        "id": id_value
    }
    if error:
        response["error"] = error
    else:
        response["result"] = result
    return response

def fix_tool_schema(tool):
    """Fix tool schema to ensure outputSchema and annotations are objects"""
    if isinstance(tool, dict):
        # Ensure outputSchema is an object with proper type
        if tool.get("outputSchema") is None:
            tool["outputSchema"] = {"type": "object"}
        elif isinstance(tool["outputSchema"], dict) and tool["outputSchema"].get("type") is None:
            tool["outputSchema"]["type"] = "object"
        
        # Ensure annotations is an object
        if tool.get("annotations") is None:
            tool["annotations"] = {}
        
        # Ensure meta is an object
        if tool.get("meta") is None:
            tool["meta"] = {}
    
    return tool

async def handle_initialize_request(request_data):
    """Handle MCP initialize request"""
    return create_jsonrpc_response(
        request_data.get("id"),
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "StackHawk MCP",
                "version": __version__
            }
        }
    )

async def handle_list_tools_request(request_data):
    """Handle MCP list tools request"""
    try:
        tools = await mcp_server.list_tools()
        # Fix the tool schemas to ensure proper objects
        fixed_tools = [fix_tool_schema(t.dict() if hasattr(t, 'dict') else t) for t in tools]
        return create_jsonrpc_response(
            request_data.get("id"),
            {
                "tools": fixed_tools
            }
        )
    except Exception as e:
        return create_jsonrpc_response(
            request_data.get("id"),
            error={
                "code": -1,
                "message": str(e)
            }
        )

async def handle_call_tool_request(request_data):
    """Handle MCP call tool request"""
    try:
        params = request_data.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {})
        
        result = await mcp_server.call_tool(name, arguments)
        return create_jsonrpc_response(
            request_data.get("id"),
            {
                "content": [r.dict() if hasattr(r, 'dict') else r for r in result]
            }
        )
    except Exception as e:
        return create_jsonrpc_response(
            request_data.get("id"),
            error={
                "code": -1,
                "message": str(e)
            }
        )

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """Main MCP endpoint that handles all JSON-RPC messages"""
    
    # Check Accept header
    accept_header = request.headers.get("accept", "")
    if "application/json" not in accept_header and "text/event-stream" not in accept_header:
        return JSONResponse(
            content={"error": "Accept header must include application/json or text/event-stream"},
            status_code=400
        )
    
    try:
        # Parse request body
        body = await request.body()
        if not body:
            return JSONResponse(content={"error": "Empty request body"}, status_code=400)
        
        data = json.loads(body)
        
        # Handle batched requests
        if isinstance(data, list):
            responses = []
            for item in data:
                response = await handle_jsonrpc_message(item)
                if response:
                    responses.append(response)
            
            if len(responses) == 1:
                return JSONResponse(content=responses[0])
            else:
                return JSONResponse(content=responses)
        else:
            # Single request
            response = await handle_jsonrpc_message(data)
            if response:
                return JSONResponse(content=response)
            else:
                return Response(status_code=202)  # Accepted with no body
                
    except json.JSONDecodeError:
        return JSONResponse(content={"error": "Invalid JSON"}, status_code=400)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

async def handle_jsonrpc_message(message):
    """Handle individual JSON-RPC message"""
    if not isinstance(message, dict):
        return None
    
    method = message.get("method")
    message_id = message.get("id")
    
    if method == "initialize":
        return await handle_initialize_request(message)
    elif method == "tools/list":
        return await handle_list_tools_request(message)
    elif method == "tools/call":
        return await handle_call_tool_request(message)
    elif method == "notifications/cancelled":
        # Handle cancellation
        return None
    else:
        return create_jsonrpc_response(
            message_id,
            error={
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        )

@app.get("/mcp")
async def mcp_sse_endpoint(request: Request):
    """SSE endpoint for streaming responses"""
    
    # Check Accept header
    accept_header = request.headers.get("accept", "")
    if "text/event-stream" not in accept_header:
        return JSONResponse(
            content={"error": "Accept header must include text/event-stream"},
            status_code=405
        )
    
    # Generate connection ID
    connection_id = str(uuid.uuid4())
    active_connections[connection_id] = True
    
    async def event_stream():
        try:
            while active_connections.get(connection_id, False):
                # For now, just keep the connection alive
                # In a real implementation, you'd send actual events here
                await asyncio.sleep(1)
        except Exception:
            pass
        finally:
            if connection_id in active_connections:
                del active_connections[connection_id]
    
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream",
        }
    )

# Legacy endpoints for manual testing (keep these for now)
@app.get("/")
async def root():
    return JSONResponse(content={
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "serverName": "StackHawk MCP",
            "serverVersion": __version__,
            "protocolVersion": "v1"
        }
    })

@app.post("/")
async def root_post():
    return JSONResponse(content={
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "serverName": "StackHawk MCP",
            "serverVersion": __version__,
            "protocolVersion": "v1"
        }
    })

if __name__ == "__main__":
    uvicorn.run("stackhawk_mcp.http_server:app", host="0.0.0.0", port=8080, reload=True) 