#!/usr/bin/env python3
"""
Example: Using StackHawk MCP with Published Schema

This example demonstrates how the StackHawk MCP server uses the official
published schema from StackHawk's API instead of hardcoded schemas.
"""

import asyncio
import json
from stackhawk_mcp.server import StackHawkMCPServer

async def demonstrate_schema_usage():
    """Demonstrate the schema-based approach"""
    
    print("=== StackHawk MCP Schema-Based Approach ===\n")
    
    # Create server instance
    server = StackHawkMCPServer("mock-api-key")
    
    print("1. Fetching schema from StackHawk API...")
    try:
        schema_info = await server._get_stackhawk_schema()
        print("✅ Schema fetched successfully!")
        print(f"   Source: {schema_info['source']}")
        print(f"   Cached: {schema_info['cached']}")
        print(f"   Cache age: {schema_info['cache_age']}")
        
        # Show schema structure
        schema = schema_info['schema']
        print(f"\n   Schema structure:")
        print(f"   - Type: {schema.get('type', 'unknown')}")
        print(f"   - Required fields: {schema.get('required', [])}")
        print(f"   - Properties: {list(schema.get('properties', {}).keys())}")
        
    except Exception as e:
        print(f"❌ Failed to fetch schema: {e}")
        print("   Using fallback schema...")
    
    print("\n2. Benefits of using published schema:")
    print("   ✅ Always up-to-date with StackHawk's latest configuration options")
    print("   ✅ Automatic validation against current schema")
    print("   ✅ No need to maintain hardcoded schemas")
    print("   ✅ Cached for performance (24-hour TTL)")
    print("   ✅ Fallback schema for offline usage")
    
    print("\n3. Schema caching behavior:")
    print("   - First request: Fetches from API")
    print("   - Subsequent requests: Uses cached version")
    print("   - After 24 hours: Automatically refreshes")
    print("   - Manual refresh: Use refresh_schema_cache tool")
    
    print("\n=== Example Complete ===")

if __name__ == "__main__":
    asyncio.run(demonstrate_schema_usage()) 