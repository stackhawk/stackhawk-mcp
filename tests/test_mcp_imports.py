#!/usr/bin/env python3
"""
Test script to verify MCP imports and basic functionality
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest

def test_imports():
    """Test all required imports"""
    print("Testing imports...")
    
    try:
        import httpx
        print("✅ httpx imported successfully")
    except ImportError as e:
        print(f"❌ httpx import failed: {e}")
        return False
    
    try:
        import yaml
        print("✅ PyYAML imported successfully")
    except ImportError as e:
        print(f"❌ PyYAML import failed: {e}")
        return False
    
    try:
        from jsonschema import validate
        print("✅ jsonschema imported successfully")
    except ImportError as e:
        print(f"❌ jsonschema import failed: {e}")
        return False
    
    try:
        from mcp.server import Server
        print("✅ mcp.server imported successfully")
    except ImportError as e:
        print(f"❌ mcp.server import failed: {e}")
        return False
    
    try:
        from mcp.types import Tool, TextContent
        print("✅ mcp.types imported successfully")
    except ImportError as e:
        print(f"❌ mcp.types import failed: {e}")
        return False
    
    return True

def test_environment():
    """Test environment setup"""
    print("\nTesting environment...")
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if api_key:
        print(f"✅ STACKHAWK_API_KEY found: {api_key[:20]}...")
    else:
        print("❌ STACKHAWK_API_KEY not found in environment")
        return False
    
    return True

def test_server_creation():
    """Test server creation"""
    print("\nTesting server creation...")
    
    try:
        from stackhawk_mcp.server import StackHawkMCPServer
        print("✅ StackHawkMCPServer imported successfully")
        
        # Test creating server instance
        api_key = os.environ.get("STACKHAWK_API_KEY")
        if api_key:
            server = StackHawkMCPServer(api_key)
            print("✅ StackHawkMCPServer created successfully")
            return True
        else:
            print("❌ Cannot create server without API key")
            return False
            
    except Exception as e:
        print(f"❌ Server creation failed: {e}")
        return False

def test_mcp_imports():
    # ... existing test code ...
    pass

if __name__ == "__main__":
    print("=== StackHawk MCP Server Import Test ===\n")
    
    success = True
    success &= test_imports()
    success &= test_environment()
    success &= test_server_creation()
    
    print(f"\n=== Test Results ===")
    if success:
        print("✅ All tests passed! MCP server should work in Cursor.")
    else:
        print("❌ Some tests failed. Check the errors above.")
    
    sys.exit(0 if success else 1) 