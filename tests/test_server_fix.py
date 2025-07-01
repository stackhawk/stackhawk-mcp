#!/usr/bin/env python3
"""
Test script to verify the server fixes work correctly.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def test_server_import():
    """Test that the server can be imported without errors"""
    try:
        import stackhawk_mcp.server
        assert stackhawk_mcp.server is not None
    except Exception as e:
        assert False, f"Failed to import server module: {e}"

def test_server_class():
    """Test that the server class can be instantiated"""
    try:
        from stackhawk_mcp.server import StackHawkMCPServer
        server = StackHawkMCPServer("dummy_key")
        assert server is not None
        # Test that the _detect_project_language_and_frameworks method exists
        assert hasattr(server, '_detect_project_language_and_frameworks')
        result = server._detect_project_language_and_frameworks()
        assert isinstance(result, dict)
        # Test that the _get_stackhawk_scan_instructions method exists
        assert hasattr(server, '_get_stackhawk_scan_instructions')
        result = server._get_stackhawk_scan_instructions()
        assert isinstance(result, str)
    except Exception as e:
        assert False, f"Failed to instantiate server class: {e}"

# Optional: allow manual run for quick feedback
if __name__ == "__main__":
    test_server_import()
    test_server_class()
    print("Manual tests passed.") 