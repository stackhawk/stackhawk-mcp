#!/usr/bin/env python3
"""
Test script for StackHawk YAML configuration tools

This script tests the YAML configuration tools that use the official StackHawk schema
fetched from the API rather than hardcoded schemas. The schema is automatically cached
for 24 hours to improve performance.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import json
import yaml
from stackhawk_mcp.server import StackHawkMCPServer
import pytest

@pytest.mark.asyncio
async def test_yaml_tools():
    """Test the YAML configuration tools"""
    
    # Create a mock server instance (without API key for testing)
    server = StackHawkMCPServer("mock-api-key")
    
    print("=== Testing StackHawk YAML Configuration Tools ===\n")
    
    # Test 1: Create a basic configuration
    print("1. Creating basic StackHawk configuration...")
    result = await server._create_stackhawk_config(
        application_id="12345678-1234-1234-1234-123456789012",
        app_name="Test Application",
        host="localhost",
        port=3000,
        environment="dev",
        protocol="http"
    )
    
    if result["success"]:
        print("✅ Configuration created successfully!")
        print("YAML Output:")
        print(result["yaml"])
        print(f"Config path: {result['config_path']}")
    else:
        print(f"❌ Failed to create configuration: {result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 2: Create configuration with authentication
    print("2. Creating configuration with authentication...")
    result = await server._create_stackhawk_config(
        application_id="87654321-4321-4321-4321-210987654321",
        app_name="Secure App",
        host="myapp.com",
        port=443,
        environment="prod",
        protocol="https",
        include_auth=True,
        auth_type="form"
    )
    
    if result["success"]:
        print("✅ Configuration with auth created successfully!")
        print("YAML Output:")
        print(result["yaml"])
    else:
        print(f"❌ Failed to create configuration: {result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 3: Validate a good configuration
    print("3. Validating a good configuration...")
    good_config = """
app:
  applicationId: "test-app-id"
  env: "dev"
  host: "http://localhost:3000"
  name: "Test App"
  description: "A test application"
hawk:
  spider:
    base: true
    ajax: false
    maxDurationMinutes: 30
  scan:
    maxDurationMinutes: 60
    threads: 10
  startupTimeoutMinutes: 5
  failureThreshold: "high"
"""
    
    validation_result = await server._validate_stackhawk_config(good_config)
    if validation_result["valid"]:
        print("✅ Configuration is valid!")
        print(f"Summary: {validation_result['config_summary']}")
    else:
        print(f"❌ Configuration is invalid: {validation_result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 4: Validate a bad configuration
    print("4. Validating a bad configuration...")
    bad_config = """
app:
  # Missing required fields
  name: "Bad App"
hawk:
  spider:
    base: "invalid_value"  # Should be boolean
"""
    
    validation_result = await server._validate_stackhawk_config(bad_config)
    if not validation_result["valid"]:
        print("✅ Correctly identified invalid configuration!")
        print(f"Error: {validation_result['error']}")
        print(f"Message: {validation_result['message']}")
    else:
        print("❌ Should have detected invalid configuration")
    
    print("\n" + "="*50 + "\n")
    
    # Test 5: Get schema
    print("5. Getting StackHawk schema...")
    schema_result = await server._get_stackhawk_schema()
    if "schema" in schema_result:
        print("✅ Schema retrieved successfully!")
        print(f"Schema version: {schema_result['version']}")
        print(f"Description: {schema_result['description']}")
        print(f"Source: {schema_result['source']}")
        print(f"Cached: {schema_result['cached']}")
        if schema_result['cache_age']:
            print(f"Cache age: {schema_result['cache_age']}")
    else:
        print(f"❌ Failed to get schema: {schema_result['error']}")
    
    print("\n=== Testing Complete ===") 