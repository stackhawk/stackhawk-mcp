#!/usr/bin/env python3
"""
Test script for StackHawk MCP Anti-Hallucination Features

This script demonstrates how the MCP server prevents LLMs from suggesting
invalid fields that don't exist in the actual StackHawk schema.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import json
from stackhawk_mcp.server import StackHawkMCPServer
import pytest

@pytest.mark.asyncio
async def test_anti_hallucination():
    """Test the anti-hallucination features"""
    
    # Create a mock server instance
    server = StackHawkMCPServer("mock-api-key")
    
    print("=== Testing StackHawk MCP Anti-Hallucination Features ===\n")
    
    # Test 1: Validate existing fields
    print("1. Validating existing fields...")
    valid_fields = [
        "app.applicationId",
        "app.env", 
        "app.host",
        "hawk.spider.base",
        "hawk.scan.maxDurationMinutes",
        "tags[].name"
    ]
    
    for field in valid_fields:
        result = await server._validate_field_exists(field)
        if result["success"]:
            print(f"✅ {field}: {result['type']} - {result['description']}")
        else:
            print(f"❌ {field}: {result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 2: Validate non-existent fields (hallucinated)
    print("2. Validating non-existent (hallucinated) fields...")
    invalid_fields = [
        "app.port",  # Doesn't exist in schema
        "app.protocol",  # Doesn't exist in schema
        "hawkScan.scannerMode",  # Wrong section name
        "hawk.invalidField",  # Non-existent field
        "app.authentication.invalidType",  # Non-existent nested field
        "hawk.spider.maxDepth",  # Doesn't exist in spider config
        "hawk.scan.scanTimeout"  # Wrong field name
    ]
    
    for field in invalid_fields:
        result = await server._validate_field_exists(field)
        if not result["success"]:
            print(f"✅ Correctly rejected: {field}")
            print(f"   Error: {result['error']}")
            print(f"   Suggestion: {result['suggestion']}")
        else:
            print(f"❌ Should have rejected: {field}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 3: Get schema fields for specific sections
    print("3. Getting schema fields for specific sections...")
    sections = ["app", "hawk", "hawkAddOn", "tags"]
    
    for section in sections:
        result = await server._get_schema_fields(section=section)
        if "fields" in result:
            print(f"✅ {section} section: {result['total_fields']} fields")
            # Show first few fields
            field_names = list(result["fields"].keys())[:3]
            print(f"   Sample fields: {', '.join(field_names)}")
        else:
            print(f"❌ Failed to get {section} fields: {result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 4: Get all available fields
    print("4. Getting all available fields...")
    result = await server._get_schema_fields()
    if "all_fields" in result:
        print(f"✅ Total fields available: {result['total_fields']}")
        print(f"   Available sections: {', '.join(result['available_sections'])}")
        print(f"   Schema URL: {result['schema_url']}")
    else:
        print(f"❌ Failed to get all fields: {result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 5: Configuration suggestions
    print("5. Testing configuration suggestions...")
    use_cases = [
        "web application",
        "REST API testing", 
        "authentication required",
        "production deployment"
    ]
    
    for use_case in use_cases:
        result = await server._suggest_configuration(use_case, environment="dev")
        if "recommendations" in result:
            print(f"✅ {use_case}: {len(result['recommendations'])} recommendations")
            for rec in result["recommendations"][:2]:  # Show first 2
                print(f"   - {rec['recommendation']}")
        else:
            print(f"❌ Failed to get suggestions for {use_case}: {result['error']}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 6: Demonstrate how to prevent hallucination
    print("6. Anti-Hallucination Workflow Example:")
    print("   Step 1: Always validate fields before suggesting them")
    print("   Step 2: Use get_schema_fields to see what's actually available")
    print("   Step 3: Use suggest_configuration for AI-powered recommendations")
    print("   Step 4: Validate final configuration before deployment")
    
    print("\n=== Anti-Hallucination Testing Complete ===") 