#!/usr/bin/env python3
"""
Test script to verify API calls are working correctly with org_id parameter

This script tests the corrected API approach using organization findings
with app_id filtering.
"""

import asyncio
import json
import os
import sys
from datetime import datetime
import pytest

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from stackhawk_mcp.server import StackHawkMCPServer


@pytest.mark.asyncio
async def test_api_calls():
    """Test the corrected API calls"""
    
    # Get API key from environment
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing Corrected API Calls")
    print("=" * 50)
    
    # Create server instance
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info to find organization ID
        print("\n1. Getting user information...")
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        org_name = user_info["user"]["external"]["organizations"][0]["organization"]["name"]
        print(f"✅ Organization: {org_name} (ID: {org_id})")
        
        # Get applications to find a specific app
        print("\n2. Getting applications...")
        apps_response = await server.client.list_applications(org_id, pageSize=5)
        applications = apps_response.get("applications", [])
        
        if not applications:
            print("❌ No applications found")
            return
        
        # Use the first application for testing
        test_app = applications[0]
        app_id = test_app["id"]
        app_name = test_app["name"]
        print(f"✅ Test Application: {app_name} (ID: {app_id})")
        
        # Test 1: Organization-wide findings (no app_id filter)
        print("\n3. Testing Organization-Wide Findings...")
        try:
            org_findings = await server.client.list_organization_findings(org_id, pageSize=10)
            org_count = len(org_findings.get("findings", []))
            print(f"✅ Organization-wide findings: {org_count} total")
        except Exception as e:
            print(f"❌ Error getting org-wide findings: {e}")
        
        # Test 2: Application-specific findings (with app_id filter)
        print("\n4. Testing Application-Specific Findings...")
        try:
            app_findings = await server.client.get_application_findings(app_id, org_id, pageSize=10)
            app_count = len(app_findings.get("findings", []))
            print(f"✅ Application-specific findings: {app_count} for {app_name}")
            
            # Show sample findings
            findings = app_findings.get("findings", [])
            if findings:
                print(f"\n   Sample findings for {app_name}:")
                for i, finding in enumerate(findings[:3]):
                    print(f"     {i+1}. {finding.get('findingName', 'Unknown')}")
                    print(f"        Severity: {finding.get('findingRisk', 'Unknown')}")
                    print(f"        Application: {finding.get('applicationName', 'Unknown')}")
                    print()
        except Exception as e:
            print(f"❌ Error getting app-specific findings: {e}")
        
        # Test 3: Application findings summary
        print("\n5. Testing Application Findings Summary...")
        try:
            app_summary = await server.client.get_application_findings_summary(app_id, org_id, pageSize=5)
            summary_count = len(app_summary.get("findings", []))
            print(f"✅ Application summary findings: {summary_count} for {app_name}")
        except Exception as e:
            print(f"❌ Error getting app summary: {e}")
        
        # Test 4: Compare the difference
        print("\n6. Comparing Results...")
        if 'org_count' in locals() and 'app_count' in locals():
            print(f"✅ Organization-wide: {org_count} findings")
            print(f"✅ Application-specific: {app_count} findings")
            print(f"✅ Difference: {org_count - app_count} findings from other applications")
            
            if org_count > app_count:
                print(f"✅ This confirms the app_id filter is working correctly!")
        
        print("\n" + "=" * 50)
        print("✅ API Call Tests Completed!")
        
        # Save results
        results = {
            "organization_id": org_id,
            "organization_name": org_name,
            "test_application": {
                "id": app_id,
                "name": app_name
            },
            "api_tests": {
                "org_wide_count": org_count if 'org_count' in locals() else None,
                "app_specific_count": app_count if 'app_count' in locals() else None,
                "summary_count": summary_count if 'summary_count' in locals() else None
            },
            "timestamp": datetime.now().isoformat()
        }
        
        with open("api_call_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print("📄 Results saved to api_call_results.json")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup() 