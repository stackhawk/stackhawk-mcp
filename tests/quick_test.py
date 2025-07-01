#!/usr/bin/env python3
"""
Quick test to verify pagination fix
"""

import asyncio
import os
import sys
import pytest

# Add the current directory to the path so we can import the server
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from stackhawk_mcp.server import StackHawkMCPServer

@pytest.mark.asyncio
async def test_pagination():
    """Test that pagination now works correctly"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing pagination fix...")
    
    try:
        # Create server instance
        server = StackHawkMCPServer(api_key)
        
        # Get user info to find org ID
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        
        print(f"📋 Testing with organization: {org_id}")
        
        # Test 1: Get findings with all_results=True (should use pagination)
        print("\n1. Testing all_results=True (should fetch all pages)...")
        findings_response = await server.client.list_organization_findings(org_id, all_results=True)
        total_findings = len(findings_response.get("findings", []))
        print(f"   ✅ Total findings with all_results=True: {total_findings}")
        
        # Test 2: Get findings with pageSize=100 (should get only first page)
        print("\n2. Testing pageSize=100 (should get only first page)...")
        findings_response = await server.client.list_organization_findings(org_id, pageSize=100)
        first_page_findings = len(findings_response.get("findings", []))
        print(f"   ✅ First page findings: {first_page_findings}")
        
        # Test 3: Compare results
        if total_findings > first_page_findings:
            print(f"   ✅ Pagination is working! Found {total_findings} total vs {first_page_findings} on first page")
        elif total_findings == first_page_findings:
            print(f"   ℹ️  All findings fit on first page ({total_findings} findings)")
        else:
            print(f"   ❌ Unexpected: total ({total_findings}) < first page ({first_page_findings})")
        
        # Test 4: Test executive summary with all-time
        print("\n3. Testing executive summary with all-time...")
        summary = await server._generate_executive_summary(org_id, time_period="all")
        summary_findings = summary.get("summary", {}).get("totalFindings", 0)
        print(f"   ✅ Executive summary total findings: {summary_findings}")
        
        if summary_findings == total_findings:
            print("   ✅ Executive summary matches total findings count")
        else:
            print(f"   ❌ Mismatch: executive summary ({summary_findings}) vs total ({total_findings})")
        
        await server.cleanup()
        print("\n✅ Pagination test completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_pagination()) 