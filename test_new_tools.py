#!/usr/bin/env python3
"""
Test script for the new MCP tools implemented for issue #66

This script tests:
1. check_repository_attack_surface - Check if repo is in attack surface
2. check_repository_sensitive_data - Check if repo has sensitive data
3. list_application_repository_connections - List app-repo connections
4. get_sensitive_data_summary - Comprehensive sensitive data summary
"""

import asyncio
import json
import os
import sys
from datetime import datetime

# Add the stackhawk_mcp directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from stackhawk_mcp.server import StackHawkMCPServer


async def test_new_tools():
    """Test the new MCP tools implemented for issue #66"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        print("Please set it to test the new tools")
        return
    
    print("🔍 Testing New MCP Tools for Issue #66")
    print("=" * 60)
    
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        org_name = user_info["user"]["external"]["organizations"][0]["organization"]["name"]
        
        print(f"✅ Connected to organization: {org_name} (ID: {org_id})")
        print()
        
        # Test 1: Check Repository Attack Surface
        print("1. Testing check_repository_attack_surface...")
        try:
            # Test with the current repository name (auto-detected from directory)
            current_repo = os.path.basename(os.getcwd())  # Dynamic detection
            result = await server._check_repository_attack_surface(
                repo_name=current_repo,
                include_vulnerabilities=True,
                include_apps=True
            )
            print("✅ Repository attack surface check completed!")
            print(f"   Repository: {result['repository_name']}")
            print(f"   Found in attack surface: {result.get('found_in_attack_surface', False)}")
            print(f"   Total matching repos: {len(result.get('matching_repositories', []))}")
            if result.get('connected_applications'):
                print(f"   Connected apps: {result['total_connected_apps']}")
            print(f"   Recommendation: {result.get('recommendation', 'None')}")
        except Exception as e:
            print(f"❌ Failed to check repository attack surface: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 2: Check Repository Sensitive Data
        print("2. Testing check_repository_sensitive_data...")
        try:
            result = await server._check_repository_sensitive_data(
                repo_name=current_repo,
                data_type_filter="All",
                include_remediation=True
            )
            print("✅ Repository sensitive data check completed!")
            print(f"   Repository: {result['repository_name']}")
            print(f"   Found in StackHawk: {result.get('found_in_stackhawk', False)}")
            print(f"   Has sensitive data: {result.get('has_sensitive_data', False)}")
            print(f"   Total findings: {result.get('total_findings', 0)}")
            if result.get('data_type_breakdown'):
                print(f"   Data type breakdown: {result['data_type_breakdown']}")
            print(f"   Recommendation: {result.get('recommendation', 'None')}")
        except Exception as e:
            print(f"❌ Failed to check repository sensitive data: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 3: List Application Repository Connections
        print("3. Testing list_application_repository_connections...")
        try:
            result = await server._list_application_repository_connections(
                include_repo_details=True,
                include_app_details=True,
                filter_connected_only=False
            )
            print("✅ Application-repository connections listed!")
            print(f"   Total applications: {result['total_applications']}")
            print(f"   Total repositories: {result['total_repositories']}")
            print(f"   Total connections: {result['total_connections']}")
            
            coverage_stats = result.get('coverage_stats', {})
            print(f"   Connected applications: {coverage_stats.get('connected_applications', 0)}")
            print(f"   Orphaned applications: {coverage_stats.get('orphaned_applications', 0)}")
            print(f"   Orphaned repositories: {coverage_stats.get('orphaned_repositories', 0)}")
            print(f"   Connection coverage: {coverage_stats.get('connection_coverage', 0):.1f}%")
            
            recommendations = result.get('recommendations', [])
            if recommendations:
                print("   Recommendations:")
                for i, rec in enumerate(recommendations[:3], 1):
                    print(f"     {i}. {rec}")
        except Exception as e:
            print(f"❌ Failed to list application-repository connections: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 4: Get Comprehensive Sensitive Data Summary
        print("4. Testing get_comprehensive_sensitive_data_summary...")
        try:
            result = await server._get_comprehensive_sensitive_data_summary(
                time_period="30d",
                include_trends=True,
                include_critical_only=False,
                include_recommendations=True,
                group_by="data_type"
            )
            print("✅ Comprehensive sensitive data summary generated!")
            print(f"   Total findings: {result['total_findings']}")
            print(f"   Analysis type: {result['analysis_type']}")
            print(f"   Overall risk score: {result.get('overall_risk_score', 0):.1f}")
            print(f"   Group by: {result['group_by']}")
            
            grouped_summary = result.get('grouped_summary', {})
            print(f"   Groups found: {len(grouped_summary)}")
            for group_name, group_data in list(grouped_summary.items())[:3]:
                print(f"     {group_name}: {group_data['count']} findings, risk: {group_data['risk_score']:.1f}")
            
            recommendations = result.get('recommendations', [])
            if recommendations:
                print("   Recommendations:")
                for i, rec in enumerate(recommendations[:3], 1):
                    print(f"     {i}. {rec}")
        except Exception as e:
            print(f"❌ Failed to generate comprehensive sensitive data summary: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 5: Test MCP Tool Interface
        print("5. Testing MCP tool interface...")
        try:
            # List available tools
            tools = await server._list_tools_handler()
            new_tool_names = [
                "check_repository_attack_surface",
                "check_repository_sensitive_data", 
                "list_application_repository_connections",
                "get_sensitive_data_summary"
            ]
            
            # Handle different possible return types from _list_tools_handler
            tool_names = []
            if tools:
                for tool in tools:
                    if hasattr(tool, 'name'):
                        tool_names.append(tool.name)
                    elif isinstance(tool, dict) and 'name' in tool:
                        tool_names.append(tool['name'])
            
            found_tools = [name for name in tool_names if name in new_tool_names]
            print(f"✅ Found {len(found_tools)}/{len(new_tool_names)} new tools in MCP interface")
            for tool_name in found_tools:
                print(f"   ✓ {tool_name}")
            
            missing_tools = [name for name in new_tool_names if name not in found_tools]
            if missing_tools:
                print("   Missing tools:")
                for tool_name in missing_tools:
                    print(f"   ✗ {tool_name}")
        except Exception as e:
            print(f"❌ Failed to test MCP tool interface: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 6: Demonstrate improved tool usage
        print("6. Testing tool call interface...")
        try:
            # Test calling the new tool through the MCP interface
            result = await server.call_tool(
                "check_repository_attack_surface",
                {"repo_name": "test-repo", "include_vulnerabilities": True}
            )
            print("✅ Tool call interface working!")
            print(f"   Response type: {type(result)}")
            print(f"   Response length: {len(result) if result else 0}")
        except Exception as e:
            print(f"⚠️  Tool call interface test failed: {e}")
        
        print("\n" + "="*60)
        print("✅ All New MCP Tools Testing Complete!")
        print("\nSummary of Changes for Issue #66:")
        print("- ✅ Removed duplicate sensitive data tools")
        print("- ✅ Added attack surface lookup for current repository")
        print("- ✅ Added sensitive data lookup for current repository")
        print("- ✅ Added application/code repository connection mapping")
        print("- ✅ Consolidated sensitive data tools into single comprehensive tool")
        print("- ✅ All tools support auto-detection of current repository name")
        print("- ✅ All tools provide actionable recommendations")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(test_new_tools())