#!/usr/bin/env python3
"""
Test script for StackHawk MCP Server Sensitive Data Analysis

This script tests the new sensitive data analysis capabilities including:
- Comprehensive sensitive data summary
- Repository-specific sensitive data checks
- Application and repository connection mapping
"""

import asyncio
import os
import sys
from datetime import datetime
import pytest

# Add the stackhawk_mcp directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from stackhawk_mcp.server import StackHawkMCPServer


@pytest.mark.asyncio
async def test_sensitive_data_functionality():
    """Test the sensitive data analysis functionality"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing StackHawk Sensitive Data Analysis")
    print("=" * 60)
    
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info and organization ID
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        org_name = user_info["user"]["external"]["organizations"][0]["organization"]["name"]
        
        print(f"✅ Connected to organization: {org_name} (ID: {org_id})")
        print()
        
        # Test 1: Get Comprehensive Sensitive Data Summary
        print("1. Testing comprehensive sensitive data summary...")
        try:
            result = await server._get_comprehensive_sensitive_data_summary(
                org_id=org_id,
                time_period="30d",
                include_trends=True,
                include_critical_only=False,
                include_recommendations=True,
                group_by="data_type"
            )
            print("✅ Comprehensive sensitive data summary generated successfully!")
            print(f"   Total findings: {result.get('total_findings', 0)}")
            print(f"   Analysis type: {result.get('analysis_type', 'N/A')}")
            print(f"   Risk score: {result.get('overall_risk_score', 0):.1f}")
        except Exception as e:
            print(f"❌ Failed to generate comprehensive summary: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 2: Check Repository Sensitive Data
        print("2. Testing repository sensitive data check...")
        try:
            # Get a sample repository
            repos_response = await server.client.list_repositories(org_id, pageSize=5)
            repositories = repos_response.get("repositories", [])
            
            if repositories:
                repo_name = repositories[0]["name"]
                
                result = await server._check_repository_sensitive_data(
                    repo_name=repo_name,
                    org_id=org_id,
                    data_type_filter="All",
                    include_remediation=True
                )
                print(f"✅ Repository sensitive data checked for {repo_name}!")
                print(f"   Found in StackHawk: {result.get('found_in_stackhawk', False)}")
                print(f"   Has sensitive data: {result.get('has_sensitive_data', False)}")
                print(f"   Total findings: {result.get('total_findings', 0)}")
            else:
                print("⚠️  No repositories found to test with")
        except Exception as e:
            print(f"❌ Failed to check repository sensitive data: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 3: Check Repository Attack Surface
        print("3. Testing repository attack surface check...")
        try:
            repos_response = await server.client.list_repositories(org_id, pageSize=5)
            repositories = repos_response.get("repositories", [])
            
            if repositories:
                repo_name = repositories[0]["name"]
                
                result = await server._check_repository_attack_surface(
                    repo_name=repo_name,
                    org_id=org_id,
                    include_vulnerabilities=True,
                    include_apps=True
                )
                print(f"✅ Repository attack surface checked for {repo_name}!")
                print(f"   Found in attack surface: {result.get('found_in_attack_surface', False)}")
                print(f"   Connected apps: {result.get('total_connected_apps', 0)}")
            else:
                print("⚠️  No repositories found to test with")
        except Exception as e:
            print(f"❌ Failed to check repository attack surface: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 4: List Application-Repository Connections
        print("4. Testing application-repository connections...")
        try:
            result = await server._list_application_repository_connections(
                org_id=org_id,
                include_repo_details=True,
                include_app_details=True,
                filter_connected_only=False
            )
            print("✅ Application-repository connections listed!")
            print(f"   Total applications: {result.get('total_applications', 0)}")
            print(f"   Total repositories: {result.get('total_repositories', 0)}")
            print(f"   Total connections: {result.get('total_connections', 0)}")
            coverage_stats = result.get('coverage_stats', {})
            print(f"   Connection coverage: {coverage_stats.get('connection_coverage', 0):.1f}%")
        except Exception as e:
            print(f"❌ Failed to list connections: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 5: Test Different Grouping Options
        print("5. Testing different grouping options for sensitive data...")
        grouping_options = ["data_type", "application", "repository"]
        for group_by in grouping_options:
            try:
                result = await server._get_comprehensive_sensitive_data_summary(
                    org_id=org_id,
                    time_period="7d",
                    include_trends=False,
                    group_by=group_by
                )
                print(f"✅ {group_by} grouping: {result.get('total_findings', 0)} findings")
            except Exception as e:
                print(f"❌ Failed with {group_by} grouping: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 6: API Endpoint Information
        print("6. New Sensitive Data API Structure:")
        print("    Repository-specific: GET /api/v1/org/{orgId}/repo/{repoId}/sensitive/list")
        print("    Features:")
        print("      - Repository-centric approach for better granularity")
        print("      - Comprehensive org-wide summaries with aggregation")
        print("      - Attack surface analysis and mapping")
        print("      - Application-repository connection tracking")
        print("      - Risk assessment and recommendations")
        
        print("\n=== Sensitive Data Analysis Testing Complete ===")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup()


@pytest.mark.asyncio
async def test_sensitive_data_api_endpoints():
    """Test direct sensitive data API endpoints"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("\n🔍 Testing Direct Sensitive Data API Endpoints")
    print("=" * 60)
    
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        
        # Test 1: List Sensitive Data Findings (aggregated)
        print("\n1. Testing list_sensitive_data_findings endpoint...")
        try:
            findings_response = await server.client.list_sensitive_data_findings(org_id, pageSize=10)
            findings = findings_response.get("sensitiveDataFindings", [])
            
            print(f"✅ Found {len(findings)} sensitive data findings (aggregated from repositories)")
            if findings:
                print("   Sample findings:")
                for i, finding in enumerate(findings[:3]):
                    print(f"     {i+1}. Type: {finding.get('dataType', 'Unknown')}")
                    print(f"        Location: {finding.get('location', 'Unknown')}")
                    print()
        except Exception as e:
            print(f"⚠️  Could not get sensitive data findings: {e}")
        
        # Test 2: Get Sensitive Data Summary
        print("\n2. Testing get_sensitive_data_summary endpoint...")
        try:
            summary_response = await server.client.get_sensitive_data_summary(org_id)
            print("✅ Sensitive data summary retrieved successfully")
            print(f"   Summary: {summary_response}")
        except Exception as e:
            print(f"⚠️  Could not get sensitive data summary (endpoint may use fallback): {e}")
        
        # Test 3: Repository-Specific Sensitive Data
        print("\n3. Testing repository-specific sensitive data (official endpoint)...")
        try:
            repos_response = await server.client.list_repositories(org_id, pageSize=5)
            repositories = repos_response.get("repositories", [])
            
            if repositories:
                repo_id = repositories[0]["id"]
                repo_sensitive_data = await server.client.get_repository_sensitive_data(org_id, repo_id, pageSize=10)
                findings = repo_sensitive_data.get("sensitiveDataFindings", [])
                print(f"✅ Found {len(findings)} sensitive data findings for repository {repositories[0]['name']}")
                print(f"   Using official endpoint: /api/v1/org/{org_id}/repo/{repo_id}/sensitive/list")
            else:
                print("⚠️  No repositories found to test with")
        except Exception as e:
            print(f"⚠️  Could not get repository sensitive data: {e}")
        
        print("\n" + "="*60)
        print("✅ Sensitive Data API Endpoint Tests Completed!")
        
    except Exception as e:
        print(f"❌ Error during API testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup() 