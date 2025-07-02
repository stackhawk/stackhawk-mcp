#!/usr/bin/env python3
"""
Test script for StackHawk MCP Server Sensitive Data Analysis

This script tests the new sensitive data analysis capabilities including:
- Sensitive data reporting
- Trend analysis
- Critical findings identification
- Application and repository specific analysis
- Data type categorization
- Risk assessment and mapping
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
        
        # Test 2: Get Sensitive Data Report
        print("2. Testing sensitive data report generation...")
        try:
            result = await server._get_sensitive_data_report(
                org_id=org_id,
                data_type_filter="All",
                time_range="30d",
                include_details=True,
                group_by="data_type"
            )
            print("✅ Sensitive data report generated successfully!")
            print(f"   Total findings: {result['totalFindings']}")
            print(f"   Data type filter: {result['dataTypeFilter']}")
            print(f"   Time range: {result['timeRange']}")
            print(f"   Report groups: {len(result['report'])}")
        except Exception as e:
            print(f"❌ Failed to generate sensitive data report: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 3: Analyze Sensitive Data Trends
        print("3. Testing sensitive data trend analysis...")
        try:
            result = await server._analyze_sensitive_data_trends(
                org_id=org_id,
                analysis_period="90d",
                include_applications=True,
                include_repositories=True
            )
            print("✅ Sensitive data trends analyzed successfully!")
            trends = result.get("trends", {})
            print(f"   Total findings: {trends.get('totalFindings', 0)}")
            print(f"   Data type breakdown: {trends.get('dataTypeBreakdown', {})}")
            print(f"   Application trends: {len(trends.get('applicationTrends', []))}")
            print(f"   Repository trends: {len(trends.get('repositoryTrends', []))}")
        except Exception as e:
            print(f"❌ Failed to analyze sensitive data trends: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 4: Get Critical Sensitive Data
        print("4. Testing critical sensitive data identification...")
        try:
            result = await server._get_critical_sensitive_data(
                org_id=org_id,
                data_types=["PII", "PCI", "PHI"],
                include_remediation=True,
                max_results=25
            )
            print("✅ Critical sensitive data retrieved successfully!")
            print(f"   Total critical findings: {result['totalFindings']}")
            print(f"   Data types monitored: {result['dataTypes']}")
            if result['findings']:
                print("   Sample findings:")
                for i, finding in enumerate(result['findings'][:3]):
                    print(f"     {i+1}. Type: {finding.get('dataType', 'Unknown')}")
                    print(f"        Location: {finding.get('location', 'Unknown')}")
                    print(f"        Severity: {finding.get('severity', 'Unknown')}")
        except Exception as e:
            print(f"❌ Failed to get critical sensitive data: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 5: Generate Sensitive Data Summary
        print("5. Testing sensitive data summary generation...")
        try:
            result = await server._generate_sensitive_data_summary(
                org_id=org_id,
                time_period="30d",
                include_recommendations=True,
                include_risk_assessment=True
            )
            print("✅ Sensitive data summary generated successfully!")
            summary = result.get("summary", {})
            print(f"   Total findings: {summary.get('totalFindings', 0)}")
            print(f"   Data type breakdown: {summary.get('dataTypeBreakdown', {})}")
            if 'riskAssessment' in summary:
                print(f"   Risk assessment score: {summary['riskAssessment']}")
            if 'recommendations' in summary:
                print(f"   Recommendations: {len(summary['recommendations'])}")
        except Exception as e:
            print(f"❌ Failed to generate sensitive data summary: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 6: Map Sensitive Data Surface
        print("6. Testing sensitive data surface mapping...")
        try:
            result = await server._map_sensitive_data_surface(
                org_id=org_id,
                include_applications=True,
                include_repositories=True,
                risk_visualization=True
            )
            print("✅ Sensitive data surface mapped successfully!")
            exposure_vectors = result.get("exposure_vectors", {})
            print(f"   Applications analyzed: {len(exposure_vectors.get('applications', []))}")
            print(f"   Repositories analyzed: {len(exposure_vectors.get('repositories', []))}")
            print(f"   Data type distribution: {result.get('data_type_distribution', {})}")
            if result.get('risk_heatmap'):
                heatmap = result['risk_heatmap']
                print(f"   High risk items: {len(heatmap.get('high_risk', []))}")
                print(f"   Medium risk items: {len(heatmap.get('medium_risk', []))}")
                print(f"   Low risk items: {len(heatmap.get('low_risk', []))}")
        except Exception as e:
            print(f"❌ Failed to map sensitive data surface: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 7: Application-Specific Sensitive Data
        print("7. Testing application-specific sensitive data...")
        try:
            # Get a sample application
            apps_response = await server.client.list_applications(org_id, pageSize=5)
            applications = apps_response.get("applications", [])
            
            if applications:
                app_id = applications[0]["id"]
                app_name = applications[0]["name"]
                
                result = await server._get_sensitive_data(
                    target_type="application",
                    target_id=app_id,
                    org_id=org_id,
                    data_type_filter="All",
                    include_details=True,
                    max_results=50
                )
                print(f"✅ Application sensitive data retrieved for {app_name}!")
                print(f"   Total findings: {result['totalFindings']}")
                print(f"   Data type breakdown: {result['dataTypeBreakdown']}")
                print(f"   Data type filter: {result['dataTypeFilter']}")
            else:
                print("⚠️  No applications found to test with")
        except Exception as e:
            print(f"❌ Failed to get application sensitive data: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 8: Repository-Specific Sensitive Data
        print("8. Testing repository-specific sensitive data...")
        try:
            # Get a sample repository
            repos_response = await server.client.list_repositories(org_id, pageSize=5)
            repositories = repos_response.get("repositories", [])
            
            if repositories:
                repo_id = repositories[0]["id"]
                repo_name = repositories[0]["name"]
                
                result = await server._get_sensitive_data(
                    target_type="repository",
                    target_id=repo_id,
                    org_id=org_id,
                    data_type_filter="All",
                    include_details=True,
                    max_results=50
                )
                print(f"✅ Repository sensitive data retrieved for {repo_name}!")
                print(f"   Total findings: {result['totalFindings']}")
                print(f"   Data type breakdown: {result['dataTypeBreakdown']}")
                print(f"   Data type filter: {result['dataTypeFilter']}")
            else:
                print("⚠️  No repositories found to test with")
        except Exception as e:
            print(f"❌ Failed to get repository sensitive data: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 9: Demonstrate different data type filters
        print("9. Testing different data type filters...")
        data_types = ["PII", "PCI", "PHI"]
        for data_type in data_types:
            try:
                result = await server._get_sensitive_data_report(
                    org_id=org_id,
                    data_type_filter=data_type,
                    time_range="7d",
                    include_details=True,
                    group_by="application"
                )
                print(f"✅ {data_type} data report: {result['totalFindings']} findings")
            except Exception as e:
                print(f"❌ Failed to generate {data_type} report: {e}")
        
        print("\n" + "="*60 + "\n")
        
        # Test 10: API Endpoint Information
        print("10. Sensitive Data API Endpoints:")
        print("    Organization-wide: GET /api/v1/org/{orgId}/sensitive-data")
        print("    Application-specific: GET /api/v1/org/{orgId}/sensitive-data?appIds={appId}")
        print("    Repository-specific: GET /api/v1/org/{orgId}/repos/{repoId}/sensitive-data")
        print("    Data types: GET /api/v1/org/{orgId}/sensitive-data/types")
        print("    Summary: GET /api/v1/org/{orgId}/sensitive-data/summary")
        print("    Features:")
        print("      - Comprehensive filtering by data type (PII, PCI, PHI)")
        print("      - Time-based filtering and trend analysis")
        print("      - Application and repository-specific analysis")
        print("      - Risk assessment and visualization")
        print("      - Pagination support for large datasets")
        
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
        
        # Test 1: List Sensitive Data Findings
        print("\n1. Testing list_sensitive_data_findings endpoint...")
        try:
            findings_response = await server.client.list_sensitive_data_findings(org_id, pageSize=10)
            findings = findings_response.get("sensitiveDataFindings", [])
            
            print(f"✅ Found {len(findings)} sensitive data findings")
            if findings:
                print("   Sample findings:")
                for i, finding in enumerate(findings[:3]):
                    print(f"     {i+1}. Type: {finding.get('dataType', 'Unknown')}")
                    print(f"        Location: {finding.get('location', 'Unknown')}")
                    print(f"        Severity: {finding.get('severity', 'Unknown')}")
                    print()
        except Exception as e:
            print(f"⚠️  Could not get sensitive data findings: {e}")
        
        # Test 3: Get Sensitive Data Summary
        print("\n3. Testing get_sensitive_data_summary endpoint...")
        try:
            summary_response = await server.client.get_sensitive_data_summary(org_id)
            print("✅ Sensitive data summary retrieved successfully")
            print(f"   Summary: {summary_response}")
        except Exception as e:
            print(f"⚠️  Could not get sensitive data summary: {e}")
        
        # Test 4: Application-Specific Sensitive Data
        print("\n4. Testing application-specific sensitive data...")
        try:
            apps_response = await server.client.list_applications(org_id, pageSize=5)
            applications = apps_response.get("applications", [])
            
            if applications:
                app_id = applications[0]["id"]
                app_sensitive_data = await server.client.get_application_sensitive_data(app_id, org_id, pageSize=10)
                findings = app_sensitive_data.get("sensitiveDataFindings", [])
                print(f"✅ Found {len(findings)} sensitive data findings for application {applications[0]['name']}")
            else:
                print("⚠️  No applications found to test with")
        except Exception as e:
            print(f"⚠️  Could not get application sensitive data: {e}")
        
        # Test 5: Repository-Specific Sensitive Data
        print("\n5. Testing repository-specific sensitive data...")
        try:
            repos_response = await server.client.list_repositories(org_id, pageSize=5)
            repositories = repos_response.get("repositories", [])
            
            if repositories:
                repo_id = repositories[0]["id"]
                repo_sensitive_data = await server.client.get_repository_sensitive_data(org_id, repo_id, pageSize=10)
                findings = repo_sensitive_data.get("sensitiveDataFindings", [])
                print(f"✅ Found {len(findings)} sensitive data findings for repository {repositories[0]['name']}")
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