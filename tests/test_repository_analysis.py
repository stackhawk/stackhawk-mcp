#!/usr/bin/env python3
"""
Test script for StackHawk MCP Repository and Threat Surface Analysis

This script demonstrates the new repository analysis and threat surface mapping
capabilities of the StackHawk MCP server.
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
async def test_repository_analysis():
    """Test repository and threat surface analysis features"""
    
    # Get API key from environment
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing StackHawk Repository and Threat Surface Analysis")
    print("=" * 60)
    
    # Create server instance
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info to find organization ID
        print("\n1. Getting user information...")
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        org_name = user_info["user"]["external"]["organizations"][0]["organization"]["name"]
        print(f"✅ Organization: {org_name} (ID: {org_id})")
        
        # Test 1: Analyze Threat Surface
        print("\n2. Analyzing Threat Surface...")
        threat_surface = await server._analyze_threat_surface(
            org_id=org_id,
            include_repositories=True,
            include_applications=True,
            include_vulnerabilities=True,
            risk_assessment=True
        )
        
        print("✅ Threat Surface Analysis Results:")
        print(f"   - Total Assets: {threat_surface['summary']['total_assets']}")
        print(f"   - Total Vulnerabilities: {threat_surface['summary']['total_vulnerabilities']}")
        print(f"   - Risk Level: {threat_surface['summary']['risk_level']}")
        
        if 'repositories' in threat_surface['analysis']:
            repos = threat_surface['analysis']['repositories']
            print(f"   - Repositories: {repos.get('total_repositories', 0)} total")
            print(f"   - Active Repos: {repos.get('active_repositories', 0)}")
            print(f"   - Archived Repos: {repos.get('archived_repositories', 0)}")
        
        if 'applications' in threat_surface['analysis']:
            apps = threat_surface['analysis']['applications']
            print(f"   - Applications: {apps.get('total_applications', 0)} total")
            print(f"   - Production Apps: {apps.get('production_apps', 0)}")
            print(f"   - Development Apps: {apps.get('development_apps', 0)}")
        
        if 'risk_assessment' in threat_surface['analysis']:
            risk = threat_surface['analysis']['risk_assessment']
            print(f"   - Overall Risk Score: {risk.get('overall_risk_score', 0):.1f}")
            print(f"   - Risk Factors: {len(risk.get('risk_factors', []))}")
            print(f"   - Recommendations: {len(risk.get('recommendations', []))}")
        
        # Test 2: Repository Security Overview
        print("\n3. Getting Repository Security Overview...")
        repo_overview = await server._get_repository_security_overview(
            org_id=org_id,
            include_scan_results=True,
            include_vulnerabilities=True,
            filter_by_status="all"
        )
        
        print("✅ Repository Security Overview:")
        print(f"   - Total Repositories: {repo_overview.get('total_repositories', 0)}")
        
        security_summary = repo_overview.get('security_summary', {})
        print(f"   - High Risk Repos: {security_summary.get('high_risk_repos', 0)}")
        print(f"   - Medium Risk Repos: {security_summary.get('medium_risk_repos', 0)}")
        print(f"   - Low Risk Repos: {security_summary.get('low_risk_repos', 0)}")
        
        # Show first few repositories
        repos = repo_overview.get('repositories', [])
        if repos:
            print(f"\n   Sample Repositories:")
            for i, repo in enumerate(repos[:3]):
                print(f"     {i+1}. {repo.get('name', 'Unknown')} - Score: {repo.get('security_score', 0)}")
        
        # Test 3: Identify High Risk Repositories
        print("\n4. Identifying High Risk Repositories...")
        high_risk = await server._identify_high_risk_repositories(
            org_id=org_id,
            risk_threshold="high",
            include_remediation=True,
            max_results=10
        )
        
        print("✅ High Risk Repository Analysis:")
        print(f"   - Total High Risk Repos: {high_risk.get('total_identified', 0)}")
        
        high_risk_repos = high_risk.get('high_risk_repositories', [])
        if high_risk_repos:
            print(f"\n   High Risk Repositories:")
            for i, repo in enumerate(high_risk_repos[:5]):
                print(f"     {i+1}. {repo.get('name', 'Unknown')}")
                print(f"        Risk Level: {repo.get('risk_level', 'Unknown')}")
                print(f"        Security Score: {repo.get('security_score', 0)}")
                print(f"        Vulnerabilities: {repo.get('vulnerability_count', 0)}")
                if repo.get('remediation'):
                    print(f"        Remediation: {repo['remediation'][0] if repo['remediation'] else 'None'}")
                print()
        
        # Test 4: Generate Code Security Report
        print("\n5. Generating Code Security Report...")
        security_report = await server._generate_code_security_report(
            org_id=org_id,
            report_type="executive",
            include_trends=True,
            include_comparison=True
        )
        
        print("✅ Code Security Report Generated:")
        summary = security_report.get('summary', {})
        print(f"   - Total Repositories: {summary.get('total_repositories', 0)}")
        print(f"   - Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   - Average Security Score: {summary.get('average_security_score', 0):.1f}")
        
        risk_dist = summary.get('risk_distribution', {})
        print(f"   - Risk Distribution: High={risk_dist.get('high', 0)}, Medium={risk_dist.get('medium', 0)}, Low={risk_dist.get('low', 0)}")
        
        if 'executive_summary' in security_report:
            exec_summary = security_report['executive_summary']
            print(f"\n   Executive Summary:")
            print(f"     - Key Findings: {len(exec_summary.get('key_findings', []))}")
            print(f"     - Recommendations: {len(exec_summary.get('recommendations', []))}")
            
            risk_assessment = exec_summary.get('risk_assessment', {})
            print(f"     - Overall Risk Level: {risk_assessment.get('overall_risk_level', 'Unknown')}")
        
        # Test 5: Map Attack Surface
        print("\n6. Mapping Attack Surface...")
        attack_surface = await server._map_attack_surface(
            org_id=org_id,
            include_internal=True,
            include_external=True,
            include_third_party=True,
            risk_visualization=True
        )
        
        print("✅ Attack Surface Mapping:")
        attack_vectors = attack_surface.get('attack_vectors', {})
        print(f"   - Repositories: {len(attack_vectors.get('repositories', []))}")
        print(f"   - Applications: {len(attack_vectors.get('applications', []))}")
        print(f"   - Entry Points: {len(attack_surface.get('entry_points', []))}")
        
        # Show risk heatmap
        risk_heatmap = attack_surface.get('risk_heatmap', {})
        print(f"\n   Risk Heatmap:")
        print(f"     - High Risk: {len(risk_heatmap.get('high_risk', []))}")
        print(f"     - Medium Risk: {len(risk_heatmap.get('medium_risk', []))}")
        print(f"     - Low Risk: {len(risk_heatmap.get('low_risk', []))}")
        
        # Show entry points
        entry_points = attack_surface.get('entry_points', [])
        if entry_points:
            print(f"\n   Entry Points:")
            for i, entry in enumerate(entry_points[:3]):
                print(f"     {i+1}. {entry.get('type', 'Unknown')} - {entry.get('name', 'Unknown')}")
                print(f"        Risk Level: {entry.get('risk_level', 'Unknown')}")
        
        print("\n" + "=" * 60)
        print("✅ All Repository and Threat Surface Analysis Tests Completed!")
        
        # Save detailed results to file
        results = {
            "threat_surface": threat_surface,
            "repository_overview": repo_overview,
            "high_risk_repositories": high_risk,
            "security_report": security_report,
            "attack_surface": attack_surface,
            "timestamp": datetime.now().isoformat()
        }
        
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "repository_analysis_results.json")
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"📄 Detailed results saved to {output_path}")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup()


@pytest.mark.asyncio
async def test_repository_api_endpoints():
    """Test direct repository API endpoints"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("\n🔍 Testing Direct Repository API Endpoints")
    print("=" * 50)
    
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        
        # Test 1: List Repositories
        print("\n1. Testing list_repositories endpoint...")
        repos_response = await server.client.list_repositories(org_id, pageSize=10)
        repositories = repos_response.get("repositories", [])
        
        print(f"✅ Found {len(repositories)} repositories")
        if repositories:
            print("   Sample repositories:")
            for i, repo in enumerate(repositories[:3]):
                print(f"     {i+1}. {repo.get('name', 'Unknown')} (ID: {repo.get('id', 'Unknown')})")
                print(f"        Status: {repo.get('status', 'Unknown')}")
                print(f"        Security Score: {repo.get('securityScore', 'Unknown')}")
                print(f"        Last Scan: {repo.get('lastScanDate', 'Unknown')}")
                print()
        
        # Test 2: Get Repository Details (if we have a repo)
        if repositories:
            repo_id = repositories[0]["id"]
            print(f"\n2. Testing get_repository_details for repo {repo_id}...")
            try:
                repo_details = await server.client.get_repository_details(org_id, repo_id)
                print("✅ Repository details retrieved successfully")
                print(f"   Name: {repo_details.get('name', 'Unknown')}")
                print(f"   Status: {repo_details.get('status', 'Unknown')}")
                print(f"   Security Score: {repo_details.get('securityScore', 'Unknown')}")
            except Exception as e:
                print(f"⚠️  Could not get repository details: {e}")
        
        # Test 3: Get Repository Security Scan (if we have a repo)
        if repositories:
            repo_id = repositories[0]["id"]
            print(f"\n3. Testing get_repository_security_scan for repo {repo_id}...")
            try:
                scan_results = await server.client.get_repository_security_scan(org_id, repo_id)
                print("✅ Repository security scan results retrieved successfully")
                print(f"   Scan Status: {scan_results.get('status', 'Unknown')}")
                print(f"   Vulnerabilities Found: {scan_results.get('vulnerabilityCount', 'Unknown')}")
            except Exception as e:
                print(f"⚠️  Could not get repository security scan: {e}")
        
        print("\n" + "=" * 50)
        print("✅ Repository API Endpoint Tests Completed!")
        
    except Exception as e:
        print(f"❌ Error during API testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup() 