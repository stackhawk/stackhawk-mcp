#!/usr/bin/env python3
"""
Test script for Application-Specific vs Organization-Wide Vulnerabilities

This script demonstrates the difference between getting vulnerabilities
for a specific application vs getting all organization-wide vulnerabilities.
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
async def test_vulnerability_scoping():
    """Test the difference between organization-wide and application-specific vulnerabilities"""
    
    # Get API key from environment
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing Application-Specific vs Organization-Wide Vulnerabilities")
    print("=" * 70)
    
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
        apps_response = await server.client.list_applications(org_id, pageSize=10)
        applications = apps_response.get("applications", [])
        
        if not applications:
            print("❌ No applications found")
            return
        
        # Use the first application for testing
        test_app = applications[0]
        app_id = test_app["id"]
        app_name = test_app["name"]
        print(f"✅ Test Application: {app_name} (ID: {app_id})")
        
        # Test 1: Organization-wide vulnerabilities (OLD METHOD - CAUSES CONFUSION)
        print("\n3. Testing Organization-Wide Vulnerabilities (OLD METHOD)...")
        org_vulns = await server._search_vulnerabilities(org_id, severity="High")
        
        print("✅ Organization-Wide Results:")
        print(f"   - Total Matches: {org_vulns.get('totalMatches', 0)}")
        print(f"   - Note: {org_vulns.get('note', 'No note')}")
        
        # Show first few findings
        findings = org_vulns.get('findings', [])
        if findings:
            print(f"\n   Sample Organization-Wide Findings:")
            for i, finding in enumerate(findings[:3]):
                print(f"     {i+1}. {finding.get('findingName', 'Unknown')}")
                print(f"        Application: {finding.get('applicationName', 'Unknown')}")
                print(f"        Severity: {finding.get('findingRisk', 'Unknown')}")
                print()
        
        # Test 2: Application-specific vulnerabilities (Unified Method)
        print("\n4. Testing Application-Specific Vulnerabilities (Unified Method)...")
        app_vulns = await server._get_application_vulnerabilities(
            app_id=app_id,
            org_id=org_id,
            severity_filter="All",
            include_remediation=True,
            max_results=50
        )
        print("✅ Application-Specific Results:")
        print(f"   - Application: {app_vulns.get('applicationName', 'Unknown')}")
        print(f"   - Total Findings: {app_vulns.get('totalFindings', 0)}")
        print(f"   - Note: {app_vulns.get('note', 'No note')}")
        severity_breakdown = app_vulns.get('severityBreakdown', {})
        print(f"   - Severity Breakdown: High={severity_breakdown.get('High', 0)}, Medium={severity_breakdown.get('Medium', 0)}, Low={severity_breakdown.get('Low', 0)}")
        findings = app_vulns.get('findings', [])
        if findings:
            print(f"\n   Sample Application-Specific Findings:")
            for i, finding in enumerate(findings[:3]):
                print(f"     {i+1}. {finding.get('findingName', 'Unknown')}")
                print(f"        Severity: {finding.get('findingRisk', 'Unknown')}")
                print(f"        Status: {finding.get('status', 'Unknown')}")
                print()
        # Test 2b: Application-specific vulnerabilities (Triage Mode)
        print("\n4b. Testing Application-Specific Vulnerabilities (Triage Mode)...")
        app_vulns_triage = await server._get_application_vulnerabilities(
            app_id=app_id,
            org_id=org_id,
            triage_mode=True,
            max_results=100
        )
        print("✅ Application-Specific Triage Results:")
        print(f"   - Application: {app_vulns_triage.get('applicationName', 'Unknown')}")
        print(f"   - Total Triage Findings: {app_vulns_triage.get('totalFindings', 0)}")
        print(f"   - Triage Mode: {app_vulns_triage.get('triageMode', False)}")
        print(f"   - Failure Threshold: {app_vulns_triage.get('failureThreshold', 'High/Medium')}")
        triage_findings = app_vulns_triage.get('findings', [])
        if triage_findings:
            print(f"\n   Sample Triage Findings:")
            for i, finding in enumerate(triage_findings[:3]):
                print(f"     {i+1}. {finding.get('findingName', 'Unknown')}")
                print(f"        Severity: {finding.get('findingRisk', 'Unknown')}")
                print(f"        Status: {finding.get('status', 'Unknown')}")
                print()
        
        # Test 3: Application Security Summary
        print("\n5. Testing Application Security Summary...")
        app_summary = await server._get_application_security_summary(
            app_id=app_id,
            org_id=org_id,
            include_trends=False,
            include_recommendations=True
        )
        
        print("✅ Application Security Summary:")
        print(f"   - Application: {app_summary.get('applicationName', 'Unknown')}")
        print(f"   - Environment: {app_summary.get('environment', 'Unknown')}")
        
        security_metrics = app_summary.get('securityMetrics', {})
        print(f"   - Security Score: {security_metrics.get('securityScore', 0)}")
        print(f"   - Total Vulnerabilities: {security_metrics.get('totalVulnerabilities', 0)}")
        print(f"   - Critical Findings: {security_metrics.get('criticalFindings', 0)}")
        
        recommendations = app_summary.get('recommendations', [])
        if recommendations:
            print(f"\n   Recommendations:")
            for i, rec in enumerate(recommendations):
                print(f"     {i+1}. {rec}")
        
        # Test 4: Compare the difference
        print("\n6. Comparing Organization-Wide vs Application-Specific...")
        
        org_total = org_vulns.get('totalMatches', 0)
        app_total = app_vulns.get('totalFindings', 0)
        
        print("✅ Comparison Results:")
        print(f"   - Organization-Wide Vulnerabilities: {org_total}")
        print(f"   - Application-Specific Vulnerabilities: {app_total}")
        print(f"   - Difference: {org_total - app_total} vulnerabilities from other applications")
        
        if org_total > app_total:
            print(f"   - ⚠️  Organization-wide shows {org_total - app_total} more vulnerabilities from other applications!")
            print(f"   - 💡 This is why LLMs might think you have {org_total} vulnerabilities in one app")
        
        # Test 5: Application Comparison (if we have multiple apps)
        if len(applications) > 1:
            print("\n7. Testing Application Comparison...")
            app_ids = [app["id"] for app in applications[:3]]  # Compare first 3 apps
            
            comparison = await server._compare_application_security(
                org_id=org_id,
                app_ids=app_ids,
                comparison_metrics=["vulnerability_count", "security_score"]
            )
            
            print("✅ Application Comparison Results:")
            vuln_counts = comparison.get('comparison', {}).get('vulnerabilityCounts', {})
            for app_name, count in vuln_counts.items():
                print(f"   - {app_name}: {count} vulnerabilities")
            
            insights = comparison.get('insights', [])
            if insights:
                print(f"\n   Insights:")
                for insight in insights:
                    print(f"     - {insight}")
        
        print("\n" + "=" * 70)
        print("✅ Vulnerability Scoping Tests Completed!")
        
        # Save detailed results to file
        results = {
            "organization_wide_vulnerabilities": org_vulns,
            "application_specific_vulnerabilities": app_vulns,
            "application_security_summary": app_summary,
            "comparison": {
                "org_total": org_total,
                "app_total": app_total,
                "difference": org_total - app_total
            },
            "timestamp": datetime.now().isoformat()
        }
        
        with open("vulnerability_scoping_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print("📄 Detailed results saved to vulnerability_scoping_results.json")
        
        # Summary and recommendations
        print("\n📋 Summary and Recommendations:")
        print("=" * 50)
        print("🔍 The Issue:")
        print("   - Organization-wide methods return ALL vulnerabilities across ALL applications")
        print("   - This can make it appear that a single app has hundreds/thousands of vulnerabilities")
        print("   - LLMs may misinterpret this as application-specific data")
        
        print("\n✅ The Solution:")
        print("   - Use get_application_vulnerabilities() for app-specific data")
        print("   - Use get_application_security_summary() for app-specific summaries")
        print("   - Organization-wide methods now include clear disclaimers")
        print("   - Reduced page sizes to prevent overwhelming results")
        
        print("\n💡 Best Practices:")
        print("   - Always specify the application ID when asking about vulnerabilities")
        print("   - Use application-specific tools for detailed analysis")
        print("   - Use organization-wide tools only for high-level overviews")
        print("   - Check the 'note' field in responses for clarification")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup()


async def main():
    """Main test function"""
    print("🚀 StackHawk MCP Vulnerability Scoping Test Suite")
    print("=" * 70)
    
    await test_vulnerability_scoping()
    
    print("\n🎉 All tests completed!")


if __name__ == "__main__":
    asyncio.run(main()) 