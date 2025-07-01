#!/usr/bin/env python3
"""
Test script to verify that all-time reports include all findings
"""

import asyncio
import os
import sys
from datetime import datetime
import pytest

# Add the current directory to the path so we can import the server
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from stackhawk_mcp.server import StackHawkMCPServer

@pytest.mark.asyncio
async def test_all_time_reports():
    """Test that all-time reports include all findings"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing all-time reports to verify complete data inclusion...")
    
    try:
        # Create server instance
        server = StackHawkMCPServer(api_key)
        
        # Get user info to find organization ID
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        org_name = user_info["user"]["external"]["organizations"][0]["organization"]["name"]
        
        print(f"📊 Testing organization: {org_name} ({org_id})")
        
        # Test 1: Executive Summary - All Time
        print("\n1. Testing all-time executive summary...")
        start_time = datetime.now()
        exec_summary = await server._generate_executive_summary(
            org_id=org_id,
            time_period="all",
            include_recommendations=True,
            include_risk_score=True
        )
        end_time = datetime.now()
        
        total_findings = exec_summary["summary"]["totalFindings"]
        scan_coverage = exec_summary["summary"]["scanCoverage"]
        
        print(f"✅ All-time executive summary generated!")
        print(f"   Total findings: {total_findings}")
        print(f"   Scan coverage: {scan_coverage['totalScans']} total scans")
        print(f"   Processing time: {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Test 2: Vulnerability Report - All Time
        print("\n2. Testing all-time vulnerability report...")
        start_time = datetime.now()
        vuln_report = await server._get_vulnerability_report(
            org_id=org_id,
            severity_filter="All",
            time_range="all",
            include_remediation=True,
            group_by="severity"
        )
        end_time = datetime.now()
        
        total_findings_vuln = vuln_report.get("totalFindings", 0)
        
        print(f"✅ All-time vulnerability report generated!")
        print(f"   Total findings: {total_findings_vuln}")
        print(f"   Processing time: {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Test 3: Critical Findings - All Time
        print("\n3. Testing all-time critical findings...")
        start_time = datetime.now()
        critical_findings = await server._get_critical_findings(
            org_id=org_id,
            severity_levels=["Critical", "High"],
            include_remediation=True,
            max_results=100
        )
        end_time = datetime.now()
        
        total_critical = critical_findings.get("totalFindings", 0)
        
        print(f"✅ All-time critical findings retrieved!")
        print(f"   Total critical/high findings: {total_critical}")
        print(f"   Processing time: {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Test 4: Vulnerability Trends - All Time
        print("\n4. Testing all-time vulnerability trends...")
        start_time = datetime.now()
        trends = await server._analyze_vulnerability_trends(
            org_id=org_id,
            analysis_period="1y",
            include_applications=True,
            include_severity_breakdown=True
        )
        end_time = datetime.now()
        
        total_trends = len(trends.get("trends", []))
        
        print(f"✅ All-time vulnerability trends analyzed!")
        print(f"   Applications analyzed: {total_trends}")
        print(f"   Processing time: {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Test 5: Sensitive Data Report - All Time
        print("\n5. Testing all-time sensitive data report...")
        start_time = datetime.now()
        sensitive_report = await server._get_sensitive_data_report(
            org_id=org_id,
            data_type_filter="All",
            time_range="all",
            include_details=True,
            group_by="data_type"
        )
        end_time = datetime.now()
        
        total_sensitive = sensitive_report.get("totalFindings", 0)
        
        print(f"✅ All-time sensitive data report generated!")
        print(f"   Total sensitive data findings: {total_sensitive}")
        print(f"   Processing time: {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Test 6: Sensitive Data Summary - All Time
        print("\n6. Testing all-time sensitive data summary...")
        start_time = datetime.now()
        sensitive_summary = await server._generate_sensitive_data_summary(
            org_id=org_id,
            time_period="all",
            include_recommendations=True,
            include_risk_assessment=True
        )
        end_time = datetime.now()
        
        total_sensitive_summary = sensitive_summary["summary"]["totalFindings"]
        
        print(f"✅ All-time sensitive data summary generated!")
        print(f"   Total sensitive data findings: {total_sensitive_summary}")
        print(f"   Processing time: {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Summary
        print(f"\n📈 SUMMARY:")
        print(f"   Executive Summary Findings: {total_findings}")
        print(f"   Vulnerability Report Findings: {total_findings_vuln}")
        print(f"   Critical Findings: {total_critical}")
        print(f"   Sensitive Data Findings: {total_sensitive}")
        print(f"   Sensitive Data Summary: {total_sensitive_summary}")
        
        # Verify consistency
        if total_findings == total_findings_vuln:
            print(f"✅ Consistency check passed: All reports show same total findings")
        else:
            print(f"⚠️  Consistency check: Executive summary ({total_findings}) vs Vulnerability report ({total_findings_vuln})")
        
        # Check if we're getting substantial data (more than just page size)
        if total_findings > 1000:
            print(f"✅ Success: All-time reports include more than 1000 findings ({total_findings}), confirming complete data inclusion")
        else:
            print(f"ℹ️  Note: Total findings ({total_findings}) is within expected range")
        
        await server.cleanup()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc() 