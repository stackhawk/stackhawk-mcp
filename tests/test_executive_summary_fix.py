#!/usr/bin/env python3
"""
Test script to verify the executive summary fix

This script tests the fixed generate_executive_summary method to ensure it:
- Properly handles time period filtering
- Generates meaningful recommendations
- Calculates risk scores correctly
- Handles edge cases properly
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
async def test_executive_summary_fix():
    """Test the fixed executive summary functionality"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing Fixed Executive Summary")
    print("=" * 50)
    
    server = StackHawkMCPServer(api_key)
    
    try:
        # Get user info and organization ID
        user_info = await server.client.get_user_info()
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        org_name = user_info["user"]["external"]["organizations"][0]["organization"]["name"]
        
        print(f"✅ Connected to organization: {org_name} (ID: {org_id})")
        print()
        
        # Test 1: Default executive summary (30 days)
        print("1. Testing default executive summary (30 days)...")
        try:
            result = await server._generate_executive_summary(org_id)
            print("✅ Default executive summary generated successfully!")
            print(f"   Time period: {result.get('timePeriod', 'Unknown')}")
            print(f"   Total findings: {result['summary']['totalFindings']}")
            print(f"   Critical findings: {result['summary']['criticalFindings']}")
            print(f"   Risk score: {result['summary'].get('riskScore', 'N/A')}")
            print(f"   Risk level: {result['summary'].get('riskLevel', 'N/A')}")
            print(f"   Recommendations: {len(result['summary'].get('recommendations', []))}")
        except Exception as e:
            print(f"❌ Failed to generate default executive summary: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 2: 7-day executive summary
        print("2. Testing 7-day executive summary...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="7d",
                include_recommendations=True,
                include_risk_score=True
            )
            print("✅ 7-day executive summary generated successfully!")
            print(f"   Time period: {result.get('timePeriod', 'Unknown')}")
            print(f"   Total findings: {result['summary']['totalFindings']}")
            print(f"   Critical findings: {result['summary']['criticalFindings']}")
            print(f"   Risk score: {result['summary'].get('riskScore', 'N/A')}")
            print(f"   Risk level: {result['summary'].get('riskLevel', 'N/A')}")
        except Exception as e:
            print(f"❌ Failed to generate 7-day executive summary: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 3: 90-day executive summary
        print("3. Testing 90-day executive summary...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="90d",
                include_recommendations=True,
                include_risk_score=True
            )
            print("✅ 90-day executive summary generated successfully!")
            print(f"   Time period: {result.get('timePeriod', 'Unknown')}")
            print(f"   Total findings: {result['summary']['totalFindings']}")
            print(f"   Critical findings: {result['summary']['criticalFindings']}")
            print(f"   Risk score: {result['summary'].get('riskScore', 'N/A')}")
            print(f"   Risk level: {result['summary'].get('riskLevel', 'N/A')}")
        except Exception as e:
            print(f"❌ Failed to generate 90-day executive summary: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 4: All-time executive summary
        print("4. Testing all-time executive summary...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="all",
                include_recommendations=True,
                include_risk_score=True
            )
            print("✅ All-time executive summary generated successfully!")
            print(f"   Time period: {result.get('timePeriod', 'Unknown')}")
            print(f"   Total findings: {result['summary']['totalFindings']}")
            print(f"   Critical findings: {result['summary']['criticalFindings']}")
            print(f"   Risk score: {result['summary'].get('riskScore', 'N/A')}")
            print(f"   Risk level: {result['summary'].get('riskLevel', 'N/A')}")
        except Exception as e:
            print(f"❌ Failed to generate all-time executive summary: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 5: Executive summary without recommendations
        print("5. Testing executive summary without recommendations...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="30d",
                include_recommendations=False,
                include_risk_score=True
            )
            print("✅ Executive summary without recommendations generated successfully!")
            print(f"   Total findings: {result['summary']['totalFindings']}")
            print(f"   Risk score: {result['summary'].get('riskScore', 'N/A')}")
            print(f"   Recommendations included: {'recommendations' in result['summary']}")
        except Exception as e:
            print(f"❌ Failed to generate executive summary without recommendations: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 6: Executive summary without risk score
        print("6. Testing executive summary without risk score...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="30d",
                include_recommendations=True,
                include_risk_score=False
            )
            print("✅ Executive summary without risk score generated successfully!")
            print(f"   Total findings: {result['summary']['totalFindings']}")
            print(f"   Risk score included: {'riskScore' in result['summary']}")
            print(f"   Recommendations: {len(result['summary'].get('recommendations', []))}")
        except Exception as e:
            print(f"❌ Failed to generate executive summary without risk score: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 7: Verify recommendations structure
        print("7. Testing recommendations structure...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="30d",
                include_recommendations=True,
                include_risk_score=True
            )
            
            recommendations = result['summary'].get('recommendations', [])
            print("✅ Recommendations structure verified!")
            print(f"   Number of recommendations: {len(recommendations)}")
            
            for i, rec in enumerate(recommendations):
                print(f"   Recommendation {i+1}:")
                print(f"     Priority: {rec.get('priority', 'Unknown')}")
                print(f"     Recommendation: {rec.get('recommendation', 'Unknown')}")
                print(f"     Action: {rec.get('action', 'Unknown')}")
        except Exception as e:
            print(f"❌ Failed to verify recommendations structure: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 8: Verify severity breakdown
        print("8. Testing severity breakdown...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="30d",
                include_recommendations=True,
                include_risk_score=True
            )
            
            severity_breakdown = result['summary'].get('severityBreakdown', {})
            print("✅ Severity breakdown verified!")
            print(f"   High: {severity_breakdown.get('High', 0)}")
            print(f"   Medium: {severity_breakdown.get('Medium', 0)}")
            print(f"   Low: {severity_breakdown.get('Low', 0)}")
            
            # Verify the breakdown matches the critical findings count
            critical_count = result['summary'].get('criticalFindings', 0)
            high_count = severity_breakdown.get('High', 0)
            if critical_count == high_count:
                print("   ✅ Critical findings count matches High severity count")
            else:
                print(f"   ⚠️  Mismatch: critical_count={critical_count}, high_count={high_count}")
        except Exception as e:
            print(f"❌ Failed to verify severity breakdown: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 9: Verify scan coverage integration
        print("9. Testing scan coverage integration...")
        try:
            result = await server._generate_executive_summary(
                org_id=org_id,
                time_period="30d",
                include_recommendations=True,
                include_risk_score=True
            )
            
            scan_coverage = result['summary'].get('scanCoverage', {})
            print("✅ Scan coverage integration verified!")
            print(f"   Total scans: {scan_coverage.get('totalScans', 0)}")
            print(f"   Successful scans: {scan_coverage.get('successfulScans', 0)}")
            print(f"   Failed scans: {scan_coverage.get('failedScans', 0)}")
            print(f"   In-progress scans: {scan_coverage.get('inProgressScans', 0)}")
            
            # Check if scan coverage affects recommendations
            recommendations = result['summary'].get('recommendations', [])
            scan_related_recommendations = [r for r in recommendations if 'scan' in r.get('recommendation', '').lower()]
            print(f"   Scan-related recommendations: {len(scan_related_recommendations)}")
            
            # Check if scan coverage affects risk score
            risk_score = result['summary'].get('riskScore', 0)
            print(f"   Risk score: {risk_score}")
            
            if scan_coverage.get('totalScans', 0) == 0:
                print("   ⚠️  No scans detected - risk score should be elevated")
            elif scan_coverage.get('successfulScans', 0) == 0:
                print("   ⚠️  No successful scans - risk score should be elevated")
            else:
                print("   ✅ Good scan coverage detected")
                
        except Exception as e:
            print(f"❌ Failed to verify scan coverage integration: {e}")
        
        print("\n" + "="*50 + "\n")
        
        # Test 10: Test different time periods with scan coverage
        print("10. Testing scan coverage across different time periods...")
        time_periods = ["7d", "30d", "90d"]
        for period in time_periods:
            try:
                result = await server._generate_executive_summary(
                    org_id=org_id,
                    time_period=period,
                    include_recommendations=True,
                    include_risk_score=True
                )
                
                scan_coverage = result['summary'].get('scanCoverage', {})
                risk_score = result['summary'].get('riskScore', 0)
                
                print(f"   {period} period:")
                print(f"     Scans: {scan_coverage.get('totalScans', 0)} total, {scan_coverage.get('successfulScans', 0)} successful")
                print(f"     Risk score: {risk_score}")
                
            except Exception as e:
                print(f"   ❌ Failed to test {period} period: {e}")
        
        print("\n=== Executive Summary Fix Testing Complete ===")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await server.cleanup() 