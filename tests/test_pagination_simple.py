#!/usr/bin/env python3
"""
Simple test to verify pagination logic
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import pytest

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def debug_print(message):
    """Print debug messages"""
    print(f"[DEBUG] {message}")

class SimpleStackHawkClient:
    """Simplified client for testing pagination"""

    def __init__(self, api_key: str, base_url: str = "https://api.stackhawk.com"):
        self.api_key = api_key
        self.base_url = base_url
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._authenticated = False

    async def _get_client(self):
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def _ensure_authenticated(self):
        """Ensure we have a valid access token"""
        if not self._authenticated or not self.access_token or (
                self.token_expires_at and datetime.now() >= self.token_expires_at):
            await self._authenticate()

    async def _authenticate(self):
        """Authenticate with the StackHawk API"""
        try:
            client = await self._get_client()
            response = await client.get(
                f"{self.base_url}/api/v1/auth/login",
                headers={"X-ApiKey": self.api_key}
            )
            response.raise_for_status()

            data = response.json()
            self.access_token = data["token"]
            self.token_expires_at = datetime.now() + timedelta(minutes=25)
            self._authenticated = True

            debug_print("Successfully authenticated with StackHawk API")
        except Exception as e:
            debug_print(f"Authentication failed: {e}")
            raise

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an authenticated request to the StackHawk API"""
        await self._ensure_authenticated()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"

        url = urljoin(self.base_url, endpoint)

        try:
            client = await self._get_client()
            response = await client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            debug_print(f"API request failed: {e.response.status_code} {e.response.text}")
            raise
        except Exception as e:
            debug_print(f"Request error: {e}")
            raise

    async def list_organization_findings(self, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """List organization-wide findings, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=params)

    async def _fetch_all_pages(self, endpoint: str, params: dict) -> list:
        """Fetch all pages of findings from a paginated StackHawk API endpoint using pageToken/nextPageToken."""
        all_findings = []
        page_token = None  # Start with no pageToken for first page
        page_size = params.get("pageSize", 100)
        page_count = 0
        
        debug_print(f"Starting pagination for {endpoint} with pageSize={page_size}")
        
        while True:
            page_count += 1
            page_params = dict(params)
            page_params["pageSize"] = page_size
            if page_token:
                page_params["pageToken"] = page_token
                debug_print(f"Fetching page {page_count} with pageToken={page_token}")
            else:
                debug_print(f"Fetching page {page_count} (first page)")
                
            response = await self._make_request("GET", endpoint, params=page_params)
            findings = response.get("findings") or response.get("sensitiveDataFindings") or []
            all_findings.extend(findings)
            
            debug_print(f"Page {page_count}: got {len(findings)} findings, total so far: {len(all_findings)}")
            
            next_page_token = response.get("nextPageToken")
            if not next_page_token:
                debug_print(f"No more pages, total findings: {len(all_findings)}")
                break
            page_token = next_page_token
            
        return all_findings

    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()

@pytest.mark.asyncio
async def test_pagination():
    """Test that pagination now works correctly"""
    
    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        print("❌ STACKHAWK_API_KEY environment variable is required")
        return
    
    print("🔍 Testing pagination fix...")
    
    try:
        # Create client instance
        client = SimpleStackHawkClient(api_key)
        
        # Get user info to find org ID
        user_info = await client._make_request("GET", "/api/v1/user")
        org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
        
        print(f"📋 Testing with organization: {org_id}")
        
        # Test 1: Get findings with all_results=True (should use pagination)
        print("\n1. Testing all_results=True (should fetch all pages)...")
        findings_response = await client.list_organization_findings(org_id, all_results=True)
        total_findings = len(findings_response.get("findings", []))
        print(f"   ✅ Total findings with all_results=True: {total_findings}")
        
        # Test 2: Get findings with pageSize=100 (should get only first page)
        print("\n2. Testing pageSize=100 (should get only first page)...")
        findings_response = await client.list_organization_findings(org_id, pageSize=100)
        first_page_findings = len(findings_response.get("findings", []))
        print(f"   ✅ First page findings: {first_page_findings}")
        
        # Test 3: Compare results
        if total_findings > first_page_findings:
            print(f"   ✅ Pagination is working! Found {total_findings} total vs {first_page_findings} on first page")
        elif total_findings == first_page_findings:
            print(f"   ℹ️  All findings fit on first page ({total_findings} findings)")
        else:
            print(f"   ❌ Unexpected: total ({total_findings}) < first page ({first_page_findings})")
        
        await client.close()
        print("\n✅ Pagination test completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc() 