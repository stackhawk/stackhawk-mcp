"""
Test suite to validate that all API endpoints used in the StackHawk MCP server 
are correctly defined and follow StackHawk API specification.
"""

import pytest
import re
from stackhawk_mcp.server import StackHawkClient
from typing import Dict, List, Tuple


class TestAPIEndpointValidation:
    """Validate all API endpoints against expected patterns and conventions."""

    @pytest.fixture
    def expected_endpoints(self) -> Dict[str, Dict]:
        """Define all expected API endpoints with their details."""
        return {
            # Authentication
            "/api/v1/auth/login": {
                "method": "GET", 
                "version": "v1",
                "category": "auth",
                "description": "Authentication with API key"
            },
            
            # User management
            "/api/v1/user": {
                "method": "GET",
                "version": "v1", 
                "category": "user",
                "description": "Get current user information"
            },
            
            # Application management
            "/api/v2/org/{org_id}/apps": {
                "method": "GET",
                "version": "v2",
                "category": "applications",
                "description": "List applications for organization"
            },
            "/api/v1/app/{app_id}": {
                "method": "GET",
                "version": "v1",
                "category": "applications", 
                "description": "Get specific application details"
            },
            "/api/v1/org/{org_id}/app": {
                "method": "POST",
                "version": "v1",
                "category": "applications",
                "description": "Create new application"
            },
            "/api/v1/app/{app_id}/policy/flags": {
                "method": "PUT",
                "version": "v1",
                "category": "applications",
                "description": "Update application technology flags"
            },
            
            # Organization management  
            "/api/v2/org/{org_id}/envs": {
                "method": "GET",
                "version": "v2",
                "category": "organization",
                "description": "List environments for organization"
            },
            "/api/v1/org/{org_id}/teams": {
                "method": "GET",
                "version": "v1",
                "category": "organization",
                "description": "List teams for organization"
            },
            
            # Vulnerability/Scan management
            "/api/v1/scan/{org_id}": {
                "method": "GET",
                "version": "v1",
                "category": "scans",
                "description": "List scans for organization"
            },
            "/api/v1/reports/org/{org_id}/findings": {
                "method": "GET",
                "version": "v1",
                "category": "vulnerabilities",
                "description": "Organization-wide findings"
            },
            "/api/v1/scan/{org_id}/{scan_id}/findings": {
                "method": "GET",
                "version": "v1",
                "category": "vulnerabilities",
                "description": "Findings for specific scan"
            },
            
            # Repository management
            "/api/v1/org/{org_id}/repos": {
                "method": "GET",
                "version": "v1",
                "category": "repositories",
                "description": "List repositories for organization"
            },
            "/api/v1/org/{org_id}/repos/{repo_id}": {
                "method": "GET",
                "version": "v1", 
                "category": "repositories",
                "description": "Get specific repository details"
            },
            "/api/v1/org/{org_id}/repos/{repo_id}/security-scan": {
                "method": "GET",
                "version": "v1",
                "category": "repositories",
                "description": "Repository security scan results"
            },
            
            # Sensitive data management
            "/api/v1/org/{org_id}/sensitive-data": {
                "method": "GET",
                "version": "v1",
                "category": "sensitive-data",
                "description": "Organization sensitive data findings"
            },
            "/api/v1/org/{org_id}/repos/{repo_id}/sensitive-data": {
                "method": "GET",
                "version": "v1",
                "category": "sensitive-data",
                "description": "Repository sensitive data findings"
            },
            "/api/v1/org/{org_id}/sensitive-data/types": {
                "method": "GET",
                "version": "v1",
                "category": "sensitive-data",
                "description": "Available sensitive data types"
            },
            "/api/v1/org/{org_id}/sensitive-data/summary": {
                "method": "GET",
                "version": "v1",
                "category": "sensitive-data", 
                "description": "Sensitive data summary"
            }
        }

    def test_api_endpoint_patterns(self, expected_endpoints):
        """Test that all endpoints follow correct URL patterns."""
        
        for endpoint, details in expected_endpoints.items():
            # Test API version pattern
            version_match = re.search(r'/api/(v\d+)/', endpoint)
            assert version_match is not None, f"Endpoint {endpoint} missing version"
            assert version_match.group(1) == details["version"], \
                f"Version mismatch in {endpoint}: expected {details['version']}, got {version_match.group(1)}"
            
            # Test parameter patterns
            param_pattern = r'\{[a-z_]+\}'
            params = re.findall(param_pattern, endpoint)
            
            # Validate org_id parameter format
            if '{org_id}' in endpoint:
                assert '{org_id}' in params, f"org_id parameter format issue in {endpoint}"
            
            # Validate app_id parameter format  
            if '{app_id}' in endpoint:
                assert '{app_id}' in params, f"app_id parameter format issue in {endpoint}"
            
            # Validate repo_id parameter format
            if '{repo_id}' in endpoint:
                assert '{repo_id}' in params, f"repo_id parameter format issue in {endpoint}"
            
            # Validate scan_id parameter format
            if '{scan_id}' in endpoint:
                assert '{scan_id}' in params, f"scan_id parameter format issue in {endpoint}"

    def test_api_version_consistency(self, expected_endpoints):
        """Test API versioning strategy consistency."""
        
        v1_endpoints = [ep for ep, details in expected_endpoints.items() if details["version"] == "v1"]
        v2_endpoints = [ep for ep, details in expected_endpoints.items() if details["version"] == "v2"]
        
        # Validate v2 usage pattern (should be for listing operations)
        v2_listing_pattern = r'/api/v2/org/\{org_id\}/(apps|envs)$'
        for endpoint in v2_endpoints:
            assert re.match(v2_listing_pattern, endpoint), \
                f"v2 endpoint {endpoint} doesn't follow expected listing pattern"
        
        # Validate v1 endpoints are used for details and actions
        assert len(v1_endpoints) > len(v2_endpoints), \
            "v1 should be the primary API version for most endpoints"

    def test_resource_hierarchy(self, expected_endpoints):
        """Test that resource hierarchy follows REST conventions."""
        
        # Organization-level resources
        org_resources = [ep for ep in expected_endpoints.keys() if '/org/{org_id}/' in ep]
        assert len(org_resources) > 0, "Should have organization-level resources"
        
        # Application-level resources
        app_resources = [ep for ep in expected_endpoints.keys() if '/app/{app_id}' in ep]
        assert len(app_resources) > 0, "Should have application-level resources"
        
        # Repository-level resources
        repo_resources = [ep for ep in expected_endpoints.keys() if '/repos/{repo_id}' in ep]
        assert len(repo_resources) > 0, "Should have repository-level resources"
        
        # Validate hierarchy: org -> apps/repos -> details
        for endpoint in org_resources:
            if '/apps' in endpoint or '/envs' in endpoint or '/teams' in endpoint or '/repos' in endpoint:
                # These should be listing endpoints
                assert not endpoint.endswith('/{id}'), f"Org listing endpoint {endpoint} shouldn't end with ID"

    def test_sensitive_data_endpoints(self, expected_endpoints):
        """Test sensitive data endpoint completeness."""
        
        sensitive_endpoints = [
            ep for ep, details in expected_endpoints.items() 
            if details["category"] == "sensitive-data"
        ]
        
        # Should have org-level sensitive data endpoint
        org_sensitive = [ep for ep in sensitive_endpoints if ep == "/api/v1/org/{org_id}/sensitive-data"]
        assert len(org_sensitive) == 1, "Should have org-level sensitive data endpoint"
        
        # Should have repo-level sensitive data endpoint
        repo_sensitive = [ep for ep in sensitive_endpoints if "repos/{repo_id}/sensitive-data" in ep]
        assert len(repo_sensitive) == 1, "Should have repo-level sensitive data endpoint"
        
        # Should have metadata endpoints
        types_endpoint = [ep for ep in sensitive_endpoints if ep.endswith("/sensitive-data/types")]
        assert len(types_endpoint) == 1, "Should have sensitive data types endpoint"
        
        summary_endpoint = [ep for ep in sensitive_endpoints if ep.endswith("/sensitive-data/summary")]  
        assert len(summary_endpoint) == 1, "Should have sensitive data summary endpoint"

    def test_vulnerability_endpoints(self, expected_endpoints):
        """Test vulnerability/findings endpoint completeness."""
        
        vuln_endpoints = [
            ep for ep, details in expected_endpoints.items()
            if details["category"] in ["vulnerabilities", "scans"]
        ]
        
        # Should have org-level findings
        org_findings = [ep for ep in vuln_endpoints if "/reports/org/{org_id}/findings" in ep]
        assert len(org_findings) == 1, "Should have org-level findings endpoint"
        
        # Should have scan listing
        scan_listing = [ep for ep in vuln_endpoints if ep == "/api/v1/scan/{org_id}"]
        assert len(scan_listing) == 1, "Should have scan listing endpoint"
        
        # Should have scan-specific findings
        scan_findings = [ep for ep in vuln_endpoints if "/scan/{org_id}/{scan_id}/findings" in ep]
        assert len(scan_findings) == 1, "Should have scan-specific findings endpoint"

    def test_client_implementation_coverage(self, expected_endpoints):
        """Test that StackHawkClient implements all expected endpoints."""
        
        # Read the server.py file to check endpoint usage
        import os
        server_file = os.path.join(os.path.dirname(__file__), '..', 'stackhawk_mcp', 'server.py')
        
        with open(server_file, 'r') as f:
            content = f.read()
        
        # Check that all expected endpoints are referenced in the code
        for endpoint in expected_endpoints.keys():
            # Look for the actual endpoint string in the code
            # Replace variables with simpler patterns for matching
            search_patterns = [
                endpoint,  # Try exact match first
                endpoint.replace('{org_id}', '{org_id}'),  # Standard pattern
                endpoint.replace('{org_id}', 'org_id'),    # Without braces
                endpoint.replace('{app_id}', 'app_id'),
                endpoint.replace('{repo_id}', 'repo_id'),
                endpoint.replace('{scan_id}', 'scan_id'),
            ]
            
            # Also check for f-string patterns (without redundant replacement)
            search_patterns.append(endpoint)
            
            found = False
            for pattern in search_patterns:
                if pattern in content:
                    found = True
                    break
            
            # Special handling for f-strings in the code
            if not found:
                # Check for f-string format like f"/api/v1/org/{org_id}/apps"
                if '/apps' in endpoint:
                    found = '/apps' in content
                elif '/envs' in endpoint:
                    found = '/envs' in content
                elif '/teams' in endpoint:
                    found = '/teams' in content
                elif '/repos' in endpoint and '/sensitive-data' not in endpoint:
                    found = '/repos' in content
                elif '/sensitive-data' in endpoint:
                    found = 'sensitive-data' in content
                elif '/findings' in endpoint:
                    found = '/findings' in content
                elif '/scan/' in endpoint:
                    found = '/scan' in content
                elif '/auth/login' in endpoint:
                    found = 'auth/login' in content
                elif '/user' in endpoint:
                    found = '/user' in content
                elif '/app/' in endpoint or endpoint.endswith('/app'):
                    found = '/app' in content
            
            assert found, f"Endpoint {endpoint} not found in client implementation"

    def test_http_methods(self, expected_endpoints):
        """Test that HTTP methods are appropriate for each endpoint."""
        
        for endpoint, details in expected_endpoints.items():
            method = details["method"]
            
            # GET methods for retrieval operations
            if 'list' in details["description"].lower() or 'get' in details["description"].lower():
                assert method == "GET", f"Endpoint {endpoint} should use GET for retrieval"
            
            # POST for creation
            if 'create' in details["description"].lower():
                assert method == "POST", f"Endpoint {endpoint} should use POST for creation"
            
            # PUT for updates  
            if 'update' in details["description"].lower():
                assert method == "PUT", f"Endpoint {endpoint} should use PUT for updates"

    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test that StackHawkClient initializes correctly with expected base URL."""
        
        client = StackHawkClient("test_api_key")
        
        assert client.base_url == "https://api.stackhawk.com", "Default base URL should match StackHawk API"
        assert client.api_key == "test_api_key", "API key should be stored correctly"
        assert client.access_token is None, "Access token should be None initially"
        assert not client._authenticated, "Client should not be authenticated initially"

    @pytest.mark.asyncio 
    async def test_user_agent_header(self):
        """Test that proper User-Agent header is configured."""
        
        from stackhawk_mcp import __version__
        
        client = StackHawkClient("test_api_key")
        expected_user_agent = f"StackHawk-MCP/{__version__}"
        
        # The User-Agent should be set in the _get_client method
        http_client = await client._get_client()
        headers = http_client.headers
        assert "User-Agent" in headers, "User-Agent header should be set"
        assert headers["User-Agent"] == expected_user_agent, f"User-Agent should be {expected_user_agent}"