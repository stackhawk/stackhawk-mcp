#!/usr/bin/env python3
"""
StackHawk MCP Server - 

This MCP server provides security monitoring and analytics capabilities by integrating
with the StackHawk API. It offers tools for both developer integration and security
team analytics across applications and vulnerabilities.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urljoin
import glob
import os
import re

import httpx
import yaml
from jsonschema import validate, ValidationError
from mcp.server import Server
from mcp.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)
import mcp.server.stdio
import mcp.types as types

# Configure logging to stderr so Claude Desktop can see it
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("stackhawk-mcp")

STACKHAWK_MCP_VERSION = "1.0.0"


def debug_print(message):
    """Print debug messages to stderr for Claude Desktop"""
    print(f"[DEBUG] {message}", file=sys.stderr, flush=True)


class StackHawkClient:
    """Client for interacting with the StackHawk API"""

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
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={
                    "User-Agent": f"StackHawk-MCP/{STACKHAWK_MCP_VERSION}"
                }
            )
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
            # JWT tokens typically expire in 30 minutes, refresh after 25 minutes
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

    async def get_user_info(self) -> Dict[str, Any]:
        """Get current user information"""
        return await self._make_request("GET", "/api/v1/user")

    async def list_applications(self, org_id: str, **params) -> Dict[str, Any]:
        """List applications for an organization"""
        return await self._make_request("GET", f"/api/v2/org/{org_id}/apps", params=params)

    async def list_environments(self, org_id: str, **params) -> Dict[str, Any]:
        """List environments for an organization"""
        return await self._make_request("GET", f"/api/v2/org/{org_id}/envs", params=params)

    async def get_application(self, app_id: str) -> Dict[str, Any]:
        """Get details for a specific application"""
        return await self._make_request("GET", f"/api/v1/app/{app_id}")

    async def list_scans(self, org_id: str, **params) -> Dict[str, Any]:
        """List scans for an organization"""
        return await self._make_request("GET", f"/api/v1/scan/{org_id}", params=params)

    async def list_organization_findings(self, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """List organization-wide findings, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=params)

    async def get_organization_findings_detailed(self, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get detailed organization findings with comprehensive filtering options and optional pagination."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"findings": findings}
        else:
            default_params = {"pageSize": 100}
            default_params.update(params)
            return await self._make_request("GET", endpoint, params=default_params)

    async def get_application_findings(self, app_id: str, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get findings for a specific application, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        default_params = {
            "pageSize": 100,
            "appIds": app_id
        }
        default_params.update(params)
        if all_results:
            findings = await self._fetch_all_pages(endpoint, default_params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=default_params)

    async def get_application_findings_summary(self, app_id: str, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get summary of findings for a specific application, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        default_params = {
            "pageSize": 50,
            "appIds": app_id
        }
        default_params.update(params)
        if all_results:
            findings = await self._fetch_all_pages(endpoint, default_params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=default_params)

    async def list_teams(self, org_id: str, **params) -> Dict[str, Any]:
        """List teams for an organization"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/teams", params=params)

    async def list_repositories(self, org_id: str, **params) -> Dict[str, Any]:
        """List repositories for an organization"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/repos", params=params)

    async def get_repository_details(self, org_id: str, repo_id: str, **params) -> Dict[str, Any]:
        """Get detailed information about a specific repository"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/repos/{repo_id}", params=params)

    async def get_repository_security_scan(self, org_id: str, repo_id: str, **params) -> Dict[str, Any]:
        """Get security scan results for a specific repository"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/repos/{repo_id}/security-scan", params=params)

    async def get_yaml_schema(self) -> Dict[str, Any]:
        """Get the StackHawk YAML configuration schema from the official URL"""
        # Use the official StackHawk schema URL
        schema_url = "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json"
        
        try:
            client = await self._get_client()
            response = await client.get(schema_url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            debug_print(f"Failed to fetch schema from {schema_url}: {e}")
            raise

    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()

    async def _fetch_all_pages(self, endpoint: str, params: dict) -> list:
        """Fetch all pages of findings from a paginated StackHawk API endpoint using integer pageToken."""
        all_findings = []
        page_token = 0
        page_size = params.get("pageSize", 1000)
        page_count = 0

        debug_print(f"Starting pagination for {endpoint} with pageSize={page_size}")

        while True:
            page_count += 1
            page_params = dict(params)
            page_params["pageSize"] = page_size
            page_params["pageToken"] = page_token
            debug_print(f"Fetching page {page_count} with pageToken={page_token}")

            response = await self._make_request("GET", endpoint, params=page_params)
            findings = response.get("findings") or response.get("sensitiveDataFindings") or []
            all_findings.extend(findings)

            debug_print(f"Page {page_count}: got {len(findings)} findings, total so far: {len(all_findings)}")

            if len(findings) < page_size:
                debug_print(f"No more pages, total findings: {len(all_findings)}")
                break
            page_token += 1

        return all_findings

    async def list_sensitive_data_findings(self, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """List sensitive data findings for an organization"""
        endpoint = f"/api/v1/org/{org_id}/sensitive-data"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"sensitiveDataFindings": findings}
        else:
            return await self._make_request("GET", endpoint, params=params)

    async def get_sensitive_data_findings_detailed(self, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get detailed sensitive data findings with comprehensive filtering options and optional pagination."""
        endpoint = f"/api/v1/org/{org_id}/sensitive-data"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"sensitiveDataFindings": findings}
        else:
            default_params = {"pageSize": 100}
            default_params.update(params)
            return await self._make_request("GET", endpoint, params=default_params)

    async def get_application_sensitive_data(self, app_id: str, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get sensitive data findings for a specific application"""
        endpoint = f"/api/v1/org/{org_id}/sensitive-data"
        default_params = {
            "pageSize": 100,
            "appIds": app_id
        }
        default_params.update(params)
        if all_results:
            findings = await self._fetch_all_pages(endpoint, default_params)
            return {"sensitiveDataFindings": findings}
        else:
            return await self._make_request("GET", endpoint, params=default_params)

    async def get_repository_sensitive_data(self, org_id: str, repo_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get sensitive data findings for a specific repository"""
        endpoint = f"/api/v1/org/{org_id}/repos/{repo_id}/sensitive-data"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"sensitiveDataFindings": findings}
        else:
            return await self._make_request("GET", endpoint, params=params)

    async def get_sensitive_data_types(self, org_id: str, **params) -> Dict[str, Any]:
        """Get available sensitive data types and categories"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/sensitive-data/types", params=params)

    async def get_sensitive_data_summary(self, org_id: str, **params) -> Dict[str, Any]:
        """Get summary of sensitive data findings across the organization"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/sensitive-data/summary", params=params)

    async def _get_project_open_stackhawk_issues(self, config_path: str = None) -> dict:
        """Discover StackHawk config, extract applicationId, and summarize open issues for the app."""
        import os
        import yaml
        
        # 1. Discover config file if not provided
        if not config_path:
            candidates = glob.glob("stackhawk.y*ml") + glob.glob("stackhawk*.y*ml")
            if not candidates:
                return {"error": "No StackHawk config file found in current directory."}
            config_path = candidates[0]
        if not os.path.exists(config_path):
            return {"error": f"Config file not found: {config_path}"}
        
        # 2. Parse config for applicationId and failureThreshold
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            app_id = config.get("app", {}).get("applicationId")
            if not app_id:
                return {"error": f"No applicationId found in {config_path}"}
            # Always look for failureThreshold in hawk section
            failure_threshold = None
            if "hawk" in config and "failureThreshold" in config["hawk"]:
                failure_threshold = config["hawk"]["failureThreshold"]
            # Normalize threshold (capitalize)
            if failure_threshold:
                failure_threshold = failure_threshold.capitalize()
        except Exception as e:
            return {"error": f"Failed to parse config: {e}"}
        
        # 3. Fetch open vulnerabilities for this app
        try:
            result = await self._get_application_vulnerabilities(app_id, severity_filter="All", max_results=1000)
            findings = result.get("findings", [])
            # Only include findings that are High, Medium, or >= failureThreshold
            allowed_severities = ["High", "Medium"]
            if failure_threshold and failure_threshold not in allowed_severities:
                allowed_severities.append(failure_threshold)
            filtered_findings = [f for f in findings if f.get("findingRisk") in allowed_severities]
            return {
                "config_path": config_path,
                "applicationId": app_id,
                "failureThreshold": failure_threshold or "High/Medium",
                "open_issues_summary": self._calculate_severity_breakdown(filtered_findings),
                "totalOpenIssues": len(filtered_findings),
                "openIssues": filtered_findings,
                "note": "Returned issues are High, Medium, or at/above the configured failureThreshold (if set in hawk section) so chat can help fix them."
            }
        except Exception as e:
            return {"error": f"Failed to fetch vulnerabilities: {e}"}

    async def create_application(self, org_id: str, app_name: str, language: str = None, frameworks: list = None, tech_flags: dict = None) -> dict:
        """Create a new StackHawk application in the given org with tech flags."""
        payload = {
            "name": app_name,
        }
        if language:
            payload["language"] = language
        if frameworks:
            payload["frameworks"] = frameworks
        if tech_flags:
            payload["techFlags"] = tech_flags
        return await self._make_request("POST", f"/api/v2/org/{org_id}/apps", json=payload)


class StackHawkMCPServer:
    """StackHawk MCP Server implementation"""

    def __init__(self, api_key: str):
        debug_print("Initializing StackHawkMCPServer...")
        self.client = StackHawkClient(api_key)
        self.server = Server("stackhawk-mcp")
        self._schema_cache: Optional[Dict[str, Any]] = None
        self._schema_cache_time: Optional[datetime] = None
        self._schema_cache_ttl = timedelta(hours=24)  # Cache schema for 24 hours
        self._setup_handlers()
        debug_print("StackHawkMCPServer initialized")

    def _setup_handlers(self):
        """Set up MCP server handlers"""
        debug_print("Setting up MCP handlers...")

        @self.server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            """List available StackHawk resources"""
            debug_print("Resources requested")
            try:
                return [
                    Resource(
                        uri="stackhawk://auth/user",
                        name="Current User",
                        description="Information about the authenticated user and their organizations",
                        mimeType="application/json"
                    ),
                    Resource(
                        uri="stackhawk://applications",
                        name="Applications Overview",
                        description="Overview of all applications across organizations",
                        mimeType="application/json"
                    ),
                    Resource(
                        uri="stackhawk://vulnerabilities/summary",
                        name="Vulnerability Summary",
                        description="High-level vulnerability metrics and trends",
                        mimeType="application/json"
                    )
                ]
            except Exception as e:
                debug_print(f"Error in list_resources: {e}")
                raise

        @self.server.read_resource()
        async def handle_read_resource(uri: types.AnyUrl) -> str:
            """Read a specific StackHawk resource"""
            debug_print(f"Resource read requested: {uri}")
            try:
                uri_str = str(uri)

                if uri_str == "stackhawk://auth/user":
                    user_info = await self.client.get_user_info()
                    return json.dumps(user_info, indent=2)

                elif uri_str == "stackhawk://applications":
                    # Get applications across all user's organizations
                    user_info = await self.client.get_user_info()
                    all_apps = []

                    for org in user_info["user"]["external"]["organizations"]:
                        org_id = org["organization"]["id"]
                        try:
                            apps_response = await self.client.list_applications(org_id, pageSize=100)
                            all_apps.extend(apps_response.get("applications", []))
                        except Exception as e:
                            debug_print(f"Error getting apps for org {org_id}: {e}")

                    return json.dumps({
                        "totalApplications": len(all_apps),
                        "applications": all_apps
                    }, indent=2)

                elif uri_str == "stackhawk://vulnerabilities/summary":
                    return await self._generate_vulnerability_summary()

                else:
                    raise ValueError(f"Unknown resource: {uri}")

            except Exception as e:
                debug_print(f"Error in read_resource: {e}")
                raise

        @self.server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            """List available StackHawk tools"""
            debug_print("Tools requested")
            try:
                tools = [
                    Tool(
                        name="get_organization_info",
                        description="Get information about a StackHawk organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="list_applications",
                        description="List applications in a StackHawk organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "page_size": {"type": "integer", "description": "Page size (optional)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="search_vulnerabilities",
                        description="Search for vulnerabilities in a StackHawk organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "severity_filter": {"type": "string", "description": "Filter by severity (Critical, High, Medium, Low)"},
                                "time_range": {"type": "string", "description": "Time range for search (e.g., '30d', '7d')"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="generate_security_dashboard",
                        description="Generate a security dashboard for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="create_stackhawk_config",
                        description="Create a StackHawk configuration file",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "application_id": {"type": "string", "description": "StackHawk Application ID"},
                                "app_name": {"type": "string", "description": "Application name"},
                                "host": {"type": "string", "description": "Host for the app"},
                                "port": {"type": "integer", "description": "Port for the app"}
                            },
                            "required": ["application_id", "app_name", "host", "port"]
                        }
                    ),
                    Tool(
                        name="validate_stackhawk_config",
                        description="Validate a StackHawk YAML configuration file",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "yaml_content": {"type": "string", "description": "YAML content to validate"}
                            },
                            "required": ["yaml_content"]
                        }
                    ),
                    Tool(
                        name="get_stackhawk_schema",
                        description="Get the StackHawk YAML schema",
                        inputSchema={"type": "object", "properties": {}}
                    ),
                    Tool(
                        name="refresh_schema_cache",
                        description="Refresh the StackHawk YAML schema cache",
                        inputSchema={"type": "object", "properties": {}}
                    ),
                    Tool(
                        name="validate_field_exists",
                        description="Validate that a field path exists in the StackHawk schema",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "field_path": {"type": "string", "description": "Field path to validate"}
                            },
                            "required": ["field_path"]
                        }
                    ),
                    Tool(
                        name="get_schema_fields",
                        description="Get all available fields and their types from the StackHawk schema",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "section": {"type": "string", "description": "Section to filter (optional)"}
                            }
                        }
                    ),
                    Tool(
                        name="suggest_configuration",
                        description="Suggest a StackHawk configuration for a use case and environment",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "use_case": {"type": "string", "description": "Use case (e.g., API, webapp)"},
                                "environment": {"type": "string", "description": "Environment (default: dev)"},
                                "include_advanced": {"type": "boolean", "description": "Include advanced options (default: false)"}
                            },
                            "required": ["use_case"]
                        }
                    ),
                    Tool(
                        name="get_vulnerability_report",
                        description="Get a vulnerability report for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "severity_filter": {"type": "string", "description": "Severity filter"},
                                "time_range": {"type": "string", "description": "Time range"},
                                "include_remediation": {"type": "boolean", "description": "Include remediation info"},
                                "group_by": {"type": "string", "description": "Group by field"}
                            },
                            "required": ["org_id", "severity_filter", "time_range", "include_remediation", "group_by"]
                        }
                    ),
                    Tool(
                        name="analyze_vulnerability_trends",
                        description="Analyze vulnerability trends for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "analysis_period": {"type": "string", "description": "Analysis period"},
                                "include_applications": {"type": "boolean", "description": "Include applications"},
                                "include_severity_breakdown": {"type": "boolean", "description": "Include severity breakdown"}
                            },
                            "required": ["org_id", "analysis_period"]
                        }
                    ),
                    Tool(
                        name="get_critical_findings",
                        description="Get critical findings for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "severity_levels": {"type": "array", "items": {"type": "string"}, "description": "Severity levels"},
                                "include_remediation": {"type": "boolean", "description": "Include remediation info"},
                                "max_results": {"type": "integer", "description": "Max results"}
                            },
                            "required": ["org_id", "severity_levels", "include_remediation", "max_results"]
                        }
                    ),
                    Tool(
                        name="generate_executive_summary",
                        description="Generate an executive summary for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "time_period": {"type": "string", "description": "Time period (default: 30d)"},
                                "include_recommendations": {"type": "boolean", "description": "Include recommendations (default: true)"},
                                "include_risk_score": {"type": "boolean", "description": "Include risk score (default: true)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="analyze_threat_surface",
                        description="Analyze the threat surface for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "include_repositories": {"type": "boolean", "description": "Include repositories (default: true)"},
                                "include_applications": {"type": "boolean", "description": "Include applications (default: true)"},
                                "include_vulnerabilities": {"type": "boolean", "description": "Include vulnerabilities (default: true)"},
                                "risk_assessment": {"type": "boolean", "description": "Include risk assessment (default: true)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="get_repository_security_overview",
                        description="Get a security overview for repositories in an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "include_scan_results": {"type": "boolean", "description": "Include scan results (default: true)"},
                                "include_vulnerabilities": {"type": "boolean", "description": "Include vulnerabilities (default: true)"},
                                "filter_by_status": {"type": "string", "description": "Filter by status (default: all)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="identify_high_risk_repositories",
                        description="Identify high-risk repositories in an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "risk_threshold": {"type": "string", "description": "Risk threshold (default: high)"},
                                "include_remediation": {"type": "boolean", "description": "Include remediation info (default: true)"},
                                "max_results": {"type": "integer", "description": "Max results (default: 20)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="generate_code_security_report",
                        description="Generate a code security report for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "report_type": {"type": "string", "description": "Report type (default: summary)"},
                                "include_trends": {"type": "boolean", "description": "Include trends (default: true)"},
                                "include_comparison": {"type": "boolean", "description": "Include comparison (default: false)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="map_attack_surface",
                        description="Map the attack surface for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "include_internal": {"type": "boolean", "description": "Include internal (default: true)"},
                                "include_external": {"type": "boolean", "description": "Include external (default: true)"},
                                "include_third_party": {"type": "boolean", "description": "Include third party (default: true)"},
                                "risk_visualization": {"type": "boolean", "description": "Include risk visualization (default: true)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="get_application_vulnerabilities",
                        description="Get vulnerabilities for a specific application",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "app_id": {"type": "string", "description": "Application ID"},
                                "severity_filter": {"type": "string", "description": "Severity filter (default: All)"},
                                "include_remediation": {"type": "boolean", "description": "Include remediation info (default: true)"},
                                "max_results": {"type": "integer", "description": "Max results (default: 100)"}
                            },
                            "required": ["app_id"]
                        }
                    ),
                    Tool(
                        name="get_application_security_summary",
                        description="Get a security summary for a specific application",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "app_id": {"type": "string", "description": "Application ID"},
                                "include_trends": {"type": "boolean", "description": "Include trends (default: false)"},
                                "include_recommendations": {"type": "boolean", "description": "Include recommendations (default: true)"}
                            },
                            "required": ["app_id"]
                        }
                    ),
                    Tool(
                        name="compare_application_security",
                        description="Compare security across multiple applications",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "app_ids": {"type": "array", "items": {"type": "string"}, "description": "List of application IDs"},
                                "comparison_metrics": {"type": "array", "items": {"type": "string"}, "description": "Comparison metrics (optional)"}
                            },
                            "required": ["org_id", "app_ids"]
                        }
                    ),
                    Tool(
                        name="get_sensitive_data_report",
                        description="Get a sensitive data report for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "data_type_filter": {"type": "string", "description": "Data type filter (default: All)"},
                                "time_range": {"type": "string", "description": "Time range (default: 30d)"},
                                "include_details": {"type": "boolean", "description": "Include details (default: true)"},
                                "group_by": {"type": "string", "description": "Group by field (default: data_type)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="analyze_sensitive_data_trends",
                        description="Analyze sensitive data trends for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "analysis_period": {"type": "string", "description": "Analysis period (default: 90d)"},
                                "include_applications": {"type": "boolean", "description": "Include applications (default: true)"},
                                "include_repositories": {"type": "boolean", "description": "Include repositories (default: true)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="get_critical_sensitive_data",
                        description="Get critical sensitive data findings for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "data_types": {"type": "array", "items": {"type": "string"}, "description": "Data types (optional)"},
                                "include_remediation": {"type": "boolean", "description": "Include remediation info (default: true)"},
                                "max_results": {"type": "integer", "description": "Max results (default: 50)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="generate_sensitive_data_summary",
                        description="Generate a sensitive data summary for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "time_period": {"type": "string", "description": "Time period (default: 30d)"},
                                "include_recommendations": {"type": "boolean", "description": "Include recommendations (default: true)"},
                                "include_risk_assessment": {"type": "boolean", "description": "Include risk assessment (default: true)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="get_application_sensitive_data",
                        description="Get sensitive data findings for a specific application",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "app_id": {"type": "string", "description": "Application ID"},
                                "data_type_filter": {"type": "string", "description": "Data type filter (default: All)"},
                                "include_details": {"type": "boolean", "description": "Include details (default: true)"},
                                "max_results": {"type": "integer", "description": "Max results (default: 100)"}
                            },
                            "required": ["app_id"]
                        }
                    ),
                    Tool(
                        name="get_repository_sensitive_data",
                        description="Get sensitive data findings for a specific repository",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "repo_id": {"type": "string", "description": "Repository ID"},
                                "data_type_filter": {"type": "string", "description": "Data type filter (default: All)"},
                                "include_details": {"type": "boolean", "description": "Include details (default: true)"},
                                "max_results": {"type": "integer", "description": "Max results (default: 100)"}
                            },
                            "required": ["org_id", "repo_id"]
                        }
                    ),
                    Tool(
                        name="get_sensitive_data_types",
                        description="Get available sensitive data types for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="map_sensitive_data_surface",
                        description="Map sensitive data exposure for an organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "include_applications": {"type": "boolean", "description": "Include applications (default: true)"},
                                "include_repositories": {"type": "boolean", "description": "Include repositories (default: true)"},
                                "risk_visualization": {"type": "boolean", "description": "Include risk visualization (default: true)"}
                            },
                            "required": ["org_id"]
                        }
                    ),
                    Tool(
                        name="get_project_open_stackhawk_issues",
                        description="Discover StackHawk config in project, extract applicationId, and summarize open issues for the app.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "config_path": {"type": "string", "description": "Path to StackHawk config file (optional)"}
                            }
                        }
                    ),
                    Tool(
                        name="setup_stackhawk_for_project",
                        description="Set up StackHawk for a new project",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID (optional)"},
                                "app_name": {"type": "string", "description": "Application name (optional)"}
                            }
                        }
                    ),
                    Tool(
                        name="get_stackhawk_scan_instructions",
                        description="Get instructions for running StackHawk scans",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "config_path": {"type": "string", "description": "Path to StackHawk config file (default: stackhawk.yml)"}
                            }
                        }
                    )
                ]
                return tools
            except Exception as e:
                debug_print(f"Error in list_tools: {e}")
                raise

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
            """Handle tool calls"""
            debug_print(f"Tool called: {name} with arguments: {arguments}")
            try:
                if name == "get_organization_info":
                    result = await self._get_organization_info(**arguments)
                elif name == "list_applications":
                    result = await self._list_applications(**arguments)
                elif name == "search_vulnerabilities":
                    result = await self._search_vulnerabilities(**arguments)
                elif name == "generate_security_dashboard":
                    result = await self._generate_security_dashboard_tool(**arguments)
                elif name == "create_stackhawk_config":
                    result = await self._create_stackhawk_config(**arguments)
                elif name == "validate_stackhawk_config":
                    result = await self._validate_stackhawk_config(**arguments)
                elif name == "get_stackhawk_schema":
                    result = await self._get_stackhawk_schema(**arguments)
                elif name == "refresh_schema_cache":
                    result = await self._refresh_schema_cache(**arguments)
                elif name == "validate_field_exists":
                    result = await self._validate_field_exists(**arguments)
                elif name == "get_schema_fields":
                    result = await self._get_schema_fields(**arguments)
                elif name == "suggest_configuration":
                    result = await self._suggest_configuration(**arguments)
                elif name == "get_vulnerability_report":
                    result = await self._get_vulnerability_report(**arguments)
                elif name == "analyze_vulnerability_trends":
                    result = await self._analyze_vulnerability_trends(**arguments)
                elif name == "get_critical_findings":
                    result = await self._get_critical_findings(**arguments)
                elif name == "generate_executive_summary":
                    result = await self._generate_executive_summary(**arguments)
                elif name == "analyze_threat_surface":
                    result = await self._analyze_threat_surface(**arguments)
                elif name == "get_repository_security_overview":
                    result = await self._get_repository_security_overview(**arguments)
                elif name == "identify_high_risk_repositories":
                    result = await self._identify_high_risk_repositories(**arguments)
                elif name == "generate_code_security_report":
                    result = await self._generate_code_security_report(**arguments)
                elif name == "map_attack_surface":
                    result = await self._map_attack_surface(**arguments)
                elif name == "get_application_vulnerabilities":
                    result = await self._get_application_vulnerabilities(**arguments)
                elif name == "get_application_security_summary":
                    result = await self._get_application_security_summary(**arguments)
                elif name == "compare_application_security":
                    result = await self._compare_application_security(**arguments)
                elif name == "get_sensitive_data_report":
                    result = await self._get_sensitive_data_report(**arguments)
                elif name == "analyze_sensitive_data_trends":
                    result = await self._analyze_sensitive_data_trends(**arguments)
                elif name == "get_critical_sensitive_data":
                    result = await self._get_critical_sensitive_data(**arguments)
                elif name == "generate_sensitive_data_summary":
                    result = await self._generate_sensitive_data_summary(**arguments)
                elif name == "get_application_sensitive_data":
                    result = await self._get_application_sensitive_data(**arguments)
                elif name == "get_repository_sensitive_data":
                    result = await self._get_repository_sensitive_data(**arguments)
                elif name == "get_sensitive_data_types":
                    result = await self._get_sensitive_data_types(**arguments)
                elif name == "map_sensitive_data_surface":
                    result = await self._map_sensitive_data_surface(**arguments)
                elif name == "get_project_open_stackhawk_issues":
                    result = await self._get_project_open_stackhawk_issues(**arguments)
                elif name == "setup_stackhawk_for_project":
                    result = await self._setup_stackhawk_for_project(**arguments)
                elif name == "get_stackhawk_scan_instructions":
                    config_path = arguments.get("config_path", "stackhawk.yml")
                    result = self._get_stackhawk_scan_instructions(config_path)
                    return [types.TextContent(content=result)]
                else:
                    raise ValueError(f"Unknown tool: {name}")

                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

            except Exception as e:
                debug_print(f"Tool {name} failed: {e}")
                error_result = {"error": str(e), "tool": name, "arguments": arguments}
                return [types.TextContent(type="text", text=json.dumps(error_result, indent=2))]

        debug_print("MCP handlers setup complete")

    async def _get_schema(self) -> Dict[str, Any]:
        """Get the StackHawk YAML schema with caching"""
        now = datetime.now()
        
        # Check if we have a valid cached schema
        if (self._schema_cache is not None and 
            self._schema_cache_time is not None and 
            now - self._schema_cache_time < self._schema_cache_ttl):
            debug_print("Using cached schema")
            return self._schema_cache
        
        try:
            debug_print("Fetching schema from StackHawk official URL...")
            schema = await self.client.get_yaml_schema()
            self._schema_cache = schema
            self._schema_cache_time = now
            debug_print("Schema cached successfully")
            return schema
        except Exception as e:
            debug_print(f"Failed to fetch schema: {e}")
            # If we can't fetch the schema, use a minimal fallback based on the official schema structure
            fallback_schema = {
                "$schema": "https://json-schema.org/draft/2019-09/schema#",
                "$id": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json",
                "type": "object",
                "title": "HawkScan Configuration",
                "description": "JSON schema for StackHawk HawkScan configuration files.",
                "properties": {
                    "app": {
                        "type": "object",
                        "description": "Application configuration",
                        "properties": {
                            "applicationId": {"type": "string"},
                            "env": {"type": "string"},
                            "host": {"type": "string"}
                        },
                        "required": ["applicationId", "env", "host"]
                    },
                    "hawk": {
                        "type": "object",
                        "description": "HawkScan settings"
                    },
                    "hawkAddOn": {
                        "type": "object",
                        "description": "Add-ons and custom scripts"
                    },
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "value": {"type": "string"}
                            }
                        }
                    }
                },
                "required": ["app"]
            }
            debug_print("Using fallback schema based on official structure")
            return fallback_schema

    def _extract_schema_fields(self, schema: Dict[str, Any], path: str = "") -> Dict[str, Any]:
        """Extract all valid fields and their types from the schema"""
        fields = {}
        
        if "properties" in schema:
            for field_name, field_schema in schema["properties"].items():
                current_path = f"{path}.{field_name}" if path else field_name
                
                field_info = {
                    "type": field_schema.get("type", "object"),
                    "description": field_schema.get("description", ""),
                    "required": field_name in schema.get("required", []),
                    "path": current_path
                }
                
                # Handle enums
                if "enum" in field_schema:
                    field_info["enum"] = field_schema["enum"]
                
                # Handle nested objects
                if field_schema.get("type") == "object" and "properties" in field_schema:
                    field_info["nested_fields"] = self._extract_schema_fields(field_schema, current_path)
                
                # Handle arrays
                if field_schema.get("type") == "array" and "items" in field_schema:
                    field_info["array_type"] = field_schema["items"].get("type", "object")
                    if field_schema["items"].get("type") == "object":
                        field_info["array_fields"] = self._extract_schema_fields(field_schema["items"], f"{current_path}[]")
                
                fields[field_name] = field_info
        
        return fields

    def _validate_field_path(self, field_path: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Validate if a field path exists in the schema and return its details"""
        path_parts = field_path.split(".")
        current_schema = schema
        
        for part in path_parts:
            if part.endswith("[]"):
                # Handle array access
                part = part[:-2]
                if "properties" in current_schema and part in current_schema["properties"]:
                    array_schema = current_schema["properties"][part]
                    if array_schema.get("type") == "array" and "items" in array_schema:
                        current_schema = array_schema["items"]
                    else:
                        return {"exists": False, "error": f"Field '{part}' is not an array"}
                else:
                    return {"exists": False, "error": f"Array field '{part}' not found"}
            else:
                # Handle regular field access
                if "properties" in current_schema and part in current_schema["properties"]:
                    current_schema = current_schema["properties"][part]
                else:
                    return {"exists": False, "error": f"Field '{part}' not found"}
        
        return {
            "exists": True,
            "type": current_schema.get("type", "object"),
            "description": current_schema.get("description", ""),
            "enum": current_schema.get("enum"),
            "required": field_path.split(".")[-1] in current_schema.get("required", [])
        }

    async def _get_organization_info(self, org_id: str) -> Dict[str, Any]:
        """Get comprehensive organization information"""
        try:
            # Get teams and applications
            teams_response = await self.client.list_teams(org_id, pageSize=100)
            apps_response = await self.client.list_applications(org_id, pageSize=100)

            return {
                "organizationId": org_id,
                "teams": teams_response.get("teams", []),
                "applications": apps_response.get("applications", []),
                "totalTeams": teams_response.get("totalCount", 0),
                "totalApplications": apps_response.get("totalCount", 0),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _get_organization_info: {e}")
            raise

    async def _list_applications(self, org_id: str, **kwargs) -> Dict[str, Any]:
        """List applications with basic information"""
        try:
            params = {k: v for k, v in kwargs.items() if v is not None}

            # Map parameter names to API expected names
            if "page_size" in params:
                params["pageSize"] = params.pop("page_size")

            apps_response = await self.client.list_applications(org_id, **params)

            return {
                **apps_response,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _list_applications: {e}")
            raise

    async def _search_vulnerabilities(self, org_id: str, **kwargs) -> Dict[str, Any]:
        """Search for specific vulnerabilities (summarized, only latest scan per app)"""
        try:
            # Get all applications in the org
            apps_response = await self.client.list_applications(org_id, pageSize=1000)
            applications = apps_response.get("applications", [])
            app_id_to_name = {app["id"]: app.get("name", "") for app in applications}

            # For each app, get the latest scan and its findings
            latest_findings = []
            for app in applications:
                app_id = app["id"]
                scans_response = await self.client.list_scans(org_id, appIds=app_id, pageSize=1)
                scans = scans_response.get("scans", [])
                if not scans:
                    continue
                latest_scan = sorted(scans, key=lambda s: s.get("scanStart", ""), reverse=True)[0]
                scan_id = latest_scan.get("id")
                if not scan_id:
                    continue
                # Get findings for this scan only
                findings_response = await self.client._make_request(
                    "GET",
                    f"/api/v1/scan/{org_id}/{scan_id}/findings",
                    params={"pageSize": 1000}
                )
                findings = findings_response.get("findings", [])
                for f in findings:
                    f["applicationId"] = app_id
                    f["applicationName"] = app.get("name", "")
                latest_findings.extend(findings)

            # Apply client-side filters
            filtered_findings = latest_findings
            if kwargs.get("severity"):
                severity = kwargs["severity"]
                filtered_findings = [
                    f for f in filtered_findings
                    if f.get("findingRisk") == severity
                ]

            # Summarize by severity
            severity_counts = {"High": 0, "Medium": 0, "Low": 0}
            for finding in filtered_findings:
                sev = finding.get("findingRisk")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            # Optionally, show top 3 findings by severity
            top_findings = []
            for sev in ["High", "Medium", "Low"]:
                sev_findings = [f for f in filtered_findings if f.get("findingRisk") == sev]
                for f in sev_findings[:2]:
                    top_findings.append({
                        "id": f.get("id"),
                        "applicationId": f.get("applicationId"),
                        "applicationName": f.get("applicationName"),
                        "findingRisk": f.get("findingRisk"),
                        "findingPluginName": f.get("findingPluginName"),
                        "status": f.get("status")
                    })

            return {
                "organizationId": org_id,
                "searchCriteria": kwargs,
                "totalMatches": len(filtered_findings),
                "severityBreakdown": severity_counts,
                "topFindings": top_findings,
                "timestamp": datetime.now().isoformat(),
                "note": "Summarized: Only findings from the latest scan per app are included. Full lists omitted for LLM efficiency."
            }
        except Exception as e:
            debug_print(f"Error in _search_vulnerabilities: {e}")
            raise

    async def _generate_security_dashboard_tool(self, org_id: str) -> Dict[str, Any]:
        """Generate basic security dashboard (summarized, only latest scan per app)"""
        try:
            # Get applications
            apps_response = await self.client.list_applications(org_id, pageSize=1000)
            applications = apps_response.get("applications", [])

            # For each app, get the latest scan and its findings
            latest_findings = []
            for app in applications:
                app_id = app["id"]
                scans_response = await self.client.list_scans(org_id, appIds=app_id, pageSize=1)
                scans = scans_response.get("scans", [])
                if not scans:
                    continue
                latest_scan = sorted(scans, key=lambda s: s.get("scanStart", ""), reverse=True)[0]
                scan_id = latest_scan.get("id")
                if not scan_id:
                    continue
                findings_response = await self.client._make_request(
                    "GET",
                    f"/api/v1/scan/{org_id}/{scan_id}/findings",
                    params={"pageSize": 1000}
                )
                findings = findings_response.get("findings", [])
                latest_findings.extend(findings)

            # Basic metrics
            severity_counts = {"High": 0, "Medium": 0, "Low": 0}
            for finding in latest_findings:
                severity = finding.get("findingRisk")
                if severity in severity_counts:
                    severity_counts[severity] += 1

            return {
                "organizationId": org_id,
                "generatedAt": datetime.now().isoformat(),
                "overview": {
                    "totalApplications": len(applications),
                    "totalFindings": len(latest_findings)
                },
                "securityMetrics": {
                    "severityBreakdown": severity_counts,
                    "totalVulnerabilities": len(latest_findings)
                },
                "note": "Summarized: Only findings from the latest scan per app are included. Full lists omitted for LLM efficiency."
            }
        except Exception as e:
            debug_print(f"Error in _generate_security_dashboard_tool: {e}")
            raise

    async def _generate_vulnerability_summary(self) -> str:
        """Generate organization-wide vulnerability summary (summarized, only latest scan per app)"""
        try:
            user_info = await self.client.get_user_info()
            summary_data = {"organizations": []}

            for org in user_info["user"]["external"]["organizations"]:
                org_id = org["organization"]["id"]
                org_name = org["organization"]["name"]

                try:
                    # Get all applications
                    apps_response = await self.client.list_applications(org_id, pageSize=1000)
                    applications = apps_response.get("applications", [])

                    # For each app, get the latest scan and its findings
                    latest_findings = []
                    for app in applications:
                        app_id = app["id"]
                        scans_response = await self.client.list_scans(org_id, appIds=app_id, pageSize=1)
                        scans = scans_response.get("scans", [])
                        if not scans:
                            continue
                        latest_scan = sorted(scans, key=lambda s: s.get("scanStart", ""), reverse=True)[0]
                        scan_id = latest_scan.get("id")
                        if not scan_id:
                            continue
                        findings_response = await self.client._make_request(
                            "GET",
                            f"/api/v1/scan/{org_id}/{scan_id}/findings",
                            params={"pageSize": 1000}
                        )
                        findings = findings_response.get("findings", [])
                        latest_findings.extend(findings)

                    # Aggregate by severity
                    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
                    for finding in latest_findings:
                        severity = finding.get("findingRisk")
                        if severity in severity_counts:
                            severity_counts[severity] += 1

                    org_summary = {
                        "organizationId": org_id,
                        "organizationName": org_name,
                        "totalFindings": len(latest_findings),
                        "severityBreakdown": severity_counts,
                        "note": "Summarized: Only findings from the latest scan per app are included. Full lists omitted for LLM efficiency."
                    }

                    summary_data["organizations"].append(org_summary)

                except Exception as e:
                    debug_print(f"Could not get findings for org {org_id}: {e}")
                    summary_data["organizations"].append({
                        "organizationId": org_id,
                        "organizationName": org_name,
                        "error": str(e)
                    })

            summary_data["generatedAt"] = datetime.now().isoformat()
            return json.dumps(summary_data, indent=2)
        except Exception as e:
            debug_print(f"Error in _generate_vulnerability_summary: {e}")
            raise

    async def _create_stackhawk_config(self, application_id: str, app_name: str, host: str, port: int, **kwargs) -> Dict[str, Any]:
        """
        Create a new StackHawk YAML configuration with best practices.
        
        Usage:
            1. First, call setup_stackhawk_for_project to create the app and get applicationId/appName.
            2. Then, call this function with:
                application_id = result["applicationId"]
                app_name = result["appName"]
                host, port = (prompt user or auto-detect)
                (plus any other kwargs)
        """
        try:
            # Set defaults
            environment = kwargs.get("environment", "dev")
            protocol = kwargs.get("protocol", "https")
            scanner_mode = kwargs.get("scanner_mode", "standard")
            include_auth = kwargs.get("include_auth", False)
            auth_type = kwargs.get("auth_type", "form")

            # Build the host URL
            host_url = f"{protocol}://{host}:{port}" if port != (443 if protocol == "https" else 80) else f"{protocol}://{host}"

            # Build the configuration based on the official schema
            config = {
                "app": {
                    "applicationId": application_id,
                    "env": environment,
                    "host": host_url,
                    "name": app_name,
                    "description": f"StackHawk configuration for {app_name} in {environment} environment"
                },
                "hawk": {
                    "spider": {
                        "base": True,
                        "ajax": False,
                        "maxDurationMinutes": 30
                    },
                    "scan": {
                        "maxDurationMinutes": 60,
                        "threads": 10
                    },
                    "startupTimeoutMinutes": 5,
                    "failureThreshold": "high"
                },
                "tags": [
                    {"name": "environment", "value": environment},
                    {"name": "application", "value": app_name.lower().replace(" ", "-")}
                ]
            }

            # Add authentication if requested
            if include_auth:
                auth_config = {
                    "type": auth_type,
                    "username": "your-username",
                    "password": "your-password"
                }

                if auth_type == "form":
                    auth_config.update({
                        "loginUrl": f"{host_url}/login",
                        "usernameField": "username",
                        "passwordField": "password"
                    })
                elif auth_type == "header":
                    auth_config.update({
                        "headers": {
                            "Authorization": "Bearer your-token-here"
                        }
                    })
                elif auth_type == "json":
                    auth_config.update({
                        "loginUrl": f"{host_url}/api/auth/login",
                        "jsonData": {
                            "username": "your-username",
                            "password": "your-password"
                        }
                    })

                config["app"]["authentication"] = auth_config

            # Convert to YAML
            yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False)

            return {
                "success": True,
                "config": config,
                "yaml": yaml_content,
                "filename": f"stackhawk-{app_name.lower().replace(' ', '-')}-{environment}.yml",
                "validation": "Configuration follows official StackHawk schema and best practices",
                "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json",
                "next_steps": [
                    "Review and customize the configuration",
                    "Update authentication credentials",
                    "Adjust scan parameters as needed",
                    "Test the configuration with a dry run"
                ]
            }

        except Exception as e:
            debug_print(f"Error in _create_stackhawk_config: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to create StackHawk configuration"
            }

    async def _validate_stackhawk_config(self, yaml_content: str) -> Dict[str, Any]:
        """Validate a StackHawk YAML configuration against the schema"""
        try:
            # Parse YAML
            try:
                config_data = yaml.safe_load(yaml_content)
            except yaml.YAMLError as e:
                return {
                    "valid": False,
                    "error_type": "YAML_PARSE_ERROR",
                    "error": str(e),
                    "message": "Invalid YAML syntax"
                }

            # Get the schema
            schema = await self._get_schema()

            # Validate against schema
            try:
                validate(instance=config_data, schema=schema)
                validation_result = {
                    "valid": True,
                    "message": "Configuration is valid and follows official StackHawk schema",
                    "config_summary": {
                        "application_id": config_data.get("app", {}).get("applicationId"),
                        "app_name": config_data.get("app", {}).get("name"),
                        "environment": config_data.get("app", {}).get("env"),
                        "host": config_data.get("app", {}).get("host"),
                        "has_hawk_config": "hawk" in config_data,
                        "has_hawk_addon": "hawkAddOn" in config_data,
                        "has_tags": "tags" in config_data,
                        "has_authentication": "authentication" in config_data.get("app", {})
                    }
                }

                # Additional validation checks
                warnings = []
                
                # Check for common issues
                app_config = config_data.get("app", {})
                hawk_config = config_data.get("hawk", {})
                
                if not app_config.get("description"):
                    warnings.append("Consider adding a description for better documentation")
                
                if not hawk_config.get("spider", {}).get("base"):
                    warnings.append("Consider enabling base spider for traditional web applications")
                
                if hawk_config.get("scan", {}).get("maxDurationMinutes", 0) > 120:
                    warnings.append("Scan duration is quite high (>2 hours), consider reducing for faster feedback")
                
                if warnings:
                    validation_result["warnings"] = warnings

                return validation_result

            except ValidationError as e:
                return {
                    "valid": False,
                    "error_type": "SCHEMA_VALIDATION_ERROR",
                    "error": str(e),
                    "message": f"Configuration does not match StackHawk schema: {e.message}",
                    "path": " -> ".join(str(p) for p in e.path) if e.path else "unknown"
                }

        except Exception as e:
            debug_print(f"Error in _validate_stackhawk_config: {e}")
            return {
                "valid": False,
                "error_type": "UNKNOWN_ERROR",
                "error": str(e),
                "message": "Unexpected error during validation"
            }

    async def _get_stackhawk_schema(self, **kwargs) -> Dict[str, Any]:
        """Get the complete StackHawk YAML configuration schema"""
        try:
            schema = await self._get_schema()
            return {
                "schema": schema,
                "description": "StackHawk YAML Configuration Schema",
                "version": "1.0.0",
                "source": "Official StackHawk Schema URL",
                "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json",
                "cached": self._schema_cache_time is not None,
                "cache_age": str(datetime.now() - self._schema_cache_time) if self._schema_cache_time else None,
                "documentation": {
                    "app": "Application configuration section (required)",
                    "hawk": "HawkScan settings (optional)",
                    "hawkAddOn": "Add-ons and custom scripts (optional)",
                    "tags": "Metadata tags (optional)"
                },
                "examples": {
                    "basic_config": {
                        "app": {
                            "applicationId": "your-app-id",
                            "env": "dev",
                            "host": "http://localhost:3000"
                        }
                    },
                    "with_scan_config": {
                        "app": {
                            "applicationId": "your-app-id",
                            "env": "prod",
                            "host": "https://myapp.com"
                        },
                        "hawk": {
                            "spider": {
                                "base": True,
                                "ajax": False
                            },
                            "scan": {
                                "maxDurationMinutes": 60
                            }
                        }
                    }
                }
            }
        except Exception as e:
            debug_print(f"Error in _get_stackhawk_schema: {e}")
            return {
                "error": str(e),
                "message": "Failed to retrieve schema"
            }

    async def _refresh_schema_cache(self, **kwargs) -> Dict[str, Any]:
        """Force refresh the cached StackHawk YAML schema from the official URL"""
        try:
            debug_print("Refreshing schema cache from official URL...")
            schema = await self.client.get_yaml_schema()
            self._schema_cache = schema
            self._schema_cache_time = datetime.now()
            debug_print("Schema cache refreshed successfully")
            return {
                "success": True,
                "message": "Schema cache refreshed successfully from official URL",
                "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json"
            }
        except Exception as e:
            debug_print(f"Error in _refresh_schema_cache: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to refresh schema cache from official URL"
            }

    async def _validate_field_exists(self, field_path: str, **kwargs) -> Dict[str, Any]:
        """Check if a specific field path exists in the StackHawk schema and get its details"""
        try:
            schema = await self._get_schema()
            result = self._validate_field_path(field_path, schema)
            
            if result["exists"]:
                return {
                    "success": True,
                    "field_path": field_path,
                    "exists": True,
                    "type": result["type"],
                    "description": result["description"],
                    "enum_values": result.get("enum"),
                    "required": result["required"],
                    "message": f"Field '{field_path}' exists in the StackHawk schema"
                }
            else:
                return {
                    "success": False,
                    "field_path": field_path,
                    "exists": False,
                    "error": result["error"],
                    "message": f"Field '{field_path}' does not exist in the StackHawk schema",
                    "suggestion": "Use get_schema_fields to see all available fields"
                }
        except Exception as e:
            debug_print(f"Error in _validate_field_exists: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to validate field existence"
            }

    async def _get_schema_fields(self, section: str = None, **kwargs) -> Dict[str, Any]:
        """Get all available fields and their types from the StackHawk schema"""
        try:
            schema = await self._get_schema()
            
            if section:
                # Filter by specific section
                if section in schema.get("properties", {}):
                    section_schema = schema["properties"][section]
                    fields = self._extract_schema_fields(section_schema, section)
                    return {
                        "section": section,
                        "fields": fields,
                        "total_fields": len(fields),
                        "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json"
                    }
                else:
                    return {
                        "error": f"Section '{section}' not found in schema",
                        "available_sections": list(schema.get("properties", {}).keys()),
                        "suggestion": "Use one of the available sections"
                    }
            else:
                # Get all fields
                fields = self._extract_schema_fields(schema)
                return {
                    "all_fields": fields,
                    "total_fields": len(fields),
                    "available_sections": list(schema.get("properties", {}).keys()),
                    "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json",
                    "note": "Use the 'section' parameter to filter by specific sections (app, hawk, hawkAddOn, tags)"
                }
        except Exception as e:
            debug_print(f"Error in _get_schema_fields: {e}")
            return {
                "error": str(e),
                "message": "Failed to retrieve schema fields"
            }

    async def _suggest_configuration(self, use_case: str, environment: str = "dev", include_advanced: bool = False, **kwargs) -> Dict[str, Any]:
        """Get AI-powered configuration suggestions based on the actual StackHawk schema"""
        try:
            schema = await self._get_schema()
            
            # Base configuration template
            base_config = {
                "app": {
                    "applicationId": "YOUR_APPLICATION_ID_HERE",
                    "env": environment,
                    "host": "YOUR_HOST_URL_HERE",
                    "name": "Your Application Name",
                    "description": f"Configuration for {use_case} in {environment} environment"
                }
            }
            
            suggestions = {
                "use_case": use_case,
                "environment": environment,
                "include_advanced": include_advanced,
                "base_configuration": base_config,
                "recommendations": [],
                "warnings": [],
                "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json"
            }
            
            # Add recommendations based on use case
            use_case_lower = use_case.lower()
            
            if "web" in use_case_lower or "frontend" in use_case_lower:
                suggestions["recommendations"].append({
                    "section": "hawk.spider",
                    "recommendation": "Enable base spider for traditional web applications",
                    "configuration": {
                        "hawk": {
                            "spider": {
                                "base": True,
                                "ajax": False,
                                "maxDurationMinutes": 30
                            }
                        }
                    }
                })
            
            if "api" in use_case_lower or "rest" in use_case_lower:
                suggestions["recommendations"].append({
                    "section": "hawk.spider",
                    "recommendation": "Disable spiders for API testing, use seed paths instead",
                    "configuration": {
                        "hawk": {
                            "spider": {
                                "base": False,
                                "ajax": False
                            }
                        }
                    }
                })
            
            if "authentication" in use_case_lower or "login" in use_case_lower:
                suggestions["recommendations"].append({
                    "section": "app.authentication",
                    "recommendation": "Add authentication configuration",
                    "configuration": {
                        "app": {
                            "authentication": {
                                "type": "form",
                                "username": "YOUR_USERNAME",
                                "password": "YOUR_PASSWORD",
                                "loginUrl": "YOUR_LOGIN_URL",
                                "usernameField": "username",
                                "passwordField": "password"
                            }
                        }
                    }
                })
            
            if environment == "prod":
                suggestions["recommendations"].append({
                    "section": "hawk.scan",
                    "recommendation": "Use conservative scan settings for production",
                    "configuration": {
                        "hawk": {
                            "scan": {
                                "maxDurationMinutes": 60,
                                "threads": 5
                            },
                            "failureThreshold": "high"
                        }
                    }
                })
            
            if include_advanced:
                suggestions["recommendations"].append({
                    "section": "tags",
                    "recommendation": "Add metadata tags for better organization",
                    "configuration": {
                        "tags": [
                            {"name": "environment", "value": environment},
                            {"name": "use_case", "value": use_case},
                            {"name": "created_by", "value": "stackhawk-mcp"}
                        ]
                    }
                })
            
            # Add warnings
            suggestions["warnings"].append("Always validate your configuration before using it in production")
            suggestions["warnings"].append("Replace placeholder values with actual application details")
            suggestions["warnings"].append("Test the configuration in a safe environment first")
            
            return suggestions
            
        except Exception as e:
            debug_print(f"Error in _suggest_configuration: {e}")
            return {
                "error": str(e),
                "message": "Failed to generate configuration suggestions"
            }

    async def _get_vulnerability_report(self, org_id: str, severity_filter: str, time_range: str, include_remediation: bool, group_by: str) -> Dict[str, Any]:
        """Generate comprehensive vulnerability report for an organization (only latest scan per app)"""
        try:
            # Get all applications
            apps_response = await self.client.list_applications(org_id, pageSize=1000)
            applications = apps_response.get("applications", [])

            # For each app, get the latest scan and its findings
            latest_findings = []
            for app in applications:
                app_id = app["id"]
                scans_response = await self.client.list_scans(org_id, appIds=app_id, pageSize=1)
                scans = scans_response.get("scans", [])
                if not scans:
                    continue
                latest_scan = sorted(scans, key=lambda s: s.get("scanStart", ""), reverse=True)[0]
                scan_id = latest_scan.get("id")
                if not scan_id:
                    continue
                findings_response = await self.client._make_request(
                    "GET",
                    f"/api/v1/scan/{org_id}/{scan_id}/findings",
                    params={"pageSize": 1000}
                )
                findings = findings_response.get("findings", [])
                latest_findings.extend(findings)

            # Apply client-side filters
            filtered_findings = latest_findings
            if severity_filter != "All":
                filtered_findings = [
                    f for f in filtered_findings
                    if f.get("findingRisk") == severity_filter
                ]

            # Group findings
            grouped_findings = {}
            for finding in filtered_findings:
                group_key = finding.get(group_by)
                if group_key not in grouped_findings:
                    grouped_findings[group_key] = []
                grouped_findings[group_key].append(finding)

            # Format findings (summarized)
            formatted_findings = []
            for group, findings in grouped_findings.items():
                sev_counts = {"High": 0, "Medium": 0, "Low": 0}
                for f in findings:
                    sev = f.get("findingRisk")
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                formatted_findings.append({
                    "group": group,
                    "totalFindings": len(findings),
                    "severityBreakdown": sev_counts
                })

            return {
                "organizationId": org_id,
                "report": formatted_findings,
                "timestamp": datetime.now().isoformat(),
                "note": "Summarized: Only findings from the latest scan per app are included. Full lists omitted for LLM efficiency."
            }
        except Exception as e:
            debug_print(f"Error in _get_vulnerability_report: {e}")
            raise

    async def _analyze_vulnerability_trends(self, org_id: str, analysis_period: str, include_applications: bool, include_severity_breakdown: bool) -> Dict[str, Any]:
        """Analyze vulnerability trends and patterns across applications (only latest scan per app)"""
        try:
            # Get all applications
            apps_response = await self.client.list_applications(org_id, pageSize=1000)
            applications = apps_response.get("applications", [])

            # For each app, get the latest scan and its findings
            app_trends = []
            for app in applications:
                app_id = app["id"]
                scans_response = await self.client.list_scans(org_id, appIds=app_id, pageSize=1)
                scans = scans_response.get("scans", [])
                if not scans:
                    continue
                latest_scan = sorted(scans, key=lambda s: s.get("scanStart", ""), reverse=True)[0]
                scan_id = latest_scan.get("id")
                if not scan_id:
                    continue
                findings_response = await self.client._make_request(
                    "GET",
                    f"/api/v1/scan/{org_id}/{scan_id}/findings",
                    params={"pageSize": 1000}
                )
                findings = findings_response.get("findings", [])
                # Summarize by severity
                sev_counts = {"High": 0, "Medium": 0, "Low": 0}
                for f in findings:
                    sev = f.get("findingRisk")
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                app_trends.append({
                    "applicationId": app_id,
                    "applicationName": app.get("name", ""),
                    "totalFindings": len(findings),
                    "severityBreakdown": sev_counts
                })

            return {
                "organizationId": org_id,
                "trends": app_trends,
                "timestamp": datetime.now().isoformat(),
                "note": "Summarized: Only findings from the latest scan per app are included. Full lists omitted for LLM efficiency."
            }
        except Exception as e:
            debug_print(f"Error in _analyze_vulnerability_trends: {e}")
            raise

    async def _get_critical_findings(self, org_id: str, severity_levels: List[str], include_remediation: bool, max_results: int) -> Dict[str, Any]:
        """Get high-severity findings requiring immediate attention"""
        try:
            # For high-severity findings, we want to see ALL high findings, not just the first page
            findings_response = await self.client.list_organization_findings(org_id, all_results=True)
            findings = findings_response.get("findings", [])

            # Filter findings based on severity levels
            filtered_findings = [
                f for f in findings
                if f.get("findingRisk") in severity_levels
            ]

            # Include remediation details
            if include_remediation:
                for finding in filtered_findings:
                    finding["remediation"] = finding.get("remediationDetails", "No remediation details available")

            return {
                "organizationId": org_id,
                "findings": filtered_findings,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _get_high_severity_findings: {e}")
            raise

    async def _generate_executive_summary(self, org_id: str, time_period: str = "30d", include_recommendations: bool = True, include_risk_score: bool = True, **kwargs) -> Dict[str, Any]:
        """Generate executive-level vulnerability summary and recommendations"""
        try:
            # Limit time period to a maximum of 90 days
            if time_period == "all" or (time_period.endswith("d") and int(time_period[:-1]) > 90):
                time_period = "90d"

            # Fetch all results up to the end date (now), then filter client-side for the last N days
            findings_response = await self.client.list_organization_findings(org_id, all_results=True)
            findings = findings_response.get("findings", [])

            # Apply time period filter (max 90 days)
            if time_period != "all":
                days = int(time_period[:-1]) if time_period.endswith("d") else 30
                time_filter = {
                    "startDate": (datetime.now() - timedelta(days=days)).isoformat(),
                    "endDate": datetime.now().isoformat()
                }
                filtered_findings = []
                for finding in findings:
                    finding_date = finding.get("findingDate")
                    if finding_date and time_filter["startDate"] <= finding_date <= time_filter["endDate"]:
                        filtered_findings.append(finding)
                findings = filtered_findings

            # Summarize findings: only aggregate counts, not full details
            severity_findings = {"High": 0, "Medium": 0, "Low": 0}
            for finding in findings:
                severity = finding.get("findingRisk")
                if severity in severity_findings:
                    severity_findings[severity] += 1

            # Calculate scan coverage from findings data (as before)
            try:
                scan_ids = set()
                for finding in findings:
                    scan_id = finding.get("scanId")
                    if scan_id:
                        scan_ids.add(scan_id)
                scan_coverage = {
                    "totalScans": len(scan_ids),
                    "successfulScans": len(scan_ids),
                    "failedScans": 0,
                    "inProgressScans": 0,
                    "uniqueScanIds": list(scan_ids)
                }
            except Exception as e:
                debug_print(f"Error calculating scan coverage from findings: {e}")
                scan_coverage = {
                    "totalScans": 0,
                    "successfulScans": 0,
                    "failedScans": 0,
                    "inProgressScans": 0,
                    "uniqueScanIds": []
                }

            summary = {
                "totalFindings": sum(severity_findings.values()),
                "severityBreakdown": severity_findings,
                "timePeriod": time_period,
                "highSeverityFindings": severity_findings["High"],
                "criticalFindings": severity_findings["High"],
                "scanCoverage": scan_coverage
            }

            # Recommendations and risk score as before
            if include_recommendations:
                recommendations = []
                if scan_coverage["totalScans"] == 0:
                    recommendations.append({
                        "priority": "High",
                        "recommendation": "No security scans performed in the specified time period",
                        "action": "Immediately schedule security scans to assess current risk posture"
                    })
                elif scan_coverage["successfulScans"] == 0:
                    recommendations.append({
                        "priority": "High",
                        "recommendation": "No successful security scans in the specified time period",
                        "action": "Investigate scan failures and ensure successful scan completion"
                    })
                elif scan_coverage["successfulScans"] < 3:
                    recommendations.append({
                        "priority": "High",
                        "recommendation": f"Limited scan coverage: only {scan_coverage['successfulScans']} successful scans",
                        "action": "Increase scan frequency and coverage"
                    })
                if severity_findings["High"] > 0:
                    recommendations.append({
                        "priority": "High",
                        "recommendation": f"Immediately address {severity_findings['High']} high-severity vulnerabilities",
                        "action": "Prioritize remediation of high-severity findings"
                    })
                if severity_findings["Medium"] > 5:
                    recommendations.append({
                        "priority": "High",
                        "recommendation": f"Address {severity_findings['Medium']} medium-severity vulnerabilities",
                        "action": "Implement systematic remediation plan"
                    })
                if severity_findings["Low"] > 10:
                    recommendations.append({
                        "priority": "Medium",
                        "recommendation": f"Review {severity_findings['Low']} low-severity findings",
                        "action": "Schedule regular security reviews"
                    })
                if (severity_findings["High"] == 0 and severity_findings["Medium"] <= 5 and scan_coverage["successfulScans"] >= 3):
                    recommendations.append({
                        "priority": "Info",
                        "recommendation": "Good security posture maintained",
                        "action": "Continue current security practices and monitoring"
                    })
                elif not recommendations:
                    recommendations.append({
                        "priority": "Info",
                        "recommendation": "No high-severity vulnerabilities found in the specified time period",
                        "action": "Maintain current security practices"
                    })
                summary["recommendations"] = recommendations

            if include_risk_score:
                summary["riskScore"] = self._calculate_risk_score_with_scan_coverage(findings, scan_coverage, time_period)
                summary["riskLevel"] = self._determine_risk_level(summary["riskScore"])

            return {
                "organizationId": org_id,
                "timePeriod": time_period,
                "summary": summary,
                "timestamp": datetime.now().isoformat(),
                "note": "⚠️ These are organization-wide findings across ALL applications. Use get_application_vulnerabilities for app-specific data. Only aggregate counts are included for LLM efficiency."
            }
        except Exception as e:
            debug_print(f"Error in _generate_executive_summary: {e}")
            raise

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on findings"""
        if not findings:
            return 0.0
        
        # Weight different severity levels
        severity_weights = {
            "High": 10.0,
            "Medium": 5.0,
            "Low": 1.0
        }
        
        total_score = 0.0
        for finding in findings:
            severity = finding.get("findingRisk", "Low")
            weight = severity_weights.get(severity, 1.0)
            total_score += weight
        
        # Normalize to 0-100 scale
        # Base score on findings count and severity distribution
        normalized_score = min(total_score / max(len(findings), 1) * 2, 100.0)
        
        return round(normalized_score, 1)

    def _calculate_risk_score_with_scan_coverage(self, findings: List[Dict[str, Any]], scan_coverage: Dict[str, int], time_period: str) -> float:
        """Calculate risk score based on findings and scan coverage"""
        # Start with base risk score from findings
        base_score = self._calculate_risk_score(findings)
        
        # Calculate scan coverage risk multiplier
        scan_risk_multiplier = 1.0
        
        total_scans = scan_coverage.get("totalScans", 0)
        successful_scans = scan_coverage.get("successfulScans", 0)
        failed_scans = scan_coverage.get("failedScans", 0)
        
        # No scans = highest risk (we can't assess the situation)
        if total_scans == 0:
            scan_risk_multiplier = 3.0  # Triple the risk score
        elif successful_scans == 0:
            scan_risk_multiplier = 2.5  # High risk due to scan failures
        elif successful_scans < 3:
            scan_risk_multiplier = 1.5  # Moderate risk due to limited coverage
        elif failed_scans > successful_scans:
            scan_risk_multiplier = 1.3  # Slight risk due to scan reliability issues
        
        # Apply scan coverage multiplier
        adjusted_score = base_score * scan_risk_multiplier
        
        # Cap at 100
        final_score = min(adjusted_score, 100.0)
        
        return round(final_score, 1)

    async def _analyze_threat_surface(self, org_id: str, include_repositories: bool = True, include_applications: bool = True, include_vulnerabilities: bool = True, risk_assessment: bool = True, **kwargs) -> Dict[str, Any]:
        """Analyze the threat surface across all repositories and applications"""
        try:
            threat_surface = {
                "organizationId": org_id,
                "analysis": {
                    "repositories": {},
                    "applications": {},
                    "vulnerabilities": {},
                    "risk_assessment": {}
                },
                "summary": {},
                "timestamp": datetime.now().isoformat()
            }

            # Analyze repositories
            if include_repositories:
                try:
                    repos_response = await self.client.list_repositories(org_id, pageSize=100)
                    repositories = repos_response.get("repositories", [])
                    
                    threat_surface["analysis"]["repositories"] = {
                        "total_repositories": len(repositories),
                        "active_repositories": len([r for r in repositories if r.get("status") == "active"]),
                        "archived_repositories": len([r for r in repositories if r.get("status") == "archived"]),
                        "repository_details": repositories
                    }
                except Exception as e:
                    debug_print(f"Error getting repositories: {e}")
                    threat_surface["analysis"]["repositories"] = {"error": str(e)}

            # Analyze applications
            if include_applications:
                try:
                    apps_response = await self.client.list_applications(org_id, pageSize=100)
                    applications = apps_response.get("applications", [])
                    
                    threat_surface["analysis"]["applications"] = {
                        "total_applications": len(applications),
                        "production_apps": len([a for a in applications if a.get("environment") == "prod"]),
                        "development_apps": len([a for a in applications if a.get("environment") == "dev"]),
                        "application_details": applications
                    }
                except Exception as e:
                    debug_print(f"Error getting applications: {e}")
                    threat_surface["analysis"]["applications"] = {"error": str(e)}

            # Analyze vulnerabilities
            if include_vulnerabilities:
                try:
                    findings_response = await self.client.list_organization_findings(org_id, all_results=True)
                    findings = findings_response.get("findings", [])
                    
                    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
                    for finding in findings:
                        severity = finding.get("findingRisk")
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                    
                    threat_surface["analysis"]["vulnerabilities"] = {
                        "total_vulnerabilities": len(findings),
                        "severity_breakdown": severity_counts,
                        "high_severity_findings": len([f for f in findings if f.get("findingRisk") == "High"])
                    }
                except Exception as e:
                    debug_print(f"Error getting vulnerabilities: {e}")
                    threat_surface["analysis"]["vulnerabilities"] = {"error": str(e)}

            # Risk assessment
            if risk_assessment:
                threat_surface["analysis"]["risk_assessment"] = {
                    "overall_risk_score": self._calculate_threat_surface_risk(threat_surface["analysis"]),
                    "risk_factors": self._identify_risk_factors(threat_surface["analysis"]),
                    "recommendations": self._generate_risk_recommendations(threat_surface["analysis"])
                }

            # Generate summary
            threat_surface["summary"] = {
                "total_assets": threat_surface["analysis"]["repositories"].get("total_repositories", 0) + 
                               threat_surface["analysis"]["applications"].get("total_applications", 0),
                "total_vulnerabilities": threat_surface["analysis"]["vulnerabilities"].get("total_vulnerabilities", 0),
                "risk_level": self._determine_risk_level(threat_surface["analysis"]["risk_assessment"].get("overall_risk_score", 0))
            }

            return threat_surface

        except Exception as e:
            debug_print(f"Error in _analyze_threat_surface: {e}")
            return {
                "error": str(e),
                "message": "Failed to analyze threat surface"
            }

    # Helper methods for threat surface analysis
    def _calculate_threat_surface_risk(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall threat surface risk score"""
        risk_score = 0.0
        
        # Repository risk
        repos = analysis.get("repositories", {})
        if "total_repositories" in repos:
            risk_score += repos["total_repositories"] * 0.1
        
        # Application risk
        apps = analysis.get("applications", {})
        if "total_applications" in apps:
            risk_score += apps["total_applications"] * 0.2
        
        # Vulnerability risk
        vulns = analysis.get("vulnerabilities", {})
        if "total_vulnerabilities" in vulns:
            risk_score += vulns["total_vulnerabilities"] * 0.5
        
        return min(risk_score, 100.0)

    def _identify_risk_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []
        
        vulns = analysis.get("vulnerabilities", {})
        if vulns.get("high_severity_findings", 0) > 0:
            risk_factors.append("High-severity vulnerabilities present")
        
        apps = analysis.get("applications", {})
        if apps.get("production_apps", 0) > 10:
            risk_factors.append("Large production footprint")
        
        repos = analysis.get("repositories", {})
        if repos.get("total_repositories", 0) > 50:
            risk_factors.append("High number of repositories")
        
        return risk_factors

    def _generate_risk_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        vulns = analysis.get("vulnerabilities", {})
        if vulns.get("high_severity_findings", 0) > 0:
            recommendations.append("Prioritize remediation of high-severity vulnerabilities")
        
        apps = analysis.get("applications", {})
        if apps.get("production_apps", 0) > 10:
            recommendations.append("Implement automated security scanning for production applications")
        
        return recommendations

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 70:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

    async def _get_repository_security_overview(self, org_id: str, include_scan_results: bool = True, include_vulnerabilities: bool = True, filter_by_status: str = "all", **kwargs) -> Dict[str, Any]:
        """Get comprehensive security overview for all repositories"""
        try:
            repos_response = await self.client.list_repositories(org_id, pageSize=100)
            repositories = repos_response.get("repositories", [])

            # Filter repositories by status
            if filter_by_status != "all":
                repositories = [r for r in repositories if r.get("status") == filter_by_status]

            security_overview = {
                "organizationId": org_id,
                "total_repositories": len(repositories),
                "repositories": [],
                "security_summary": {
                    "high_risk_repos": 0,
                    "medium_risk_repos": 0,
                    "low_risk_repos": 0,
                    "total_vulnerabilities": 0
                },
                "timestamp": datetime.now().isoformat()
            }

            for repo in repositories:
                repo_security = {
                    "repository_id": repo.get("id"),
                    "name": repo.get("name"),
                    "status": repo.get("status"),
                    "last_scan": repo.get("lastScanDate"),
                    "security_score": repo.get("securityScore", 0)
                }

                # Get scan results if requested
                if include_scan_results and repo.get("id"):
                    try:
                        scan_response = await self.client.get_repository_security_scan(org_id, repo["id"])
                        repo_security["scan_results"] = scan_response
                    except Exception as e:
                        repo_security["scan_results"] = {"error": str(e)}

                # Get vulnerability details if requested
                if include_vulnerabilities and repo.get("id"):
                    try:
                        # This would need to be implemented based on the actual API structure
                        repo_security["vulnerabilities"] = {
                            "total": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    except Exception as e:
                        repo_security["vulnerabilities"] = {"error": str(e)}

                security_overview["repositories"].append(repo_security)

                # Update summary
                score = repo_security.get("security_score", 0)
                if score < 30:
                    security_overview["security_summary"]["high_risk_repos"] += 1
                elif score < 70:
                    security_overview["security_summary"]["medium_risk_repos"] += 1
                else:
                    security_overview["security_summary"]["low_risk_repos"] += 1

            return security_overview

        except Exception as e:
            debug_print(f"Error in _get_repository_security_overview: {e}")
            return {
                "error": str(e),
                "message": "Failed to get repository security overview"
            }

    async def _identify_high_risk_repositories(self, org_id: str, risk_threshold: str = "high", include_remediation: bool = True, max_results: int = 20, **kwargs) -> Dict[str, Any]:
        """Identify repositories with high security risk or vulnerabilities"""
        try:
            repos_response = await self.client.list_repositories(org_id, pageSize=100)
            repositories = repos_response.get("repositories", [])

            high_risk_repos = []
            
            for repo in repositories:
                risk_level = self._assess_repository_risk(repo)
                
                if self._meets_risk_threshold(risk_level, risk_threshold):
                    repo_risk = {
                        "repository_id": repo.get("id"),
                        "name": repo.get("name"),
                        "risk_level": risk_level,
                        "security_score": repo.get("securityScore", 0),
                        "last_scan": repo.get("lastScanDate"),
                        "vulnerability_count": repo.get("vulnerabilityCount", 0),
                        "risk_factors": self._identify_repository_risk_factors(repo)
                    }

                    if include_remediation:
                        repo_risk["remediation"] = self._generate_repository_remediation(repo)

                    high_risk_repos.append(repo_risk)

            # Sort by risk level and limit results
            high_risk_repos.sort(key=lambda x: self._risk_level_score(x["risk_level"]), reverse=True)
            high_risk_repos = high_risk_repos[:max_results]

            return {
                "organizationId": org_id,
                "risk_threshold": risk_threshold,
                "high_risk_repositories": high_risk_repos,
                "total_identified": len(high_risk_repos),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            debug_print(f"Error in _identify_high_risk_repositories: {e}")
            return {
                "error": str(e),
                "message": "Failed to identify high-risk repositories"
            }

    async def _generate_code_security_report(self, org_id: str, report_type: str = "summary", include_trends: bool = True, include_comparison: bool = False, **kwargs) -> Dict[str, Any]:
        """Generate comprehensive code security report across repositories"""
        try:
            # Get repository data
            repos_response = await self.client.list_repositories(org_id, pageSize=100)
            repositories = repos_response.get("repositories", [])

            # Get vulnerability data
            findings_response = await self.client.list_organization_findings(org_id, pageSize=1000)
            findings = findings_response.get("findings", [])

            report = {
                "organizationId": org_id,
                "report_type": report_type,
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_repositories": len(repositories),
                    "total_vulnerabilities": len(findings),
                    "average_security_score": self._calculate_average_security_score(repositories),
                    "risk_distribution": self._calculate_risk_distribution(repositories)
                }
            }

            if report_type == "detailed":
                report["detailed_analysis"] = {
                    "repository_breakdown": self._analyze_repository_security(repositories),
                    "vulnerability_analysis": self._analyze_vulnerability_patterns(findings),
                    "security_trends": self._analyze_security_trends(repositories) if include_trends else None
                }

            if report_type == "executive":
                report["executive_summary"] = {
                    "key_findings": self._generate_key_findings(repositories, findings),
                    "risk_assessment": self._generate_executive_risk_assessment(repositories, findings),
                    "recommendations": self._generate_executive_recommendations(repositories, findings)
                }

            if include_comparison:
                report["industry_comparison"] = self._generate_industry_comparison(repositories)

            return report

        except Exception as e:
            debug_print(f"Error in _generate_code_security_report: {e}")
            return {
                "error": str(e),
                "message": "Failed to generate code security report"
            }

    async def _map_attack_surface(self, org_id: str, include_internal: bool = True, include_external: bool = True, include_third_party: bool = True, risk_visualization: bool = True, **kwargs) -> Dict[str, Any]:
        """Map the complete attack surface including repositories, applications, and entry points"""
        try:
            attack_surface = {
                "organizationId": org_id,
                "mapped_at": datetime.now().isoformat(),
                "attack_vectors": {
                    "repositories": [],
                    "applications": [],
                    "external_endpoints": [],
                    "internal_services": [],
                    "third_party_integrations": []
                },
                "risk_heatmap": {},
                "entry_points": []
            }

            # Map repositories
            try:
                repos_response = await self.client.list_repositories(org_id, pageSize=100)
                repositories = repos_response.get("repositories", [])
                
                for repo in repositories:
                    attack_vector = {
                        "id": repo.get("id"),
                        "name": repo.get("name"),
                        "type": "repository",
                        "risk_level": self._assess_repository_risk(repo),
                        "exposure": "internal" if repo.get("visibility") == "private" else "external",
                        "vulnerabilities": repo.get("vulnerabilityCount", 0)
                    }
                    attack_surface["attack_vectors"]["repositories"].append(attack_vector)
            except Exception as e:
                debug_print(f"Error mapping repositories: {e}")

            # Map applications
            try:
                apps_response = await self.client.list_applications(org_id, pageSize=100)
                applications = apps_response.get("applications", [])
                
                for app in applications:
                    attack_vector = {
                        "id": app.get("id"),
                        "name": app.get("name"),
                        "type": "application",
                        "environment": app.get("environment"),
                        "exposure": "external" if app.get("environment") == "prod" else "internal",
                        "host": app.get("host"),
                        "vulnerabilities": 0  # Would need to be calculated from findings
                    }
                    attack_surface["attack_vectors"]["applications"].append(attack_vector)
            except Exception as e:
                debug_print(f"Error mapping applications: {e}")

            # Generate risk heatmap
            if risk_visualization:
                attack_surface["risk_heatmap"] = self._generate_risk_heatmap(attack_surface["attack_vectors"])

            # Identify entry points
            attack_surface["entry_points"] = self._identify_entry_points(attack_surface["attack_vectors"])

            return attack_surface

        except Exception as e:
            debug_print(f"Error in _map_attack_surface: {e}")
            return {
                "error": str(e),
                "message": "Failed to map attack surface"
            }

    # Helper methods for threat surface analysis
    def _calculate_threat_surface_risk(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall threat surface risk score"""
        risk_score = 0.0
        
        # Repository risk
        repos = analysis.get("repositories", {})
        if "total_repositories" in repos:
            risk_score += repos["total_repositories"] * 0.1
        
        # Application risk
        apps = analysis.get("applications", {})
        if "total_applications" in apps:
            risk_score += apps["total_applications"] * 0.2
        
        # Vulnerability risk
        vulns = analysis.get("vulnerabilities", {})
        if "total_vulnerabilities" in vulns:
            risk_score += vulns["total_vulnerabilities"] * 0.5
        
        return min(risk_score, 100.0)

    def _identify_risk_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []
        
        vulns = analysis.get("vulnerabilities", {})
        if vulns.get("high_severity_findings", 0) > 0:
            risk_factors.append("High-severity vulnerabilities present")
        
        apps = analysis.get("applications", {})
        if apps.get("production_apps", 0) > 10:
            risk_factors.append("Large production footprint")
        
        repos = analysis.get("repositories", {})
        if repos.get("total_repositories", 0) > 50:
            risk_factors.append("High number of repositories")
        
        return risk_factors

    def _generate_risk_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        vulns = analysis.get("vulnerabilities", {})
        if vulns.get("high_severity_findings", 0) > 0:
            recommendations.append("Prioritize remediation of high-severity vulnerabilities")
        
        apps = analysis.get("applications", {})
        if apps.get("production_apps", 0) > 10:
            recommendations.append("Implement automated security scanning for production applications")
        
        return recommendations

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 70:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

    def _assess_repository_risk(self, repo: Dict[str, Any]) -> str:
        """Assess risk level for a repository"""
        score = repo.get("securityScore", 100)
        vuln_count = repo.get("vulnerabilityCount", 0)
        
        if score < 30 or vuln_count > 10:
            return "High"
        elif score < 70 or vuln_count > 5:
            return "Medium"
        else:
            return "Low"

    def _meets_risk_threshold(self, risk_level: str, threshold: str) -> bool:
        """Check if risk level meets threshold"""
        risk_scores = {"low": 1, "medium": 2, "high": 3}
        return risk_scores.get(risk_level, 0) >= risk_scores.get(threshold, 0)

    def _risk_level_score(self, risk_level: str) -> int:
        """Convert risk level to numeric score for sorting"""
        return {"low": 1, "medium": 2, "high": 3}.get(risk_level, 0)

    def _identify_repository_risk_factors(self, repo: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors for a repository"""
        factors = []
        
        if repo.get("securityScore", 100) < 50:
            factors.append("Low security score")
        
        if repo.get("vulnerabilityCount", 0) > 5:
            factors.append("High vulnerability count")
        
        if repo.get("lastScanDate") is None:
            factors.append("No recent security scan")
        
        return factors

    def _generate_repository_remediation(self, repo: Dict[str, Any]) -> List[str]:
        """Generate remediation recommendations for a repository"""
        recommendations = []
        
        if repo.get("securityScore", 100) < 50:
            recommendations.append("Implement automated security scanning")
        
        if repo.get("vulnerabilityCount", 0) > 5:
            recommendations.append("Prioritize vulnerability remediation")
        
        if repo.get("lastScanDate") is None:
            recommendations.append("Schedule regular security scans")
        
        return recommendations

    def _calculate_average_security_score(self, repositories: List[Dict[str, Any]]) -> float:
        """Calculate average security score across repositories"""
        if not repositories:
            return 0.0
        
        total_score = sum(repo.get("securityScore", 100) for repo in repositories)
        return total_score / len(repositories)

    def _calculate_risk_distribution(self, repositories: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate risk distribution across repositories"""
        distribution = {"high": 0, "medium": 0, "low": 0}
        
        for repo in repositories:
            risk_level = self._assess_repository_risk(repo)
            distribution[risk_level] += 1
        
        return distribution

    def _analyze_repository_security(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security patterns across repositories"""
        return {
            "security_score_distribution": self._calculate_risk_distribution(repositories),
            "average_score": self._calculate_average_security_score(repositories),
            "scan_coverage": len([r for r in repositories if r.get("lastScanDate")]) / len(repositories) if repositories else 0
        }

    def _analyze_vulnerability_patterns(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability patterns"""
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding.get("findingRisk")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "severity_distribution": severity_counts,
            "total_findings": len(findings),
            "critical_findings": severity_counts["High"]
        }

    def _analyze_security_trends(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security trends over time"""
        # This would need actual time-series data
        return {
            "trend_analysis": "Not enough historical data",
            "recommendation": "Enable continuous monitoring for trend analysis"
        }

    def _generate_key_findings(self, repositories: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> List[str]:
        """Generate key findings for executive report"""
        findings_list = []
        
        high_risk_repos = len([r for r in repositories if self._assess_repository_risk(r) == "high"])
        if high_risk_repos > 0:
            findings_list.append(f"{high_risk_repos} repositories identified as high risk")
        
        critical_vulns = len([f for f in findings if f.get("findingRisk") == "High"])
        if critical_vulns > 0:
            findings_list.append(f"{critical_vulns} critical vulnerabilities require immediate attention")
        
        return findings_list

    def _generate_executive_risk_assessment(self, repositories: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive risk assessment"""
        return {
            "overall_risk_level": self._determine_risk_level(self._calculate_threat_surface_risk({
                "repositories": {"total_repositories": len(repositories)},
                "vulnerabilities": {"total_vulnerabilities": len(findings)}
            })),
            "key_metrics": {
                "total_repositories": len(repositories),
                "total_vulnerabilities": len(findings),
                "high_risk_repositories": len([r for r in repositories if self._assess_repository_risk(r) == "high"])
            }
        }

    def _generate_executive_recommendations(self, repositories: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> List[str]:
        """Generate executive recommendations"""
        recommendations = []
        
        if len([r for r in repositories if self._assess_repository_risk(r) == "high"]) > 0:
            recommendations.append("Implement automated security scanning for high-risk repositories")
        
        if len([f for f in findings if f.get("findingRisk") == "High"]) > 0:
            recommendations.append("Establish vulnerability remediation SLA for critical issues")
        
        return recommendations

    def _generate_industry_comparison(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate industry comparison data"""
        avg_score = self._calculate_average_security_score(repositories)
        
        return {
            "organization_score": avg_score,
            "industry_average": 75.0,  # Placeholder
            "percentile": "top 25%" if avg_score > 80 else "average" if avg_score > 60 else "below average"
        }

    def _generate_risk_heatmap(self, attack_vectors: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate risk heatmap data"""
        heatmap = {
            "high_risk": [],
            "medium_risk": [],
            "low_risk": []
        }
        
        for vector_type, vectors in attack_vectors.items():
            for vector in vectors:
                risk_level = vector.get("risk_level", "low")
                heatmap[f"{risk_level}_risk"].append({
                    "id": vector.get("id"),
                    "name": vector.get("name"),
                    "type": vector_type,
                    "exposure": vector.get("exposure", "internal")
                })
        
        return heatmap

    def _identify_entry_points(self, attack_vectors: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Identify potential attack entry points"""
        entry_points = []
        
        # External applications
        for app in attack_vectors.get("applications", []):
            if app.get("exposure") == "external":
                entry_points.append({
                    "type": "external_application",
                    "name": app.get("name"),
                    "host": app.get("host"),
                    "risk_level": app.get("risk_level")
                })
        
        # Public repositories
        for repo in attack_vectors.get("repositories", []):
            if repo.get("exposure") == "external":
                entry_points.append({
                    "type": "public_repository",
                    "name": repo.get("name"),
                    "risk_level": repo.get("risk_level")
                })
        
        return entry_points

    async def _get_application_vulnerabilities(self, app_id: str, severity_filter: str = "All", include_remediation: bool = True, max_results: int = 100, **kwargs) -> Dict[str, Any]:
        """Get vulnerabilities for a specific application (not organization-wide)"""
        try:
            # Get organization ID from user info if not provided
            org_id = kwargs.get('org_id')
            if not org_id:
                user_info = await self.client.get_user_info()
                org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]

            # Use application-specific findings instead of organization-wide
            findings_params = {
                "pageSize": max_results
            }

            findings_response = await self.client.get_application_findings(app_id, org_id, **findings_params)
            findings = findings_response.get("findings", [])

            # Apply severity filter
            if severity_filter != "All":
                findings = [
                    f for f in findings
                    if f.get("findingRisk") == severity_filter
                ]

            # Get application details for context
            try:
                app_details = await self.client.get_application(app_id)
                app_name = app_details.get("name", "Unknown Application")
            except Exception as e:
                debug_print(f"Could not get application details: {e}")
                app_name = "Unknown Application"

            return {
                "applicationId": app_id,
                "applicationName": app_name,
                "organizationId": org_id,
                "severityFilter": severity_filter,
                "totalFindings": len(findings),
                "findings": findings,
                "severityBreakdown": self._calculate_severity_breakdown(findings),
                "timestamp": datetime.now().isoformat(),
                "note": "These are application-specific vulnerabilities filtered from organization-wide data"
            }

        except Exception as e:
            debug_print(f"Error in _get_application_vulnerabilities: {e}")
            return {
                "error": str(e),
                "message": "Failed to get application vulnerabilities",
                "applicationId": app_id
            }

    async def _get_application_security_summary(self, app_id: str, include_trends: bool = False, include_recommendations: bool = True, **kwargs) -> Dict[str, Any]:
        """Get security summary for a specific application"""
        try:
            # Get organization ID from user info if not provided
            org_id = kwargs.get('org_id')
            if not org_id:
                user_info = await self.client.get_user_info()
                org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]

            # Get application details
            app_details = await self.client.get_application(app_id)
            app_name = app_details.get("name", "Unknown Application")
            app_env = app_details.get("environment", "Unknown")

            # Get application-specific findings summary
            findings_response = await self.client.get_application_findings_summary(app_id, org_id)
            findings = findings_response.get("findings", [])

            # Calculate security metrics
            severity_counts = {"High": 0, "Medium": 0, "Low": 0}
            for finding in findings:
                severity = finding.get("findingRisk")
                if severity in severity_counts:
                    severity_counts[severity] += 1

            # Calculate security score (simplified)
            total_findings = len(findings)
            high_severity = severity_counts["High"]
            security_score = max(0, 100 - (high_severity * 20) - (severity_counts["Medium"] * 10) - (severity_counts["Low"] * 2))

            summary = {
                "applicationId": app_id,
                "applicationName": app_name,
                "organizationId": org_id,
                "environment": app_env,
                "securityMetrics": {
                    "totalVulnerabilities": total_findings,
                    "securityScore": security_score,
                    "severityBreakdown": severity_counts,
                    "criticalFindings": high_severity
                },
                "lastScan": app_details.get("lastScanDate"),
                "status": app_details.get("status", "Unknown")
            }

            if include_recommendations:
                summary["recommendations"] = self._generate_application_recommendations(severity_counts, security_score)

            if include_trends:
                summary["trends"] = {
                    "note": "Trend analysis requires historical data",
                    "recommendation": "Enable continuous monitoring for trend analysis"
                }

            summary["timestamp"] = datetime.now().isoformat()
            summary["note"] = "This is application-specific data filtered from organization-wide findings"

            return summary

        except Exception as e:
            debug_print(f"Error in _get_application_security_summary: {e}")
            return {
                "error": str(e),
                "message": "Failed to get application security summary",
                "applicationId": app_id
            }

    async def _compare_application_security(self, org_id: str, app_ids: List[str], comparison_metrics: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Compare security posture across multiple applications"""
        try:
            if comparison_metrics is None:
                comparison_metrics = ["vulnerability_count", "severity_distribution"]

            comparison_results = {
                "organizationId": org_id,
                "applications": [],
                "comparison": {},
                "timestamp": datetime.now().isoformat()
            }

            # Get security data for each application
            for app_id in app_ids:
                try:
                    app_summary = await self._get_application_security_summary(app_id, include_recommendations=False)
                    comparison_results["applications"].append(app_summary)
                except Exception as e:
                    debug_print(f"Error getting data for app {app_id}: {e}")
                    comparison_results["applications"].append({
                        "applicationId": app_id,
                        "error": str(e)
                    })

            # Generate comparison metrics
            if "vulnerability_count" in comparison_metrics:
                comparison_results["comparison"]["vulnerabilityCounts"] = {
                    app["applicationName"]: app.get("securityMetrics", {}).get("totalVulnerabilities", 0)
                    for app in comparison_results["applications"]
                    if "error" not in app
                }

            if "severity_distribution" in comparison_metrics:
                comparison_results["comparison"]["severityDistribution"] = {
                    app["applicationName"]: app.get("securityMetrics", {}).get("severityBreakdown", {})
                    for app in comparison_results["applications"]
                    if "error" not in app
                }

            if "security_score" in comparison_metrics:
                comparison_results["comparison"]["securityScores"] = {
                    app["applicationName"]: app.get("securityMetrics", {}).get("securityScore", 0)
                    for app in comparison_results["applications"]
                    if "error" not in app
                }

            # Add insights
            comparison_results["insights"] = self._generate_comparison_insights(comparison_results["applications"])

            return comparison_results

        except Exception as e:
            debug_print(f"Error in _compare_application_security: {e}")
            return {
                "error": str(e),
                "message": "Failed to compare application security",
                "organizationId": org_id
            }

    def _calculate_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity breakdown for findings"""
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding.get("findingRisk")
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts

    def _generate_application_recommendations(self, severity_counts: Dict[str, int], security_score: float) -> List[str]:
        """Generate security recommendations for an application"""
        recommendations = []

        if severity_counts["High"] > 0:
            recommendations.append(f"Prioritize remediation of {severity_counts['High']} high-severity vulnerabilities")

        if severity_counts["Medium"] > 5:
            recommendations.append(f"Address {severity_counts['Medium']} medium-severity vulnerabilities")

        if security_score < 50:
            recommendations.append("Implement automated security scanning in CI/CD pipeline")

        if security_score < 30:
            recommendations.append("Consider security code review and training for development team")

        return recommendations

    def _generate_comparison_insights(self, applications: List[Dict[str, Any]]) -> List[str]:
        """Generate insights from application comparison"""
        insights = []
        
        # Find applications with highest vulnerability counts
        app_vulns = [(app.get("applicationName", "Unknown"), 
                     app.get("securityMetrics", {}).get("totalVulnerabilities", 0))
                    for app in applications if "error" not in app]
        
        if app_vulns:
            max_vulns_app = max(app_vulns, key=lambda x: x[1])
            if max_vulns_app[1] > 0:
                insights.append(f"{max_vulns_app[0]} has the highest vulnerability count ({max_vulns_app[1]})")

        # Find applications with lowest security scores
        app_scores = [(app.get("applicationName", "Unknown"), 
                      app.get("securityMetrics", {}).get("securityScore", 100))
                     for app in applications if "error" not in app]
        
        if app_scores:
            min_score_app = min(app_scores, key=lambda x: x[1])
            if min_score_app[1] < 70:
                insights.append(f"{min_score_app[0]} has the lowest security score ({min_score_app[1]})")

        return insights

    # Sensitive Data Analysis Methods
    async def _get_sensitive_data_report(self, org_id: str, data_type_filter: str = "All", time_range: str = "30d", include_details: bool = True, group_by: str = "data_type", **kwargs) -> Dict[str, Any]:
        """Generate comprehensive sensitive data report for an organization"""
        try:
            # For all-time reports, fetch all results to get complete picture
            if time_range == "all":
                findings_response = await self.client.list_sensitive_data_findings(org_id, all_results=True)
                findings = findings_response.get("sensitiveDataFindings", [])
            else:
                # For time-limited reports, use pagination to get a reasonable sample
                findings_params = {"pageSize": 1000}
                findings_response = await self.client.list_sensitive_data_findings(org_id, **findings_params)
                findings = findings_response.get("sensitiveDataFindings", [])

            # Apply client-side filters
            filtered_findings = findings

            if data_type_filter != "All":
                filtered_findings = [
                    f for f in filtered_findings
                    if f.get("dataType") == data_type_filter
                ]

            if time_range != "all":
                time_filter = {
                    "startDate": (datetime.now() - timedelta(days=int(time_range[:-1]))).isoformat(),
                    "endDate": datetime.now().isoformat()
                }
                filtered_findings = [
                    f for f in filtered_findings
                    if f.get("findingDate") >= time_filter["startDate"] and f.get("findingDate") <= time_filter["endDate"]
                ]

            # Group findings
            grouped_findings = {}
            for finding in filtered_findings:
                group_key = finding.get(group_by)
                if group_key not in grouped_findings:
                    grouped_findings[group_key] = []
                grouped_findings[group_key].append(finding)

            # Format findings
            formatted_findings = []
            for group, findings in grouped_findings.items():
                formatted_findings.append({
                    "group": group,
                    "findings": findings
                })

            return {
                "organizationId": org_id,
                "dataTypeFilter": data_type_filter,
                "timeRange": time_range,
                "report": formatted_findings,
                "totalFindings": len(filtered_findings),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _get_sensitive_data_report: {e}")
            raise

    async def _analyze_sensitive_data_trends(self, org_id: str, analysis_period: str = "90d", include_applications: bool = True, include_repositories: bool = True, **kwargs) -> Dict[str, Any]:
        """Analyze sensitive data exposure trends and patterns"""
        try:
            # For trend analysis, we want comprehensive data
            findings_response = await self.client.list_sensitive_data_findings(org_id, all_results=True)
            findings = findings_response.get("sensitiveDataFindings", [])

            # Group findings by application and repository
            application_findings = {}
            repository_findings = {}
            
            for finding in findings:
                app_id = finding.get("applicationId")
                repo_id = finding.get("repositoryId")
                
                if app_id and include_applications:
                    if app_id not in application_findings:
                        application_findings[app_id] = []
                    application_findings[app_id].append(finding)
                
                if repo_id and include_repositories:
                    if repo_id not in repository_findings:
                        repository_findings[repo_id] = []
                    repository_findings[repo_id].append(finding)

            # Analyze trends
            trends = {
                "totalFindings": len(findings),
                "dataTypeBreakdown": {},
                "applicationTrends": [],
                "repositoryTrends": []
            }

            # Data type breakdown
            for finding in findings:
                data_type = finding.get("dataType", "Unknown")
                if data_type not in trends["dataTypeBreakdown"]:
                    trends["dataTypeBreakdown"][data_type] = 0
                trends["dataTypeBreakdown"][data_type] += 1

            # Application trends
            if include_applications:
                for app_id, app_findings in application_findings.items():
                    trends["applicationTrends"].append({
                        "applicationId": app_id,
                        "totalFindings": len(app_findings),
                        "dataTypeBreakdown": {}
                    })
                    for finding in app_findings:
                        data_type = finding.get("dataType", "Unknown")
                        if data_type not in trends["applicationTrends"][-1]["dataTypeBreakdown"]:
                            trends["applicationTrends"][-1]["dataTypeBreakdown"][data_type] = 0
                        trends["applicationTrends"][-1]["dataTypeBreakdown"][data_type] += 1

            # Repository trends
            if include_repositories:
                for repo_id, repo_findings in repository_findings.items():
                    trends["repositoryTrends"].append({
                        "repositoryId": repo_id,
                        "totalFindings": len(repo_findings),
                        "dataTypeBreakdown": {}
                    })
                    for finding in repo_findings:
                        data_type = finding.get("dataType", "Unknown")
                        if data_type not in trends["repositoryTrends"][-1]["dataTypeBreakdown"]:
                            trends["repositoryTrends"][-1]["dataTypeBreakdown"][data_type] = 0
                        trends["repositoryTrends"][-1]["dataTypeBreakdown"][data_type] += 1

            return {
                "organizationId": org_id,
                "analysisPeriod": analysis_period,
                "trends": trends,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _analyze_sensitive_data_trends: {e}")
            raise

    async def _get_critical_sensitive_data(self, org_id: str, data_types: List[str] = None, include_remediation: bool = True, max_results: int = 50, **kwargs) -> Dict[str, Any]:
        """Get critical sensitive data findings requiring immediate attention"""
        try:
            if data_types is None:
                data_types = ["PII", "PCI", "PHI"]

            # For critical findings, we want to see ALL critical findings, not just the first page
            findings_response = await self.client.list_sensitive_data_findings(org_id, all_results=True)
            findings = findings_response.get("sensitiveDataFindings", [])

            # Filter findings based on data types
            filtered_findings = [
                f for f in findings
                if f.get("dataType") in data_types
            ]

            # Include remediation details
            if include_remediation:
                for finding in filtered_findings:
                    finding["remediation"] = finding.get("remediationDetails", "No remediation details available")

            return {
                "organizationId": org_id,
                "dataTypes": data_types,
                "findings": filtered_findings,
                "totalFindings": len(filtered_findings),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _get_critical_sensitive_data: {e}")
            raise

    async def _generate_sensitive_data_summary(self, org_id: str, time_period: str = "30d", include_recommendations: bool = True, include_risk_assessment: bool = True, **kwargs) -> Dict[str, Any]:
        """Generate executive-level sensitive data summary and recommendations"""
        try:
            # For all-time reports, fetch all results to get complete picture
            if time_period == "all":
                findings_response = await self.client.list_sensitive_data_findings(org_id, all_results=True)
                findings = findings_response.get("sensitiveDataFindings", [])
            else:
                # For time-limited reports, use pagination to get a reasonable sample
                findings_params = {"pageSize": 1000}
                findings_response = await self.client.list_sensitive_data_findings(org_id, **findings_params)
                findings = findings_response.get("sensitiveDataFindings", [])

            # Group findings by data type
            data_type_findings = {"PII": [], "PCI": [], "PHI": [], "Other": []}
            for finding in findings:
                data_type = finding.get("dataType", "Other")
                if data_type in data_type_findings:
                    data_type_findings[data_type].append(finding)
                else:
                    data_type_findings["Other"].append(finding)

            # Generate summary
            summary = {
                "totalFindings": len(findings),
                "dataTypeBreakdown": data_type_findings
            }

            # Include recommendations
            if include_recommendations:
                summary["recommendations"] = [
                    {
                        "dataType": data_type,
                        "recommendation": f"Review and secure {data_type} data exposure"
                    }
                    for data_type, findings in data_type_findings.items()
                    if findings
                ]

            # Include risk assessment
            if include_risk_assessment:
                summary["riskAssessment"] = self._calculate_sensitive_data_risk_score(findings)

            return {
                "organizationId": org_id,
                "timePeriod": time_period,
                "summary": summary,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _generate_sensitive_data_summary: {e}")
            raise

    async def _get_application_sensitive_data(self, app_id: str, data_type_filter: str = "All", include_details: bool = True, max_results: int = 100, **kwargs) -> Dict[str, Any]:
        """Get sensitive data findings for a specific application"""
        try:
            # Get organization ID from user info if not provided
            org_id = kwargs.get('org_id')
            if not org_id:
                user_info = await self.client.get_user_info()
                org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]

            # Use application-specific sensitive data findings
            findings_params = {
                "pageSize": max_results
            }

            findings_response = await self.client.get_application_sensitive_data(app_id, org_id, **findings_params)
            findings = findings_response.get("sensitiveDataFindings", [])

            # Apply data type filter
            if data_type_filter != "All":
                findings = [
                    f for f in findings
                    if f.get("dataType") == data_type_filter
                ]

            # Get application details for context
            try:
                app_details = await self.client.get_application(app_id)
                app_name = app_details.get("name", "Unknown Application")
            except Exception as e:
                debug_print(f"Could not get application details: {e}")
                app_name = "Unknown Application"

            return {
                "applicationId": app_id,
                "applicationName": app_name,
                "organizationId": org_id,
                "dataTypeFilter": data_type_filter,
                "totalFindings": len(findings),
                "findings": findings,
                "dataTypeBreakdown": self._calculate_data_type_breakdown(findings),
                "timestamp": datetime.now().isoformat(),
                "note": "These are application-specific sensitive data findings"
            }

        except Exception as e:
            debug_print(f"Error in _get_application_sensitive_data: {e}")
            return {
                "error": str(e),
                "message": "Failed to get application sensitive data",
                "applicationId": app_id
            }

    async def _get_repository_sensitive_data(self, org_id: str, repo_id: str, data_type_filter: str = "All", include_details: bool = True, max_results: int = 100, **kwargs) -> Dict[str, Any]:
        """Get sensitive data findings for a specific repository"""
        try:
            findings_params = {
                "pageSize": max_results
            }

            findings_response = await self.client.get_repository_sensitive_data(org_id, repo_id, **findings_params)
            findings = findings_response.get("sensitiveDataFindings", [])

            # Apply data type filter
            if data_type_filter != "All":
                findings = [
                    f for f in findings
                    if f.get("dataType") == data_type_filter
                ]

            # Get repository details for context
            try:
                repo_details = await self.client.get_repository_details(org_id, repo_id)
                repo_name = repo_details.get("name", "Unknown Repository")
            except Exception as e:
                debug_print(f"Could not get repository details: {e}")
                repo_name = "Unknown Repository"

            return {
                "repositoryId": repo_id,
                "repositoryName": repo_name,
                "organizationId": org_id,
                "dataTypeFilter": data_type_filter,
                "totalFindings": len(findings),
                "findings": findings,
                "dataTypeBreakdown": self._calculate_data_type_breakdown(findings),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            debug_print(f"Error in _get_repository_sensitive_data: {e}")
            return {
                "error": str(e),
                "message": "Failed to get repository sensitive data",
                "repositoryId": repo_id,
                "organizationId": org_id
            }

    async def _get_sensitive_data_types(self, org_id: str, **kwargs) -> Dict[str, Any]:
        """Get available sensitive data types and categories"""
        try:
            types_response = await self.client.get_sensitive_data_types(org_id)
            return {
                "organizationId": org_id,
                "sensitiveDataTypes": types_response,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            debug_print(f"Error in _get_sensitive_data_types: {e}")
            return {
                "error": str(e),
                "message": "Failed to get sensitive data types",
                "organizationId": org_id
            }

    async def _map_sensitive_data_surface(self, org_id: str, include_applications: bool = True, include_repositories: bool = True, risk_visualization: bool = True, **kwargs) -> Dict[str, Any]:
        """Map sensitive data exposure across repositories and applications"""
        try:
            sensitive_data_surface = {
                "organizationId": org_id,
                "mapped_at": datetime.now().isoformat(),
                "exposure_vectors": {
                    "applications": [],
                    "repositories": []
                },
                "risk_heatmap": {},
                "data_type_distribution": {}
            }

            # Map application sensitive data
            if include_applications:
                try:
                    apps_response = await self.client.list_applications(org_id, pageSize=100)
                    applications = apps_response.get("applications", [])
                    
                    for app in applications:
                        try:
                            app_sensitive_data = await self.client.get_application_sensitive_data(app["id"], org_id, pageSize=50)
                            findings = app_sensitive_data.get("sensitiveDataFindings", [])
                            
                            exposure_vector = {
                                "id": app.get("id"),
                                "name": app.get("name"),
                                "type": "application",
                                "environment": app.get("environment"),
                                "sensitive_data_count": len(findings),
                                "data_types": list(set(f.get("dataType") for f in findings if f.get("dataType")))
                            }
                            sensitive_data_surface["exposure_vectors"]["applications"].append(exposure_vector)
                        except Exception as e:
                            debug_print(f"Error getting sensitive data for app {app.get('id')}: {e}")
                except Exception as e:
                    debug_print(f"Error mapping application sensitive data: {e}")

            # Map repository sensitive data
            if include_repositories:
                try:
                    repos_response = await self.client.list_repositories(org_id, pageSize=100)
                    repositories = repos_response.get("repositories", [])
                    
                    for repo in repositories:
                        try:
                            repo_sensitive_data = await self.client.get_repository_sensitive_data(org_id, repo["id"], pageSize=50)
                            findings = repo_sensitive_data.get("sensitiveDataFindings", [])
                            
                            exposure_vector = {
                                "id": repo.get("id"),
                                "name": repo.get("name"),
                                "type": "repository",
                                "status": repo.get("status"),
                                "sensitive_data_count": len(findings),
                                "data_types": list(set(f.get("dataType") for f in findings if f.get("dataType")))
                            }
                            sensitive_data_surface["exposure_vectors"]["repositories"].append(exposure_vector)
                        except Exception as e:
                            debug_print(f"Error getting sensitive data for repo {repo.get('id')}: {e}")
                except Exception as e:
                    debug_print(f"Error mapping repository sensitive data: {e}")

            # Generate risk heatmap
            if risk_visualization:
                sensitive_data_surface["risk_heatmap"] = self._generate_sensitive_data_risk_heatmap(sensitive_data_surface["exposure_vectors"])

            # Calculate data type distribution
            sensitive_data_surface["data_type_distribution"] = self._calculate_overall_data_type_distribution(sensitive_data_surface["exposure_vectors"])

            return sensitive_data_surface

        except Exception as e:
            debug_print(f"Error in _map_sensitive_data_surface: {e}")
            return {
                "error": str(e),
                "message": "Failed to map sensitive data surface",
                "organizationId": org_id
            }

    # Helper methods for sensitive data analysis
    def _calculate_sensitive_data_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on sensitive data findings"""
        risk_score = 0.0
        
        # Weight different data types
        data_type_weights = {
            "PII": 1.0,
            "PCI": 2.0,
            "PHI": 3.0
        }
        
        for finding in findings:
            data_type = finding.get("dataType", "Other")
            weight = data_type_weights.get(data_type, 0.5)
            risk_score += weight
        
        return min(risk_score, 100.0)

    def _calculate_data_type_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate data type breakdown for findings"""
        breakdown = {}
        for finding in findings:
            data_type = finding.get("dataType", "Unknown")
            if data_type not in breakdown:
                breakdown[data_type] = 0
            breakdown[data_type] += 1
        return breakdown

    def _generate_sensitive_data_risk_heatmap(self, exposure_vectors: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate risk heatmap data for sensitive data exposure"""
        heatmap = {
            "high_risk": [],
            "medium_risk": [],
            "low_risk": []
        }
        
        for vector_type, vectors in exposure_vectors.items():
            for vector in vectors:
                risk_level = self._assess_sensitive_data_risk(vector)
                heatmap[f"{risk_level}_risk"].append({
                    "id": vector.get("id"),
                    "name": vector.get("name"),
                    "type": vector_type,
                    "sensitive_data_count": vector.get("sensitive_data_count", 0),
                    "data_types": vector.get("data_types", [])
                })
        
        return heatmap

    def _assess_sensitive_data_risk(self, vector: Dict[str, Any]) -> str:
        """Assess risk level for sensitive data exposure"""
        data_count = vector.get("sensitive_data_count", 0)
        data_types = vector.get("data_types", [])
        
        # High risk if PHI is present or high count of sensitive data
        if "PHI" in data_types or data_count > 10:
            return "high"
        elif "PCI" in data_types or data_count > 5:
            return "medium"
        else:
            return "low"

    def _calculate_overall_data_type_distribution(self, exposure_vectors: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
        """Calculate overall data type distribution across all vectors"""
        distribution = {}
        
        for vector_type, vectors in exposure_vectors.items():
            for vector in vectors:
                data_types = vector.get("data_types", [])
                for data_type in data_types:
                    if data_type not in distribution:
                        distribution[data_type] = 0
                    distribution[data_type] += 1
        
        return distribution

    async def _get_project_open_stackhawk_issues(self, config_path: str = None) -> dict:
        """Discover StackHawk config, extract applicationId, and summarize open issues for the app."""
        import os
        import yaml
        
        # 1. Discover config file if not provided
        if not config_path:
            candidates = glob.glob("stackhawk.y*ml") + glob.glob("stackhawk*.y*ml")
            if not candidates:
                return {"error": "No StackHawk config file found in current directory."}
            config_path = candidates[0]
        if not os.path.exists(config_path):
            return {"error": f"Config file not found: {config_path}"}
        
        # 2. Parse config for applicationId and failureThreshold
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            app_id = config.get("app", {}).get("applicationId")
            if not app_id:
                return {"error": f"No applicationId found in {config_path}"}
            # Always look for failureThreshold in hawk section
            failure_threshold = None
            if "hawk" in config and "failureThreshold" in config["hawk"]:
                failure_threshold = config["hawk"]["failureThreshold"]
            # Normalize threshold (capitalize)
            if failure_threshold:
                failure_threshold = failure_threshold.capitalize()
        except Exception as e:
            return {"error": f"Failed to parse config: {e}"}
        
        # 3. Fetch open vulnerabilities for this app
        try:
            result = await self._get_application_vulnerabilities(app_id, severity_filter="All", max_results=1000)
            findings = result.get("findings", [])
            # Only include findings that are High, Medium, or >= failureThreshold
            allowed_severities = ["High", "Medium"]
            if failure_threshold and failure_threshold not in allowed_severities:
                allowed_severities.append(failure_threshold)
            filtered_findings = [f for f in findings if f.get("findingRisk") in allowed_severities]
            return {
                "config_path": config_path,
                "applicationId": app_id,
                "failureThreshold": failure_threshold or "High/Medium",
                "open_issues_summary": self._calculate_severity_breakdown(filtered_findings),
                "totalOpenIssues": len(filtered_findings),
                "openIssues": filtered_findings,
                "note": "Returned issues are High, Medium, or at/above the configured failureThreshold (if set in hawk section) so chat can help fix them."
            }
        except Exception as e:
            return {"error": f"Failed to fetch vulnerabilities: {e}"}

    def _detect_project_language_and_frameworks(self) -> dict:
        """Detect the programming language and frameworks used in the current project"""
        import os
        
        language = "unknown"
        frameworks = []
        
        # Check for common project files
        if os.path.exists("package.json"):
            language = "javascript"
            try:
                with open("package.json", "r") as f:
                    import json
                    data = json.load(f)
                    dependencies = data.get("dependencies", {})
                    dev_dependencies = data.get("devDependencies", {})
                    
                    if "express" in dependencies:
                        frameworks.append("express")
                    if "react" in dependencies:
                        frameworks.append("react")
                    if "vue" in dependencies:
                        frameworks.append("vue")
                    if "angular" in dependencies:
                        frameworks.append("angular")
                    if "next" in dependencies:
                        frameworks.append("next")
                    if "nuxt" in dependencies:
                        frameworks.append("nuxt")
            except:
                pass
        elif os.path.exists("requirements.txt") or os.path.exists("pyproject.toml"):
            language = "python"
            if os.path.exists("requirements.txt"):
                try:
                    with open("requirements.txt", "r") as f:
                        content = f.read().lower()
                        if "django" in content:
                            frameworks.append("django")
                        if "flask" in content:
                            frameworks.append("flask")
                        if "fastapi" in content:
                            frameworks.append("fastapi")
                        if "tornado" in content:
                            frameworks.append("tornado")
                except:
                    pass
        elif os.path.exists("pom.xml"):
            language = "java"
            try:
                with open("pom.xml", "r") as f:
                    content = f.read().lower()
                    if "spring-boot" in content:
                        frameworks.append("spring-boot")
                    if "spring" in content:
                        frameworks.append("spring")
            except:
                pass
        elif os.path.exists("go.mod"):
            language = "go"
        elif os.path.exists("Cargo.toml"):
            language = "rust"
        elif os.path.exists("Gemfile"):
            language = "ruby"
            try:
                with open("Gemfile", "r") as f:
                    content = f.read().lower()
                    if "rails" in content:
                        frameworks.append("rails")
                    if "sinatra" in content:
                        frameworks.append("sinatra")
            except:
                pass
        
        return {
            "language": language,
            "frameworks": frameworks
        }

    def _get_stackhawk_scan_instructions(self, config_path: str = "stackhawk.yml") -> str:
        """Get instructions for running StackHawk scans"""
        instructions = f"""
# StackHawk Scan Instructions

## Prerequisites
1. Install StackHawk CLI: `pip install stackhawk`
2. Ensure you have a valid StackHawk API key configured
3. Make sure your application is running and accessible

## Configuration
Your StackHawk configuration is located at: `{config_path}`

## Running Scans

### Basic Scan
```bash
hawk scan
```

### Scan with Custom Config
```bash
hawk scan --config {config_path}
```

### Scan with Environment Override
```bash
hawk scan --env production
```

### Scan with Custom Host
```bash
hawk scan --host https://your-app-domain.com
```

## Viewing Results
1. Check the StackHawk dashboard at https://app.stackhawk.com
2. Look for your application in the dashboard
3. Review findings and remediation recommendations

## Troubleshooting
- Ensure your application is running before starting the scan
- Check that the host and port in your config match your application
- Verify your API key has the correct permissions
- Check the scan logs for detailed error information

## Next Steps
1. Review and fix any vulnerabilities found
2. Set up automated scanning in your CI/CD pipeline
3. Configure alerts for new vulnerabilities
4. Regular security reviews and updates
"""
        return instructions

    async def _setup_stackhawk_for_project(self, org_id: str = None, app_name: str = None) -> dict:
        """Detect project language/frameworks, create StackHawk app, and return config info."""
        # 1. Detect language/frameworks
        detected = self._detect_project_language_and_frameworks()
        language = detected.get("language")
        frameworks = detected.get("frameworks")
        tech_flags = {"language": language, "frameworks": frameworks}

        # 2. Get org_id if not provided
        if not org_id:
            user_info = await self.client.get_user_info()
            orgs = user_info["user"]["external"]["organizations"]
            if not orgs:
                return {"error": "No organizations found for user."}
            org_id = orgs[0]["organization"]["id"]

        # 3. Use directory name as app_name if not provided
        if not app_name:
            app_name = os.path.basename(os.getcwd())

        # 4. Create application
        app_resp = await self.client.create_application(org_id, app_name, language, frameworks, tech_flags)
        app_id = app_resp.get("id")
        if not app_id:
            return {"error": "Failed to create application", "response": app_resp}

        # 5. Return info for config generation
        return {
            "success": True,
            "applicationId": app_id,
            "appName": app_name,
            "orgId": org_id,
            "language": language,
            "frameworks": frameworks,
            "techFlags": tech_flags,
            "appResponse": app_resp,
            "note": "Application created in StackHawk. Use this info to generate stackhawk.yml."
        }

    async def run(self):
        """Run the MCP server"""
        debug_print("Starting MCP server run...")
        try:
            async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
                debug_print("MCP stdio server created")
                await self.server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="stackhawk-mcp",
                        server_version="1.0.0",
                        capabilities=self.server.get_capabilities(
                            experimental_capabilities={},
                            notification_options=NotificationOptions()
                        )
                    )
                )
                debug_print("MCP server run completed")
        except Exception as e:
            debug_print(f"Error in run: {e}")
            raise

    async def cleanup(self):
        """Cleanup resources"""
        debug_print("Cleaning up StackHawk client...")
        await self.client.close()


async def main():
    """Main entry point"""
    debug_print("=== StackHawk MCP Server Starting ===")

    import os

    api_key = os.environ.get("STACKHAWK_API_KEY")
    if not api_key:
        debug_print("ERROR: STACKHAWK_API_KEY environment variable is required")
        sys.exit(1)

    debug_print(f"API key found: {api_key[:20]}...")

    server = None
    try:
        debug_print("Creating StackHawkMCPServer...")
        server = StackHawkMCPServer(api_key)
        debug_print("Running server...")
        await server.run()
    except KeyboardInterrupt:
        debug_print("Server stopped by user")
    except Exception as e:
        debug_print(f"Server error: {e}")
        import traceback
        debug_print(f"Traceback: {traceback.format_exc()}")
        raise
    finally:
        if server:
            await server.cleanup()
        debug_print("=== StackHawk MCP Server Ended ===")


if __name__ == "__main__":
    asyncio.run(main())