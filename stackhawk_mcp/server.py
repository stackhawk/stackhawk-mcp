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
import subprocess

import httpx
import yaml
from jsonschema import validate, ValidationError
from mcp.server import Server
from mcp.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.types import Resource, Tool, TextContent, ImageContent, EmbeddedResource, LoggingLevel
import mcp.server.stdio
import mcp.types as types
from stackhawk_mcp import __version__

# Configure logging to stderr so Claude Desktop can see it
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("stackhawk-mcp")

STACKHAWK_MCP_VERSION = __version__


def debug_print(message):
    """Print debug messages to stderr for Claude Desktop"""
    print(f"[DEBUG] {message}", file=sys.stderr, flush=True)


class StackHawkClient:
    """Client for interacting with the StackHawk API"""

    # List of valid tech flags from StackHawk documentation
    VALID_TECH_FLAGS = {
        "Db",
        "Db.MySQL",
        "Db.PostgreSQL",
        "Db.Microsoft SQL Server",
        "Db.Oracle",
        "Db.SQLite",
        "Db.Microsoft Access",
        "Db.Firebird",
        "Db.SAP MaxDB",
        "Db.Sybase",
        "Db.IBM DB2",
        "Db.HypersonicSQL",
        "Db.MongoDB",
        "Db.CouchDB",
        "Language",
        "Language.ASP",
        "Language.C",
        "Language.Java",
        "Language.Java.Spring",
        "Language.JavaScript",
        "Language.JSP/Servlet",
        "Language.PHP",
        "Language.Python",
        "Language.Ruby",
        "Language.XML",
        "OS",
        "OS.Linux",
        "OS.MacOS",
        "OS.Windows",
        "SCM",
        "SCM.Git",
        "SCM.SVN",
        "WS",
        "WS.Apache",
        "WS.IIS",
    }

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
                timeout=30.0, headers={"User-Agent": f"StackHawk-MCP/{STACKHAWK_MCP_VERSION}"}
            )
        return self._client

    async def _ensure_authenticated(self):
        """Ensure we have a valid access token"""
        if (
            not self._authenticated
            or not self.access_token
            or (self.token_expires_at and datetime.now() >= self.token_expires_at)
        ):
            await self._authenticate()

    async def _authenticate(self):
        """Authenticate with the StackHawk API"""
        try:
            client = await self._get_client()
            response = await client.get(
                f"{self.base_url}/api/v1/auth/login", headers={"X-ApiKey": self.api_key}
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

    async def list_organization_findings(
        self, org_id: str, all_results: bool = False, **params
    ) -> Dict[str, Any]:
        """List organization-wide findings, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=params)

    async def get_organization_findings_detailed(
        self, org_id: str, all_results: bool = False, **params
    ) -> Dict[str, Any]:
        """Get detailed organization findings with comprehensive filtering options and optional pagination."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"findings": findings}
        else:
            default_params = {"pageSize": 100}
            default_params.update(params)
            return await self._make_request("GET", endpoint, params=default_params)

    async def get_application_findings(
        self, app_id: str, org_id: str, all_results: bool = False, **params
    ) -> Dict[str, Any]:
        """Get findings for a specific application, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        default_params = {"pageSize": 100, "appIds": app_id}
        default_params.update(params)
        if all_results:
            findings = await self._fetch_all_pages(endpoint, default_params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=default_params)

    async def get_application_findings_summary(
        self, app_id: str, org_id: str, all_results: bool = False, **params
    ) -> Dict[str, Any]:
        """Get summary of findings for a specific application, with optional pagination for all results."""
        endpoint = f"/api/v1/reports/org/{org_id}/findings"
        default_params = {"pageSize": 50, "appIds": app_id}
        default_params.update(params)
        if all_results:
            findings = await self._fetch_all_pages(endpoint, default_params)
            return {"findings": findings}
        else:
            return await self._make_request("GET", endpoint, params=default_params)

    async def list_teams(self, org_id: str, **params) -> Dict[str, Any]:
        """List teams for an organization"""
        return await self._make_request("GET", f"/api/v1/org/{org_id}/teams", params=params)

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

            debug_print(
                f"Page {page_count}: got {len(findings)} findings, total so far: {len(all_findings)}"
            )

            if len(findings) < page_size:
                debug_print(f"No more pages, total findings: {len(all_findings)}")
                break
            page_token += 1

        return all_findings

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
        abs_config_path = os.path.abspath(config_path)
        print(f"[DEBUG] Looking for config at: {abs_config_path}")
        if not os.path.exists(abs_config_path):
            print(f"[DEBUG] File not found: {abs_config_path}")
            return {"error": f"Config file not found: {abs_config_path}"}

        # 2. Parse config for applicationId and failureThreshold
        try:
            with open(abs_config_path, "r") as f:
                config = yaml.safe_load(f)
            app_id = config.get("app", {}).get("applicationId")
            if not app_id:
                return {"error": f"No applicationId found in {abs_config_path}"}
            # Always look for failureThreshold in hawk section
            failure_threshold = None
            if "hawk" in config and "failureThreshold" in config["hawk"]:
                failure_threshold = config["hawk"]["failureThreshold"]
            # Normalize threshold (capitalize)
            if failure_threshold:
                failure_threshold = failure_threshold.capitalize()
        except Exception as e:
            print(f"[DEBUG] Error parsing config: {e}")
            return {"error": f"Failed to parse config: {e}"}

        # 3. Fetch open vulnerabilities for this app
        try:
            result = await self._get_application_vulnerabilities(
                app_id, severity_filter="All", max_results=1000
            )
            findings = result.get("findings", [])
            # Only include findings that are High, Medium, or >= failureThreshold
            allowed_severities = ["High", "Medium"]
            if failure_threshold and failure_threshold not in allowed_severities:
                allowed_severities.append(failure_threshold)
            filtered_findings = [f for f in findings if f.get("findingRisk") in allowed_severities]
            return {
                "config_path": abs_config_path,
                "applicationId": app_id,
                "failureThreshold": failure_threshold or "High/Medium",
                "open_issues_summary": self._calculate_severity_breakdown(filtered_findings),
                "totalOpenIssues": len(filtered_findings),
                "openIssues": filtered_findings,
                "note": "Returned issues are High, Medium, or at/above the configured failureThreshold (if set in hawk section) so chat can help fix them.",
            }
        except Exception as e:
            print(f"[DEBUG] Error fetching vulnerabilities: {e}")
            return {"error": f"Failed to fetch vulnerabilities: {e}"}

    async def set_application_tech_flags(self, app_id: str, tech_flags: dict) -> dict:
        """Update the technology flags for a StackHawk application. Only valid flags are sent."""
        if not isinstance(tech_flags, dict):
            raise ValueError("tech_flags must be a dictionary")
        filtered_flags = {k: bool(v) for k, v in tech_flags.items() if k in self.VALID_TECH_FLAGS}
        if not filtered_flags:
            raise ValueError("No valid tech flags provided.")
        payload = {"techFlags": filtered_flags}
        return await self._make_request("PUT", f"/api/v1/app/{app_id}/policy/flags", json=payload)

    async def create_application(
        self,
        org_id: str,
        app_name: str,
        language: str = None,
        frameworks: list = None,
        tech_flags: dict = None,
    ) -> dict:
        """Create a new StackHawk application in the given org, and set tech flags if provided."""
        payload = {
            "name": app_name,
        }
        if language:
            payload["language"] = language
        if frameworks:
            payload["frameworks"] = frameworks
        # Do not send techFlags on creation, must be set after
        app = await self._make_request("POST", f"/api/v1/org/{org_id}/app", json=payload)
        # Set tech flags if provided
        if tech_flags and "id" in app:
            await self.set_application_tech_flags(app["id"], tech_flags)
            # Optionally, fetch the updated app object
            app = await self.get_application(app["id"])
        return app

    async def run_stackhawk_scan(self, config_path: str = "stackhawk.yml") -> dict:
        """
        Run a StackHawk scan using the CLI, stream output, and return a summary of findings.
        Now always runs from the directory containing the config file.
        """
        import os
        import glob
        import asyncio

        # 1. Find the config file (absolute path)
        if not os.path.isabs(config_path):
            # Search up the tree for the config file
            search_dir = os.getcwd()
            found = False
            while True:
                candidate = os.path.join(search_dir, config_path)
                if os.path.isfile(candidate):
                    config_path = os.path.abspath(candidate)
                    found = True
                    break
                parent = os.path.dirname(search_dir)
                if parent == search_dir:
                    break
                search_dir = parent
            if not found:
                # Try glob for stackhawk*.y*ml
                search_dir = os.getcwd()
                while True:
                    for pat in [
                        "stackhawk.yml",
                        "stackhawk.yaml",
                        "stackhawk*.yml",
                        "stackhawk*.yaml",
                    ]:
                        for match in glob.glob(os.path.join(search_dir, pat)):
                            config_path = os.path.abspath(match)
                            found = True
                            break
                        if found:
                            break
                    if found:
                        break
                    parent = os.path.dirname(search_dir)
                    if parent == search_dir:
                        break
                    search_dir = parent
            if not found:
                return {
                    "success": False,
                    "error": f"Could not find StackHawk config file (tried {config_path})",
                }
        # 2. cd to the directory containing the config
        config_dir = os.path.dirname(config_path)
        config_filename = os.path.basename(config_path)
        api_key = self.api_key
        cmd = ["hawk", "--api-key", api_key, "scan", config_filename]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, cwd=config_dir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            return {
                "success": False,
                "error": "hawk CLI not installed",
                "install_instructions": (
                    "The StackHawk CLI (hawk) is not installed or not on your PATH.\n\n"
                    "## Install Instructions\n"
                    "1. Download from https://docs.stackhawk.com/download.html\n"
                    "2. The API key you are using for this MCP will work for the CLI, "
                    "but you can run `hawk init` to set it up correctly\n"
                    "3. Make sure your application is running and accessible\n"
                    "4. Then retry: `hawk scan`"
                ),
            }
        stdout_lines = []
        stderr_lines = []
        # Stream output
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            decoded = line.decode().rstrip()
            stdout_lines.append(decoded)
            # Optionally, stream to LLM/chat here
        # Wait for process to finish
        await process.wait()
        # Collect stderr
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            stderr_lines.append(line.decode().rstrip())
        # Try to find a summary in the output
        findings_summary = None
        for l in stdout_lines:
            if "Findings Summary" in l or "Findings:" in l:
                findings_summary = l
        return {
            "success": process.returncode == 0,
            "stdout": stdout_lines,
            "stderr": stderr_lines,
            "findings_summary": findings_summary,
            "note": f"Scan output and summary returned. Ran from {config_dir}. For more details, check the StackHawk dashboard or ask for findings in chat.",
        }

    async def _get_application_vulnerabilities(
        self,
        app_id: str = None,
        severity_filter: str = "All",
        include_remediation: bool = True,
        max_results: int = 100,
        app_name: str = None,
        triage_mode: bool = False,
        failure_threshold: str = None,
        config_path: str = None,
        config_content: str = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Get vulnerabilities for a specific application, with optional triage filtering (at/above failure threshold)."""
        import os
        import yaml

        try:
            # 1. If triage_mode, parse config for failure_threshold if not provided
            if triage_mode and not failure_threshold:
                if config_content:
                    try:
                        config = yaml.safe_load(config_content)
                        failure_threshold = config.get("hawk", {}).get("failureThreshold")
                        if not app_id:
                            app_id = config.get("app", {}).get("applicationId")
                    except Exception as e:
                        return {"error": f"Failed to parse config_content: {e}"}
                elif config_path or not app_id:
                    if not config_path:
                        config_path = self._find_stackhawk_config()
                    abs_config_path = os.path.abspath(config_path) if config_path else None
                    if not abs_config_path or not os.path.exists(abs_config_path):
                        return {"error": f"Config file not found: {abs_config_path}"}
                    try:
                        with open(abs_config_path, "r") as f:
                            config = yaml.safe_load(f)
                        failure_threshold = config.get("hawk", {}).get("failureThreshold")
                        if not app_id:
                            app_id = config.get("app", {}).get("applicationId")
                    except Exception as e:
                        return {"error": f"Failed to parse config: {e}"}
            if failure_threshold:
                failure_threshold = failure_threshold.capitalize()
            # 2. Use explicit app_id if provided, else auto-detect as before
            if not app_id:
                # Try to find stackhawk config up the directory tree
                config_path = self._find_stackhawk_config()
                chosen_app_id = None
                if config_path:
                    try:
                        with open(config_path, "r") as f:
                            config = yaml.safe_load(f)
                        chosen_app_id = config.get("app", {}).get("applicationId")
                    except Exception as e:
                        debug_print(f"Could not parse config at {config_path}: {e}")
                if not chosen_app_id:
                    if not app_name:
                        app_name = os.path.basename(os.getcwd())
                    user_info = await self.get_user_info()
                    orgs = user_info["user"]["external"]["organizations"]
                    if not orgs:
                        return {"error": "No organizations found for user."}
                    org_id = orgs[0]["organization"]["id"]
                    apps_response = await self.list_applications(org_id, pageSize=1000)
                    applications = apps_response.get("applications", [])
                    matches = [
                        a for a in applications if a.get("name", "").lower() == app_name.lower()
                    ]
                    if len(matches) == 1:
                        chosen_app_id = matches[0]["id"]
                    elif len(matches) > 1:
                        return {
                            "error": f"Multiple applications found with name '{app_name}'. Please specify app_id.",
                            "matches": [a["id"] for a in matches],
                        }
                    elif len(applications) == 1:
                        chosen_app_id = applications[0]["id"]
                    else:
                        return {
                            "error": f"Could not determine applicationId. Please specify app_id or ensure stackhawk.yml is present."
                        }
                app_id = chosen_app_id
            # Get org_id from user info if not provided
            org_id = kwargs.get("org_id")
            if not org_id:
                user_info = await self.get_user_info()
                org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
            findings_params = {"pageSize": max_results}
            findings_response = await self.get_application_findings(
                app_id, org_id, **findings_params
            )
            findings = findings_response.get("findings", [])
            # Apply severity filter if not triage_mode
            if not triage_mode and severity_filter != "All":
                findings = [f for f in findings if f.get("findingRisk") == severity_filter]
            # If triage_mode, filter by failure_threshold (default High/Medium)
            if triage_mode:
                allowed_severities = ["High", "Medium"]
                if failure_threshold and failure_threshold not in allowed_severities:
                    allowed_severities.append(failure_threshold)
                findings = [f for f in findings if f.get("findingRisk") in allowed_severities]
            # Get application details for context
            try:
                app_details = await self.get_application(app_id)
                app_name = app_details.get("name", "Unknown Application")
            except Exception as e:
                debug_print(f"Could not get application details: {e}")
                app_name = "Unknown Application"
            result = {
                "applicationId": app_id,
                "applicationName": app_name,
                "organizationId": org_id,
                "severityFilter": severity_filter,
                "totalFindings": len(findings),
                "findings": findings,
                "severityBreakdown": self._calculate_severity_breakdown(findings),
                "timestamp": datetime.now().isoformat(),
                "note": "These are application-specific vulnerabilities. Use triage_mode for CI/CD gating or remediation workflows.",
            }
            if triage_mode:
                result["failureThreshold"] = failure_threshold or "High/Medium"
                result["triageMode"] = True
            return result
        except Exception as e:
            debug_print(f"Error in _get_application_vulnerabilities: {e}")
            return {
                "error": str(e),
                "message": "Failed to get application vulnerabilities",
                "applicationId": app_id,
            }


class StackHawkMCPServer:
    """StackHawk MCP Server implementation"""

    def __init__(self, api_key: str, base_url: str = "https://api.stackhawk.com"):
        debug_print("Initializing StackHawkMCPServer...")
        self.client = StackHawkClient(api_key, base_url)
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
                        mimeType="application/json",
                    ),
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
                            "required": ["org_id"],
                        },
                    ),
                    Tool(
                        name="list_applications",
                        description="List applications in a StackHawk organization",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID"},
                                "page_size": {
                                    "type": "integer",
                                    "description": "Page size (optional)",
                                },
                            },
                            "required": ["org_id"],
                        },
                    ),
                    Tool(
                        name="validate_stackhawk_config",
                        description="Validate a StackHawk YAML configuration file",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "yaml_content": {
                                    "type": "string",
                                    "description": "YAML content to validate",
                                }
                            },
                            "required": ["yaml_content"],
                        },
                    ),
                    Tool(
                        name="validate_field_exists",
                        description="Validate that a field path exists in the StackHawk schema",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "field_path": {
                                    "type": "string",
                                    "description": "Field path to validate",
                                }
                            },
                            "required": ["field_path"],
                        },
                    ),
                    Tool(
                        name="setup_stackhawk_for_project",
                        description="Set up StackHawk for a new project. Finds or creates the application and generates a complete stackhawk.yml configuration file ready for scanning.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "host": {
                                    "type": "string",
                                    "description": "Target URL to scan (e.g., https://localhost:3000, https://ginandjuice.shop)",
                                },
                                "environment": {
                                    "type": "string",
                                    "description": "Environment name (default: dev)",
                                },
                                "org_id": {
                                    "type": "string",
                                    "description": "Organization ID (optional, auto-detected if omitted)",
                                },
                                "app_name": {
                                    "type": "string",
                                    "description": "Application name (optional, defaults to current directory name)",
                                },
                            },
                            "required": ["host"],
                        },
                    ),
                    Tool(
                        name="run_stackhawk_scan",
                        description="Run a StackHawk scan using the CLI and stream results back to the chat. Optionally specify a config path (default: stackhawk.yml).",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "config_path": {
                                    "type": "string",
                                    "description": "Path to StackHawk config file (default: stackhawk.yml)",
                                }
                            },
                        },
                    ),
                    Tool(
                        name="get_app_findings_for_triage",
                        description="Get triage-worthy findings for a project or application at or above the configured failureThreshold (or High/Medium if not set). Accepts app_id, config_path, or config_content.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "app_id": {
                                    "type": "string",
                                    "description": "StackHawk application ID (optional)",
                                },
                                "config_path": {
                                    "type": "string",
                                    "description": "Path to StackHawk config file (optional, default: stackhawk.yml)",
                                },
                                "config_content": {
                                    "type": "string",
                                    "description": "YAML content of the StackHawk config file (optional, takes precedence over config_path)",
                                },
                            },
                        },
                    ),
                ]
                return tools
            except Exception as e:
                debug_print(f"Error in list_tools: {e}")
                raise

        # Set as instance attribute so it's available for FastAPI
        self._list_tools_handler = handle_list_tools

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
            """Handle tool calls"""
            debug_print(f"Tool called: {name} with arguments: {arguments}")
            try:
                if name == "get_organization_info":
                    result = await self._get_organization_info(**arguments)
                elif name == "list_applications":
                    result = await self._list_applications(**arguments)
                elif name == "validate_stackhawk_config":
                    result = await self._validate_stackhawk_config(**arguments)
                elif name == "validate_field_exists":
                    result = await self._validate_field_exists(**arguments)
                elif name == "setup_stackhawk_for_project":
                    result = await self._setup_stackhawk_for_project(**arguments)
                elif name == "run_stackhawk_scan":
                    config_path = arguments.get("config_path", "stackhawk.yml")
                    result = await self.client.run_stackhawk_scan(config_path)
                    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                elif name == "get_app_findings_for_triage":
                    result = await self._get_application_vulnerabilities(
                        app_id=arguments.get("app_id"),
                        config_path=arguments.get("config_path"),
                        config_content=arguments.get("config_content"),
                        triage_mode=True,
                        failure_threshold=None,
                    )
                    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                else:
                    raise ValueError(f"Unknown tool: {name}")

                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

            except Exception as e:
                debug_print(f"Tool {name} failed: {e}")
                error_result = {"error": str(e), "tool": name, "arguments": arguments}
                return [types.TextContent(type="text", text=json.dumps(error_result, indent=2))]

        debug_print("MCP handlers setup complete")
        self._call_tool_handler = handle_call_tool

    async def call_tool(self, name: str, arguments: dict):
        return await self._call_tool_handler(name, arguments)

    async def _get_schema(self) -> Dict[str, Any]:
        """Get the StackHawk YAML schema with caching"""
        now = datetime.now()

        # Check if we have a valid cached schema
        if (
            self._schema_cache is not None
            and self._schema_cache_time is not None
            and now - self._schema_cache_time < self._schema_cache_ttl
        ):
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
                            "host": {"type": "string"},
                        },
                        "required": ["applicationId", "env", "host"],
                    },
                    "hawk": {"type": "object", "description": "HawkScan settings"},
                    "hawkAddOn": {"type": "object", "description": "Add-ons and custom scripts"},
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}, "value": {"type": "string"}},
                        },
                    },
                },
                "required": ["app"],
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
                    "path": current_path,
                }

                # Handle enums
                if "enum" in field_schema:
                    field_info["enum"] = field_schema["enum"]

                # Handle nested objects
                if field_schema.get("type") == "object" and "properties" in field_schema:
                    field_info["nested_fields"] = self._extract_schema_fields(
                        field_schema, current_path
                    )

                # Handle arrays
                if field_schema.get("type") == "array" and "items" in field_schema:
                    field_info["array_type"] = field_schema["items"].get("type", "object")
                    if field_schema["items"].get("type") == "object":
                        field_info["array_fields"] = self._extract_schema_fields(
                            field_schema["items"], f"{current_path}[]"
                        )

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
            "required": field_path.split(".")[-1] in current_schema.get("required", []),
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
                "timestamp": datetime.now().isoformat(),
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

            return {**apps_response, "timestamp": datetime.now().isoformat()}
        except Exception as e:
            debug_print(f"Error in _list_applications: {e}")
            raise

    def _generate_minimal_config(self, schema: dict) -> dict:
        """
        Recursively generate a minimal valid config block from a JSON schema.
        Only required fields are included, with sensible placeholders.
        """

        def _walk(subschema):
            if "type" in subschema:
                if subschema["type"] == "object":
                    result = {}
                    required = subschema.get("required", [])
                    properties = subschema.get("properties", {})
                    for key in required:
                        if key in properties:
                            result[key] = _walk(properties[key])
                        else:
                            result[key] = "REQUIRED_VALUE"
                    return result
                elif subschema["type"] == "array":
                    items = subschema.get("items", {})
                    return [_walk(items)] if items else []
                elif subschema["type"] == "string":
                    return "REQUIRED_STRING"
                elif subschema["type"] == "number" or subschema["type"] == "integer":
                    return 0
                elif subschema["type"] == "boolean":
                    return False
            # fallback
            return "REQUIRED_VALUE"

        return _walk(schema)

    async def _create_stackhawk_config(
        self, application_id: str, app_name: str, host: str, port: int, **kwargs
    ) -> Dict[str, Any]:
        """
        Create a new StackHawk YAML configuration with best practices, using the latest schema for required fields.
        """
        try:
            # Set defaults
            environment = kwargs.get("environment", "dev")
            protocol = kwargs.get("protocol", "https")
            # Build the host URL
            host_url = (
                f"{protocol}://{host}:{port}"
                if port != (443 if protocol == "https" else 80)
                else f"{protocol}://{host}"
            )

            # Fetch the latest schema
            schema = await self._get_schema()
            # Generate minimal config from schema
            minimal_config = self._generate_minimal_config(schema)

            # Always ensure the app section exists with required HawkScan fields
            if "app" not in minimal_config or not isinstance(minimal_config.get("app"), dict):
                minimal_config["app"] = {}
            minimal_config["app"]["applicationId"] = application_id
            minimal_config["app"]["env"] = environment
            minimal_config["app"]["host"] = host_url

            # Optionally add tags and hawk config if present in minimal config
            if "tags" in schema.get("properties", {}):
                minimal_config["tags"] = [
                    {"name": "environment", "value": environment},
                    {"name": "application", "value": app_name.lower().replace(" ", "-")},
                ]
            if "hawk" in minimal_config:
                # Optionally add some best-practice defaults for hawk
                minimal_config["hawk"].setdefault(
                    "spider", {"base": True, "ajax": False, "maxDurationMinutes": 30}
                )
                minimal_config["hawk"].setdefault("scan", {"maxDurationMinutes": 60, "threads": 10})
                minimal_config["hawk"].setdefault("startupTimeoutMinutes", 5)
                minimal_config["hawk"].setdefault("failureThreshold", "high")

            yaml_content = yaml.dump(minimal_config, default_flow_style=False, sort_keys=False)
            config_path = kwargs.get("config_path", "stackhawk.yml")
            abs_config_path = os.path.abspath(config_path)
            print(f"[DEBUG] Writing config to: {abs_config_path}")
            with open(abs_config_path, "w") as f:
                f.write(yaml_content)
            return {
                "success": True,
                "config_path": abs_config_path,
                "yaml": yaml_content,
                "next_steps": [
                    "Validate the config: use 'validate_stackhawk_config' with the generated YAML or run 'hawk validate config "
                    + abs_config_path
                    + "'",
                    "Run a scan: use 'run_stackhawk_scan' or run 'hawk scan "
                    + abs_config_path
                    + "' from the CLI",
                ],
            }
        except Exception as e:
            print(f"[DEBUG] Error writing config: {e}")
            return {
                "success": False,
                "error": str(e),
                "fix_suggestion": "Check that the target directory is writable. You can also create the config manually.",
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
                    "message": "Invalid YAML syntax",
                    "fix_suggestion": "Check the YAML syntax for indentation or formatting errors. Use 'setup_stackhawk_for_project' with host='https://your-app.com' to generate a valid config.",
                }

            # Get the schema
            schema = await self._get_schema()

            # Validate against schema
            try:
                validate(instance=config_data, schema=schema)

                # Check for fields required by HawkScan to actually run
                runnable_errors = []
                app_config = config_data.get("app", {})

                if not app_config:
                    runnable_errors.append(
                        "Missing 'app' section. HawkScan requires app.applicationId, app.host, and app.env to run."
                    )
                else:
                    if not app_config.get("applicationId"):
                        runnable_errors.append(
                            "Missing 'app.applicationId'. Get this from setup_stackhawk_for_project or the StackHawk dashboard."
                        )
                    if not app_config.get("host"):
                        runnable_errors.append(
                            "Missing 'app.host'. Set this to the URL of your running application (e.g., https://myapp.com)."
                        )
                    if not app_config.get("env"):
                        runnable_errors.append(
                            "Missing 'app.env'. Set this to your environment name (e.g., dev, staging, production)."
                        )

                if runnable_errors:
                    return {
                        "valid": False,
                        "error_type": "MISSING_REQUIRED_FIELDS",
                        "errors": runnable_errors,
                        "message": "Configuration is missing fields required by HawkScan. "
                        + " ".join(runnable_errors),
                        "fix_suggestion": "Use 'setup_stackhawk_for_project' with host='https://your-app.com' to generate a complete configuration.",
                        "cli_validation": "For additional validation, run 'hawk validate config <path-to-stackhawk.yml>' which validates against HawkScan's runtime requirements.",
                    }

                validation_result = {
                    "valid": True,
                    "message": "Configuration is valid and follows official StackHawk schema",
                    "config_summary": {
                        "application_id": app_config.get("applicationId"),
                        "app_name": app_config.get("name"),
                        "environment": app_config.get("env"),
                        "host": app_config.get("host"),
                        "has_hawk_config": "hawk" in config_data,
                        "has_hawk_addon": "hawkAddOn" in config_data,
                        "has_tags": "tags" in config_data,
                        "has_authentication": "authentication" in app_config,
                    },
                    "cli_validation": "For additional validation, run 'hawk validate config <path-to-stackhawk.yml>' which validates against HawkScan's runtime requirements.",
                }

                # Additional validation checks
                warnings = []
                hawk_config = config_data.get("hawk", {})

                if not app_config.get("description"):
                    warnings.append("Consider adding a description for better documentation")

                if not hawk_config.get("spider", {}).get("base"):
                    warnings.append(
                        "Consider enabling base spider for traditional web applications"
                    )

                if hawk_config.get("scan", {}).get("maxDurationMinutes", 0) > 120:
                    warnings.append(
                        "Scan duration is quite high (>2 hours), consider reducing for faster feedback"
                    )

                if warnings:
                    validation_result["warnings"] = warnings

                return validation_result

            except ValidationError as e:
                return {
                    "valid": False,
                    "error_type": "SCHEMA_VALIDATION_ERROR",
                    "error": str(e),
                    "message": f"Configuration does not match StackHawk schema: {e.message}",
                    "path": " -> ".join(str(p) for p in e.path) if e.path else "unknown",
                    "fix_suggestion": "Use 'validate_field_exists' to confirm valid field paths and types.",
                    "cli_validation": "For additional validation, run 'hawk validate config <path-to-stackhawk.yml>' which validates against HawkScan's runtime requirements.",
                }

        except Exception as e:
            debug_print(f"Error in _validate_stackhawk_config: {e}")
            return {
                "valid": False,
                "error_type": "UNKNOWN_ERROR",
                "error": str(e),
                "message": "Unexpected error during validation",
                "fix_suggestion": "Try validating with 'hawk validate config <path-to-stackhawk.yml>' for more detailed error information.",
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
                    "message": f"Field '{field_path}' exists in the StackHawk schema",
                }
            else:
                return {
                    "success": False,
                    "field_path": field_path,
                    "exists": False,
                    "error": result["error"],
                    "message": f"Field '{field_path}' does not exist in the StackHawk schema",
                    "suggestion": "Use get_schema_fields to see all available fields",
                }
        except Exception as e:
            debug_print(f"Error in _validate_field_exists: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to validate field existence",
            }

    @staticmethod
    def _parse_host_url(host_url: str) -> dict:
        """Parse a host URL into protocol, hostname, and port components."""
        from urllib.parse import urlparse

        parsed = urlparse(host_url)
        protocol = parsed.scheme or "https"
        hostname = parsed.hostname or host_url
        port = parsed.port
        if port is None:
            port = 443 if protocol == "https" else 80
        return {"protocol": protocol, "hostname": hostname, "port": port}

    async def _setup_stackhawk_for_project(
        self, host: str, environment: str = "dev", org_id: str = None, app_name: str = None
    ) -> dict:
        """Detect project language/frameworks, find or create StackHawk app, and generate a complete stackhawk.yml config."""
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
                return {
                    "error": "No organizations found for user.",
                    "fix_suggestion": "Ensure your STACKHAWK_API_KEY belongs to an account with at least one organization.",
                }
            org_id = orgs[0]["organization"]["id"]

        # 3. Use directory name as app_name if not provided
        if not app_name:
            app_name = os.path.basename(os.getcwd())

        # 4. List applications and check for existing app
        apps_response = await self.client.list_applications(org_id, pageSize=1000)
        applications = apps_response.get("applications", [])
        found_app = next(
            (a for a in applications if a.get("name", "").lower() == app_name.lower()), None
        )

        if found_app:
            app_id = found_app.get("id")
            app_status = "found"
            app_response = found_app
        else:
            # 5. Create application if not found
            app_resp = await self.client.create_application(
                org_id, app_name, language, frameworks, tech_flags
            )
            app_id = app_resp.get("id")
            if not app_id:
                return {
                    "error": "Failed to create application",
                    "response": app_resp,
                    "fix_suggestion": "Try creating the app manually with 'hawk create app' CLI or via the StackHawk dashboard at https://app.stackhawk.com.",
                }
            app_status = "created"
            app_response = app_resp

        # 6. Parse host URL and auto-generate config
        parsed = self._parse_host_url(host)
        config_result = await self._create_stackhawk_config(
            application_id=app_id,
            app_name=app_name,
            host=parsed["hostname"],
            port=parsed["port"],
            environment=environment,
            protocol=parsed["protocol"],
        )

        config_path = config_result.get("config_path", "stackhawk.yml")

        result = {
            "success": True,
            "applicationId": app_id,
            "appName": app_name,
            "orgId": org_id,
            "language": language,
            "frameworks": frameworks,
            "techFlags": tech_flags,
            "appResponse": app_response,
            "appStatus": app_status,
            "configGenerated": config_result.get("success", False),
            "configPath": config_result.get("config_path"),
            "configYaml": config_result.get("yaml"),
            "next_steps": [
                "Validate the config: use 'validate_stackhawk_config' with the generated YAML or run 'hawk validate config stackhawk.yml'",
                "Ensure your application is running at " + host,
                "Run a scan: use 'run_stackhawk_scan' or run 'hawk scan stackhawk.yml' from the CLI",
            ],
        }

        if not config_result.get("success"):
            result["configError"] = config_result.get("error")
            result["fix_suggestion"] = (
                "Config generation failed. Use 'setup_stackhawk_for_project' with host='https://your-app.com' to retry."
            )

        return result

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
                            experimental_capabilities={}, notification_options=NotificationOptions()
                        ),
                    ),
                )
                debug_print("MCP server run completed")
        except Exception as e:
            debug_print(f"Error in run: {e}")
            raise

    async def cleanup(self):
        """Cleanup resources"""
        debug_print("Cleaning up StackHawk client...")
        await self.client.close()

    async def list_tools(self):
        return await self._list_tools_handler()

    def guess_authentication_method(self, project_root: str = ".") -> dict:
        """
        Heuristically guess the authentication method used by the application.
        Returns: {
            "method": "jwt" | "form" | "oauth" | "session" | "apiKey" | "unknown",
            "evidence": [list of strings],
            "ask_user": bool
        }
        """
        evidence = []
        method = "unknown"
        req_path = os.path.join(project_root, "requirements.txt")
        if os.path.exists(req_path):
            with open(req_path) as f:
                reqs = f.read().lower()
                if "flask-jwt" in reqs or "pyjwt" in reqs:
                    method = "jwt"
                    evidence.append("Found flask-jwt or pyjwt in requirements.txt")
                elif (
                    "flask-login" in reqs
                    or "django.contrib.auth" in reqs
                    or "django-allauth" in reqs
                ):
                    method = "form"
                    evidence.append("Found flask-login or django auth in requirements.txt")
                elif "oauthlib" in reqs or "authlib" in reqs or "django-oauth-toolkit" in reqs:
                    method = "oauth"
                    evidence.append(
                        "Found oauthlib/authlib/django-oauth-toolkit in requirements.txt"
                    )
                elif "session" in reqs or "flask-session" in reqs or "django-session" in reqs:
                    method = "session"
                    evidence.append("Found session-related package in requirements.txt")
                elif "api-key" in reqs or "apikey" in reqs:
                    method = "apiKey"
                    evidence.append("Found api-key/apikey in requirements.txt")
        # Also check package.json for Node.js projects
        pkg_path = os.path.join(project_root, "package.json")
        if method == "unknown" and os.path.exists(pkg_path):
            import json

            with open(pkg_path) as f:
                try:
                    pkg = json.load(f)
                    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                    dep_keys = [k.lower() for k in deps.keys()]
                    if "passport" in dep_keys or "passport-local" in dep_keys:
                        method = "form"
                        evidence.append("Found passport/passport-local in package.json")
                    elif "express-session" in dep_keys or "cookie-session" in dep_keys:
                        method = "session"
                        evidence.append("Found express-session/cookie-session in package.json")
                    elif "jsonwebtoken" in dep_keys or "jwt-simple" in dep_keys:
                        method = "jwt"
                        evidence.append("Found jsonwebtoken/jwt-simple in package.json")
                    elif (
                        "oauth" in dep_keys
                        or "passport-oauth" in dep_keys
                        or "simple-oauth2" in dep_keys
                    ):
                        method = "oauth"
                        evidence.append("Found oauth/passport-oauth/simple-oauth2 in package.json")
                    elif (
                        "api-key" in dep_keys
                        or "apikey" in dep_keys
                        or "express-api-key" in dep_keys
                    ):
                        method = "apiKey"
                        evidence.append("Found api-key/apikey/express-api-key in package.json")
                except Exception as e:
                    evidence.append(f"Could not parse package.json: {e}")
        # If still unknown, do a quick scan for code patterns
        if method == "unknown":
            for fname in ["server.py", "app.py", "main.py"]:
                fpath = os.path.join(project_root, "stackhawk_mcp", fname)
                if os.path.exists(fpath):
                    with open(fpath) as f:
                        code = f.read().lower()
                        if "jwt" in code:
                            method = "jwt"
                            evidence.append(f"Found 'jwt' in {fname}")
                        elif "login_required" in code or "@login_required" in code:
                            method = "form"
                            evidence.append(f"Found 'login_required' in {fname}")
                        elif "oauth" in code:
                            method = "oauth"
                            evidence.append(f"Found 'oauth' in {fname}")
                        elif "session" in code:
                            method = "session"
                            evidence.append(f"Found 'session' in {fname}")
                        elif "api_key" in code or "apikey" in code:
                            method = "apiKey"
                            evidence.append(f"Found 'api_key' in {fname}")
        ask_user = method == "unknown"
        if ask_user:
            evidence.append(
                "No clear authentication method detected. Please specify your authentication type (e.g., form, jwt, oauth, session, apiKey)."
            )
        return {"method": method, "evidence": evidence, "ask_user": ask_user}

    def _find_stackhawk_config(self, start_dir: str = None) -> str:
        """Search up the directory tree for a stackhawk.yml or stackhawk.yaml file."""
        import os

        if not start_dir:
            start_dir = os.getcwd()
        current_dir = os.path.abspath(start_dir)
        while True:
            for fname in ["stackhawk.yml", "stackhawk.yaml"]:
                candidate = os.path.join(current_dir, fname)
                if os.path.isfile(candidate):
                    return candidate
            parent = os.path.dirname(current_dir)
            if parent == current_dir:
                break
            current_dir = parent
        return None

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
        elif glob.glob("*.csproj") or glob.glob("*.sln") or glob.glob("*.fsproj"):
            language = "csharp"
            # Check for ASP.NET Core and Blazor in .csproj files
            for csproj in glob.glob("*.csproj") + glob.glob("**/*.csproj", recursive=True):
                try:
                    with open(csproj, "r") as f:
                        content = f.read()
                        if "Microsoft.AspNetCore" in content:
                            frameworks.append("aspnet-core")
                        if "Microsoft.AspNetCore.Components" in content or "Blazor" in content:
                            frameworks.append("blazor")
                except:
                    pass
            # Deduplicate
            frameworks = list(dict.fromkeys(frameworks))

        return {"language": language, "frameworks": frameworks}

async def main():
    """Main entry point"""
    debug_print("=== StackHawk MCP Server Starting ===")

    import os

    api_key = os.environ.get("STACKHAWK_API_KEY")
    base_url = os.environ.get("STACKHAWK_BASE_URL", "https://api.stackhawk.com")
    if not api_key:
        debug_print("ERROR: STACKHAWK_API_KEY environment variable is required")
        sys.exit(1)

    debug_print(f"API key found: {api_key[:20]}...")
    debug_print(f"Base URL: {base_url}")

    server = None
    try:
        debug_print("Creating StackHawkMCPServer...")
        server = StackHawkMCPServer(api_key, base_url)
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
