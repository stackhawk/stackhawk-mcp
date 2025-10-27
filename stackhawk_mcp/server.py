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
from stackhawk_mcp import __version__

# Configure logging to stderr so Claude Desktop can see it
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
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
        "Db", "Db.MySQL", "Db.PostgreSQL", "Db.Microsoft SQL Server", "Db.Oracle", "Db.SQLite", "Db.Microsoft Access", "Db.Firebird", "Db.SAP MaxDB", "Db.Sybase", "Db.IBM DB2", "Db.HypersonicSQL", "Db.MongoDB", "Db.CouchDB",
        "Language", "Language.ASP", "Language.C", "Language.Java", "Language.Java.Spring", "Language.JavaScript", "Language.JSP/Servlet", "Language.PHP", "Language.Python", "Language.Ruby", "Language.XML",
        "OS", "OS.Linux", "OS.MacOS", "OS.Windows",
        "SCM", "SCM.Git", "SCM.SVN",
        "WS", "WS.Apache", "WS.IIS"
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
        """List sensitive data findings for an organization (aggregated from repositories)"""
        # This endpoint is not available in the official StackHawk API
        # Aggregate sensitive data from all repositories in the organization
        try:
            # Get all repositories
            repos_response = await self.list_repositories(org_id, pageSize=1000)
            repositories = repos_response.get("repositories", [])
            
            all_findings = []
            for repo in repositories:
                try:
                    repo_sensitive_data = await self.get_repository_sensitive_data(
                        org_id, repo["id"], all_results=all_results, **params
                    )
                    repo_findings = repo_sensitive_data.get("sensitiveDataFindings", [])
                    
                    # Add repository context to each finding
                    for finding in repo_findings:
                        finding["repositoryId"] = repo["id"]
                        finding["repositoryName"] = repo.get("name", "")
                    
                    all_findings.extend(repo_findings)
                except Exception as e:
                    debug_print(f"Could not get sensitive data for repository {repo.get('id', 'unknown')}: {e}")
                    continue
            
            return {
                "sensitiveDataFindings": all_findings,
                "note": "Aggregated from repository-level sensitive data - org-level endpoint not available in official API",
                "totalRepositoriesChecked": len(repositories)
            }
            
        except Exception as e:
            debug_print(f"Error aggregating sensitive data findings: {e}")
            return {
                "sensitiveDataFindings": [],
                "error": str(e),
                "note": "Could not aggregate sensitive data - org-level endpoint not available in official API"
            }

    async def get_sensitive_data_findings_detailed(self, org_id: str, all_results: bool = False, **params) -> Dict[str, Any]:
        """Get detailed sensitive data findings with comprehensive filtering options and optional pagination."""
        # This method now delegates to the aggregated implementation
        return await self.list_sensitive_data_findings(org_id, all_results=all_results, **params)

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
        """Get sensitive data findings for a specific repository (using official OAS endpoint)"""
        # Official endpoint per StackHawk OpenAPI specification
        endpoint = f"/api/v1/org/{org_id}/repo/{repo_id}/sensitive/list"
        if all_results:
            findings = await self._fetch_all_pages(endpoint, params)
            return {"sensitiveDataFindings": findings}
        else:
            return await self._make_request("GET", endpoint, params=params)

    async def get_sensitive_data_types(self, org_id: str, **params) -> Dict[str, Any]:
        """Get available sensitive data types and categories (fallback implementation)"""
        # This endpoint is not available in the official StackHawk API
        # Return standard sensitive data types as fallback
        return {
            "sensitiveDataTypes": [
                {"type": "PII", "description": "Personally Identifiable Information"},
                {"type": "PCI", "description": "Payment Card Industry data"},
                {"type": "PHI", "description": "Protected Health Information"},
                {"type": "SSN", "description": "Social Security Numbers"},
                {"type": "Email", "description": "Email addresses"},
                {"type": "Phone", "description": "Phone numbers"},
                {"type": "Address", "description": "Physical addresses"},
                {"type": "API_Key", "description": "API keys and tokens"}
            ],
            "note": "Standard sensitive data types - endpoint not available in official API"
        }

    async def get_sensitive_data_summary(self, org_id: str, **params) -> Dict[str, Any]:
        """Get summary of sensitive data findings across the organization (fallback implementation)"""
        # This endpoint is not available in the official StackHawk API
        # Calculate summary from organization-level sensitive data findings
        try:
            findings_response = await self.list_sensitive_data_findings(org_id, pageSize=1000)
            findings = findings_response.get("sensitiveDataFindings", [])
            
            # Calculate summary statistics
            summary = {
                "totalFindings": len(findings),
                "dataTypeBreakdown": self._calculate_data_type_breakdown(findings),
                "riskScore": self._calculate_sensitive_data_risk_score(findings),
                "note": "Calculated summary - endpoint not available in official API"
            }
            
            return summary
        except Exception as e:
            debug_print(f"Error calculating sensitive data summary: {e}")
            return {
                "error": str(e),
                "note": "Could not calculate summary - endpoint not available in official API"
            }

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
            result = await self._get_application_vulnerabilities(app_id, severity_filter="All", max_results=1000)
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
                "note": "Returned issues are High, Medium, or at/above the configured failureThreshold (if set in hawk section) so chat can help fix them."
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

    async def create_application(self, org_id: str, app_name: str, language: str = None, frameworks: list = None, tech_flags: dict = None) -> dict:
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
                    for pat in ["stackhawk.yml", "stackhawk.yaml", "stackhawk*.yml", "stackhawk*.yaml"]:
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
                return {"success": False, "error": f"Could not find StackHawk config file (tried {config_path})"}
        # 2. cd to the directory containing the config
        config_dir = os.path.dirname(config_path)
        config_filename = os.path.basename(config_path)
        api_key = self.api_key
        cmd = ["hawk", "--api-key", api_key, "scan", config_filename]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=config_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
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
            "note": f"Scan output and summary returned. Ran from {config_dir}. For more details, check the StackHawk dashboard or ask for findings in chat."
        }

    async def _get_application_vulnerabilities(self, app_id: str = None, severity_filter: str = "All", include_remediation: bool = True, max_results: int = 100, app_name: str = None, triage_mode: bool = False, failure_threshold: str = None, config_path: str = None, config_content: str = None, **kwargs) -> Dict[str, Any]:
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
                    matches = [a for a in applications if a.get("name", "").lower() == app_name.lower()]
                    if len(matches) == 1:
                        chosen_app_id = matches[0]["id"]
                    elif len(matches) > 1:
                        return {"error": f"Multiple applications found with name '{app_name}'. Please specify app_id.", "matches": [a["id"] for a in matches]}
                    elif len(applications) == 1:
                        chosen_app_id = applications[0]["id"]
                    else:
                        return {"error": f"Could not determine applicationId. Please specify app_id or ensure stackhawk.yml is present."}
                app_id = chosen_app_id
            # Get org_id from user info if not provided
            org_id = kwargs.get('org_id')
            if not org_id:
                user_info = await self.get_user_info()
                org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
            findings_params = {"pageSize": max_results}
            findings_response = await self.get_application_findings(app_id, org_id, **findings_params)
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
                "note": "These are application-specific vulnerabilities. Use triage_mode for CI/CD gating or remediation workflows."
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
                "applicationId": app_id
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
                        name="check_repository_attack_surface",
                        description="Check if the current repository name exists in the StackHawk attack surface and get related security info.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "repo_name": {"type": "string", "description": "Repository name to check (optional, defaults to current directory name)"},
                                "org_id": {"type": "string", "description": "Organization ID (optional, auto-detected if omitted)"},
                                "include_vulnerabilities": {"type": "boolean", "description": "Include vulnerability information (default: true)"},
                                "include_apps": {"type": "boolean", "description": "Include connected applications (default: true)"}
                            }
                        }
                    ),
                    Tool(
                        name="check_repository_sensitive_data",
                        description="Check if the current repository name has sensitive data findings in StackHawk and get exposure details.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "repo_name": {"type": "string", "description": "Repository name to check (optional, defaults to current directory name)"},
                                "org_id": {"type": "string", "description": "Organization ID (optional, auto-detected if omitted)"},
                                "data_type_filter": {"type": "string", "description": "Filter by sensitive data type (e.g., PII, PCI, PHI, or All for no filter)."},
                                "include_remediation": {"type": "boolean", "description": "Include remediation recommendations (default: true)"}
                            }
                        }
                    ),
                    Tool(
                        name="list_application_repository_connections",
                        description="List connections between StackHawk applications and code repositories to understand the attack surface mapping.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID (optional, auto-detected if omitted)"},
                                "include_repo_details": {"type": "boolean", "description": "Include repository security details (default: true)"},
                                "include_app_details": {"type": "boolean", "description": "Include application security details (default: true)"},
                                "filter_connected_only": {"type": "boolean", "description": "Only show apps/repos that have connections (default: false)"}
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
                    ),
                    Tool(
                        name="run_stackhawk_scan",
                        description="Run a StackHawk scan using the CLI and stream results back to the chat. Optionally specify a config path (default: stackhawk.yml).",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "config_path": {"type": "string", "description": "Path to StackHawk config file (default: stackhawk.yml)"}
                            }
                        }
                    ),
                    Tool(
                        name="get_app_findings_for_triage",
                        description="Get triage-worthy findings for a project or application at or above the configured failureThreshold (or High/Medium if not set). Accepts app_id, config_path, or config_content.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "app_id": {"type": "string", "description": "StackHawk application ID (optional)"},
                                "config_path": {"type": "string", "description": "Path to StackHawk config file (optional, default: stackhawk.yml)"},
                                "config_content": {"type": "string", "description": "YAML content of the StackHawk config file (optional, takes precedence over config_path)"}
                            }
                        }
                    ),
                    Tool(
                        name="get_sensitive_data_summary",
                        description="Get a comprehensive sensitive data summary for an organization, including trends, critical findings, and recommendations.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "org_id": {"type": "string", "description": "Organization ID (optional, auto-detected if omitted)"},
                                "time_period": {"type": "string", "description": "Time period for analysis (default: 30d)"},
                                "include_trends": {"type": "boolean", "description": "Include trend analysis (default: true)"},
                                "include_critical_only": {"type": "boolean", "description": "Focus only on critical findings (default: false)"},
                                "include_recommendations": {"type": "boolean", "description": "Include remediation recommendations (default: true)"},
                                "group_by": {"type": "string", "description": "Group findings by 'data_type', 'application', or 'repository' (default: data_type)"}
                            }
                        }
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
                elif name == "validate_field_exists":
                    result = await self._validate_field_exists(**arguments)
                elif name == "check_repository_attack_surface":
                    result = await self._check_repository_attack_surface(**arguments)
                elif name == "check_repository_sensitive_data":
                    result = await self._check_repository_sensitive_data(**arguments)
                elif name == "list_application_repository_connections":
                    result = await self._list_application_repository_connections(**arguments)
                elif name == "setup_stackhawk_for_project":
                    result = await self._setup_stackhawk_for_project(**arguments)
                elif name == "get_stackhawk_scan_instructions":
                    config_path = arguments.get("config_path", "stackhawk.yml")
                    result = self._get_stackhawk_scan_instructions(config_path)
                    return [types.TextContent(type="text", text=result)]
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
                        failure_threshold=None
                    )
                    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                elif name == "get_sensitive_data_summary":
                    result = await self._get_comprehensive_sensitive_data_summary(**arguments)
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

    def _generate_minimal_config(self, schema: dict) -> dict:
        """
        Recursively generate a minimal valid config block from a JSON schema.
        Only required fields are included, with sensible placeholders.
        """
        def _walk(subschema):
            if 'type' in subschema:
                if subschema['type'] == 'object':
                    result = {}
                    required = subschema.get('required', [])
                    properties = subschema.get('properties', {})
                    for key in required:
                        if key in properties:
                            result[key] = _walk(properties[key])
                        else:
                            result[key] = "REQUIRED_VALUE"
                    return result
                elif subschema['type'] == 'array':
                    items = subschema.get('items', {})
                    return [_walk(items)] if items else []
                elif subschema['type'] == 'string':
                    return "REQUIRED_STRING"
                elif subschema['type'] == 'number' or subschema['type'] == 'integer':
                    return 0
                elif subschema['type'] == 'boolean':
                    return False
            # fallback
            return "REQUIRED_VALUE"
        return _walk(schema)

    async def _create_stackhawk_config(self, application_id: str, app_name: str, host: str, port: int, **kwargs) -> Dict[str, Any]:
        """
        Create a new StackHawk YAML configuration with best practices, using the latest schema for required fields.
        """
        try:
            # Set defaults
            environment = kwargs.get("environment", "dev")
            protocol = kwargs.get("protocol", "https")
            # Build the host URL
            host_url = f"{protocol}://{host}:{port}" if port != (443 if protocol == "https" else 80) else f"{protocol}://{host}"

            # Fetch the latest schema
            schema = await self._get_schema()
            # Generate minimal config from schema
            minimal_config = self._generate_minimal_config(schema)

            # Fill in required values for 'app'
            if "app" in minimal_config:
                minimal_config["app"]["applicationId"] = application_id
                minimal_config["app"]["env"] = environment
                minimal_config["app"]["host"] = host_url

            # Optionally add tags and hawk config if present in minimal config
            if "tags" in schema.get("properties", {}):
                minimal_config["tags"] = [
                    {"name": "environment", "value": environment},
                    {"name": "application", "value": app_name.lower().replace(" ", "-")}
                ]
            if "hawk" in minimal_config:
                # Optionally add some best-practice defaults for hawk
                minimal_config["hawk"].setdefault("spider", {"base": True, "ajax": False, "maxDurationMinutes": 30})
                minimal_config["hawk"].setdefault("scan", {"maxDurationMinutes": 60, "threads": 10})
                minimal_config["hawk"].setdefault("startupTimeoutMinutes", 5)
                minimal_config["hawk"].setdefault("failureThreshold", "high")

            yaml_content = yaml.dump(minimal_config, default_flow_style=False, sort_keys=False)
            config_path = kwargs.get("config_path", "stackhawk.yml")
            abs_config_path = os.path.abspath(config_path)
            print(f"[DEBUG] Writing config to: {abs_config_path}")
            with open(abs_config_path, "w") as f:
                f.write(yaml_content)
            return {"success": True, "config_path": abs_config_path, "yaml": yaml_content}
        except Exception as e:
            print(f"[DEBUG] Error writing config: {e}")
            return {"success": False, "error": str(e)}

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

    async def _get_stackhawk_schema(self, section: str = None, **kwargs) -> Dict[str, Any]:
        """Get the latest StackHawk YAML configuration schema, or just fields for a section if specified."""
        try:
            schema = await self.client.get_yaml_schema()
            self._schema_cache = schema
            self._schema_cache_time = datetime.now()
            if section:
                # Use the same logic as get_schema_fields to extract fields for the section
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
            # Default: return full schema
            return {
                "schema": schema,
                "description": "StackHawk YAML Configuration Schema",
                "version": "1.0.0",
                "source": "Official StackHawk Schema URL",
                "schema_url": "https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json",
                "cached": True,
                "cache_age": "0:00:00",
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

    async def _get_sensitive_data(self, target_type: str, target_id: str, org_id: str = None, data_type_filter: str = "All", include_details: bool = True, max_results: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Get sensitive data findings for a specific application or repository (asset-level).
        Use this for triage, remediation, or detailed review of a single app or repo.
        """
        try:
            # Get org_id if not provided
            if not org_id:
                user_info = await self.client.get_user_info()
                org_id = user_info["user"]["external"]["organizations"][0]["organization"]["id"]
            findings_params = {"pageSize": max_results}
            # Only one endpoint: /api/v1/org/{org_id}/sensitive-data
            findings_response = await self.client.list_sensitive_data_findings(org_id, **findings_params)
            findings = findings_response.get("sensitiveDataFindings", [])
            # Filter by target
            if target_type == "application":
                findings = [f for f in findings if f.get("applicationId") == target_id]
            elif target_type == "repository":
                findings = [f for f in findings if f.get("repositoryId") == target_id]
            else:
                return {"error": f"Unknown target_type: {target_type}"}
            # Apply data type filter
            if data_type_filter != "All":
                findings = [f for f in findings if f.get("dataType") == data_type_filter]
            # Get context name
            context_name = "Unknown"
            if target_type == "application":
                try:
                    app_details = await self.client.get_application(target_id)
                    context_name = app_details.get("name", "Unknown Application")
                except Exception as e:
                    context_name = "Unknown Application"
            elif target_type == "repository":
                try:
                    repo_details = await self.client.get_repository_details(org_id, target_id)
                    context_name = repo_details.get("name", "Unknown Repository")
                except Exception as e:
                    context_name = "Unknown Repository"
            return {
                f"{target_type}Id": target_id,
                f"{target_type}Name": context_name,
                "organizationId": org_id,
                "dataTypeFilter": data_type_filter,
                "totalFindings": len(findings),
                "findings": findings,
                "dataTypeBreakdown": self._calculate_data_type_breakdown(findings),
                "timestamp": datetime.now().isoformat(),
                "note": f"These are {target_type}-specific sensitive data findings."
            }
        except Exception as e:
            debug_print(f"Error in _get_sensitive_data: {e}")
            return {
                "error": str(e),
                "message": f"Failed to get {target_type} sensitive data",
                f"{target_type}Id": target_id
            }

    async def _map_sensitive_data_surface(self, org_id: str, include_applications: bool = True, include_repositories: bool = True, risk_visualization: bool = True, **kwargs) -> Dict[str, Any]:
        """Map sensitive data exposure across repositories and applications (uses unified _get_sensitive_data)."""
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
                            app_sensitive_data = await self._get_sensitive_data(
                                target_type="application",
                                target_id=app["id"],
                                org_id=org_id,
                                max_results=50
                            )
                            findings = app_sensitive_data.get("findings", [])
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
                            repo_sensitive_data = await self._get_sensitive_data(
                                target_type="repository",
                                target_id=repo["id"],
                                org_id=org_id,
                                max_results=50
                            )
                            findings = repo_sensitive_data.get("findings", [])
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

    def _get_stackhawk_scan_instructions(self, config_path: str = "stackhawk.yml") -> str:
        """Get instructions for running StackHawk scans"""
        instructions = f"""
# StackHawk Scan Instructions

## Prerequisites
1. Install [StackHawk CLI](https://docs.stackhawk.com/download.html)
2. The API key you are using for this MCP will work for the CLI, but you can run `hawk init` to set it up correctly
3. Make sure your application is running and accessible

## Configuration
Your StackHawk configuration is located at: `{config_path}`

## Running Scans

### Basic Scan
```bash
hawk scan
```
or
```bash
hawk --api-key <your-api-key> scan
```

### Scan with Custom Config
```bash
hawk scan  {config_path}
```

### Scan with Environment Override
```bash
hawk scan -e ENV=production
```

### Scan with Custom Host
```bash
hawk scan -e HOST=https://your-app-domain.com
```

## Viewing Results
1. When the scan finishes, you can triage and remediate findings directly from this LLM chat interface. Just ask for open issues or help fixing vulnerabilities.
2. You can also check the StackHawk dashboard at https://app.stackhawk.com for a full view of your application and findings.

## Troubleshooting
- Ensure your application is running before starting the scan
- Check that the host and port in your config match your application
- Verify your API key has the correct permissions
- Check the scan logs for detailed error information

## Next Steps
1. After a scan, use this LLM chat to review, triage, and get remediation advice for any vulnerabilities found.
2. Set up automated scanning in your CI/CD pipeline
3. Configure alerts for new vulnerabilities
4. Regular security reviews and updates
"""
        return instructions

    async def _setup_stackhawk_for_project(self, org_id: str = None, app_name: str = None) -> dict:
        """Detect project language/frameworks, find or create StackHawk app, and return config info."""
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

        # 4. List applications and check for existing app
        apps_response = await self.client.list_applications(org_id, pageSize=1000)
        applications = apps_response.get("applications", [])
        found_app = next((a for a in applications if a.get("name", "").lower() == app_name.lower()), None)
        config_path = "stackhawk.yml"
        cli_instructions = self._get_stackhawk_scan_instructions(config_path)
        if found_app:
            app_id = found_app.get("id")
            return {
                "success": True,
                "applicationId": app_id,
                "appName": app_name,
                "orgId": org_id,
                "language": language,
                "frameworks": frameworks,
                "techFlags": tech_flags,
                "appResponse": found_app,
                "note": "Application already exists in StackHawk. Use this info to generate stackhawk.yml.",
                "appStatus": "found",
                "cliInstructions": cli_instructions
            }

        # 5. Create application if not found
        app_resp = await self.client.create_application(org_id, app_name, language, frameworks, tech_flags)
        app_id = app_resp.get("id")
        if not app_id:
            return {"error": "Failed to create application", "response": app_resp}

        # 6. Return info for config generation
        return {
            "success": True,
            "applicationId": app_id,
            "appName": app_name,
            "orgId": org_id,
            "language": language,
            "frameworks": frameworks,
            "techFlags": tech_flags,
            "appResponse": app_resp,
            "note": "Application created in StackHawk. Use this info to generate stackhawk.yml.",
            "appStatus": "created",
            "cliInstructions": cli_instructions
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
                elif "flask-login" in reqs or "django.contrib.auth" in reqs or "django-allauth" in reqs:
                    method = "form"
                    evidence.append("Found flask-login or django auth in requirements.txt")
                elif "oauthlib" in reqs or "authlib" in reqs or "django-oauth-toolkit" in reqs:
                    method = "oauth"
                    evidence.append("Found oauthlib/authlib/django-oauth-toolkit in requirements.txt")
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
                    elif "oauth" in dep_keys or "passport-oauth" in dep_keys or "simple-oauth2" in dep_keys:
                        method = "oauth"
                        evidence.append("Found oauth/passport-oauth/simple-oauth2 in package.json")
                    elif "api-key" in dep_keys or "apikey" in dep_keys or "express-api-key" in dep_keys:
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
            evidence.append("No clear authentication method detected. Please specify your authentication type (e.g., form, jwt, oauth, session, apiKey).")
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
        
        return {
            "language": language,
            "frameworks": frameworks
        }



    async def _analyze_sensitive_data_trends(self, org_id: str, analysis_period: str = "90d", include_applications: bool = True, include_repositories: bool = True, **kwargs) -> Dict[str, Any]:
        """
        Analyze sensitive data exposure trends and changes over time for an organization.
        Provides time-based, asset-level trend analysis by application and repository.
        Use this to answer questions like 'How is sensitive data risk changing over time?' or 'Which apps are trending up or down in exposure?'.
        For a current grouped snapshot, use get_sensitive_data_report instead.
        """
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



    async def _check_repository_attack_surface(self, repo_name: str = None, org_id: str = None, include_vulnerabilities: bool = True, include_apps: bool = True, **kwargs) -> Dict[str, Any]:
        """Check if a repository name exists in StackHawk attack surface and get security information"""
        try:
            # Get repo name and org_id using helper methods
            repo_name = self._get_current_repository_name(repo_name)
            org_id = await self._get_organization_id(org_id)

            # Find matching repositories
            matching_repos = await self._find_matching_repositories(repo_name, org_id)
            
            result = {
                "repository_name": repo_name,
                "organization_id": org_id,
                "found_in_attack_surface": len(matching_repos) > 0,
                "matching_repositories": matching_repos,
                "timestamp": datetime.now().isoformat()
            }
            
            if matching_repos:
                repo = matching_repos[0]  # Take the first match
                repo_id = repo["id"]
                
                # Get repository details with fallback
                try:
                    repo_details = await self.client.get_repository_details(org_id, repo_id)
                    result["repository_details"] = repo_details
                except Exception as e:
                    debug_print(f"Repository details endpoint not available: {e}")
                    result["repository_details"] = {
                        "note": "Repository details endpoint not available in API",
                        "basic_info": repo
                    }
                
                # Get security scan results if requested with fallback
                if include_vulnerabilities:
                    try:
                        scan_results = await self.client.get_repository_security_scan(org_id, repo_id)
                        result["security_scan"] = scan_results
                    except Exception as e:
                        debug_print(f"Repository security scan endpoint not available: {e}")
                        # Fallback: Try to get scan results from applications connected to this repo
                        result["security_scan"] = {
                            "note": "Repository-level security scanning not available",
                            "fallback_recommendation": "Check connected applications for security scan results",
                            "error": str(e)
                        }
                
                # Get connected applications if requested
                if include_apps:
                    try:
                        # Get applications and find ones connected to this repository
                        apps_response = await self.client.list_applications(org_id, pageSize=1000)
                        applications = apps_response.get("applications", [])
                        
                        connected_apps = []
                        for app in applications:
                            # Check if app is connected to this repository
                            # This is a simplified check - in reality you'd check app metadata or configuration
                            if repo_name.lower() in app.get("name", "").lower():
                                connected_apps.append(app)
                        
                        result["connected_applications"] = connected_apps
                        result["total_connected_apps"] = len(connected_apps)
                    except Exception as e:
                        debug_print(f"Could not get connected applications: {e}")
                        result["connected_applications"] = []
                
                result["recommendation"] = f"Repository '{repo_name}' is found in your StackHawk attack surface. Review the security findings and ensure proper monitoring is in place."
            else:
                result["recommendation"] = f"Repository '{repo_name}' is not found in your StackHawk attack surface. Consider adding it for security monitoring if it contains application code."
            
            return result
            
        except Exception as e:
            debug_print(f"Error in _check_repository_attack_surface: {e}")
            return {
                "error": str(e),
                "repository_name": repo_name,
                "message": "Failed to check repository attack surface"
            }

    async def _check_repository_sensitive_data(self, repo_name: str = None, org_id: str = None, data_type_filter: str = "All", include_remediation: bool = True, **kwargs) -> Dict[str, Any]:
        """Check if a repository has sensitive data findings in StackHawk"""
        try:
            # Get repo name and org_id using helper methods
            repo_name = self._get_current_repository_name(repo_name)
            org_id = await self._get_organization_id(org_id)

            # Find matching repositories
            matching_repos = await self._find_matching_repositories(repo_name, org_id)
            
            result = {
                "repository_name": repo_name,
                "organization_id": org_id,
                "found_in_stackhawk": len(matching_repos) > 0,
                "has_sensitive_data": False,
                "sensitive_data_findings": [],
                "timestamp": datetime.now().isoformat()
            }
            
            if matching_repos:
                repo = matching_repos[0]  # Take the first match
                repo_id = repo["id"]
                result["repository_id"] = repo_id
                
                # Get sensitive data findings for this repository with fallback
                try:
                    sensitive_data = await self.client.get_repository_sensitive_data(org_id, repo_id, pageSize=100)
                    findings = sensitive_data.get("sensitiveDataFindings", [])
                    
                    # Apply data type filter
                    if data_type_filter != "All":
                        findings = [f for f in findings if f.get("dataType") == data_type_filter]
                    
                    result["has_sensitive_data"] = len(findings) > 0
                    result["sensitive_data_findings"] = findings
                    result["total_findings"] = len(findings)
                    result["data_type_breakdown"] = self._calculate_data_type_breakdown(findings)
                    
                    if include_remediation and findings:
                        result["remediation_recommendations"] = [
                            f"Review and secure {finding.get('dataType', 'Unknown')} data found at {finding.get('location', 'Unknown location')}"
                            for finding in findings[:5]  # Top 5 recommendations
                        ]
                    
                    if findings:
                        result["recommendation"] = f"Repository '{repo_name}' contains {len(findings)} sensitive data findings. Immediate review and remediation recommended."
                    else:
                        result["recommendation"] = f"Repository '{repo_name}' is monitored by StackHawk but has no sensitive data findings detected."
                        
                except Exception as e:
                    debug_print(f"Repository-level sensitive data endpoint not available: {e}")
                    # Fallback: Get org-wide sensitive data and filter by repository
                    try:
                        org_sensitive_data = await self.client.list_sensitive_data_findings(org_id, pageSize=1000)
                        org_findings = org_sensitive_data.get("sensitiveDataFindings", [])
                        
                        # Filter findings for this repository (by name matching)
                        repo_findings = [
                            f for f in org_findings 
                            if (f.get("repositoryId") == repo_id or 
                                f.get("repositoryName", "").lower() == repo_name.lower())
                        ]
                        
                        # Apply data type filter
                        if data_type_filter != "All":
                            repo_findings = [f for f in repo_findings if f.get("dataType") == data_type_filter]
                        
                        result["has_sensitive_data"] = len(repo_findings) > 0
                        result["sensitive_data_findings"] = repo_findings
                        result["total_findings"] = len(repo_findings)
                        result["data_type_breakdown"] = self._calculate_data_type_breakdown(repo_findings)
                        result["fallback_used"] = True
                        result["fallback_note"] = "Used organization-level sensitive data filtering as repository endpoint not available"
                        
                        if include_remediation and repo_findings:
                            result["remediation_recommendations"] = [
                                f"Review and secure {finding.get('dataType', 'Unknown')} data found at {finding.get('location', 'Unknown location')}"
                                for finding in repo_findings[:5]
                            ]
                        
                        if repo_findings:
                            result["recommendation"] = f"Repository '{repo_name}' contains {len(repo_findings)} sensitive data findings (via fallback analysis). Immediate review and remediation recommended."
                        else:
                            result["recommendation"] = f"Repository '{repo_name}' has no sensitive data findings detected (via fallback analysis)."
                            
                    except Exception as fallback_error:
                        debug_print(f"Fallback sensitive data analysis also failed: {fallback_error}")
                        result["sensitive_data_error"] = str(e)
                        result["fallback_error"] = str(fallback_error)
                        result["recommendation"] = f"Repository '{repo_name}' is in StackHawk but sensitive data analysis failed. Repository-level endpoints may not be available in API."
            else:
                result["recommendation"] = f"Repository '{repo_name}' is not found in StackHawk. Consider adding it for sensitive data monitoring."
            
            return result
            
        except Exception as e:
            debug_print(f"Error in _check_repository_sensitive_data: {e}")
            return {
                "error": str(e),
                "repository_name": repo_name,
                "message": "Failed to check repository sensitive data"
            }

    async def _list_application_repository_connections(self, org_id: str = None, include_repo_details: bool = True, include_app_details: bool = True, filter_connected_only: bool = False, **kwargs) -> Dict[str, Any]:
        """List connections between StackHawk applications and code repositories"""
        try:
            # Get org_id using helper method
            org_id = await self._get_organization_id(org_id)

            # Get all applications and repositories
            apps_response = await self.client.list_applications(org_id, pageSize=1000)
            repos_response = await self.client.list_repositories(org_id, pageSize=1000)
            
            applications = apps_response.get("applications", [])
            repositories = repos_response.get("repositories", [])
            
            connections = []
            orphaned_apps = []
            orphaned_repos = []
            
            # Analyze connections between apps and repos
            for app in applications:
                app_name = app.get("name", "").lower()
                connected_repos = []
                
                # Find repositories that might be connected to this app
                for repo in repositories:
                    repo_name = repo.get("name", "").lower()
                    
                    # Simple connection logic - can be enhanced based on actual StackHawk metadata
                    if (app_name in repo_name or 
                        repo_name in app_name or 
                        self._calculate_name_similarity(app_name, repo_name) > 0.7):
                        connected_repos.append(repo)
                
                if connected_repos:
                    connection = {
                        "application": app,
                        "connected_repositories": connected_repos,
                        "connection_strength": "high" if len(connected_repos) == 1 else "medium"
                    }
                    
                    if include_app_details:
                        try:
                            app_details = await self.client.get_application(app["id"])
                            connection["application_details"] = app_details
                        except Exception as e:
                            debug_print(f"Could not get app details for {app['id']}: {e}")
                    
                    if include_repo_details:
                        repo_details = []
                        for repo in connected_repos:
                            try:
                                repo_detail = await self.client.get_repository_details(org_id, repo["id"])
                                repo_details.append(repo_detail)
                            except Exception as e:
                                debug_print(f"Could not get repo details for {repo['id']}: {e}")
                                repo_details.append(repo)  # Use basic info if detailed fetch fails
                        connection["repository_details"] = repo_details
                    
                    connections.append(connection)
                elif not filter_connected_only:
                    orphaned_apps.append(app)
            
            # Find repositories without app connections
            if not filter_connected_only:
                connected_repo_ids = set()
                for conn in connections:
                    for repo in conn["connected_repositories"]:
                        connected_repo_ids.add(repo["id"])
                
                orphaned_repos = [repo for repo in repositories if repo["id"] not in connected_repo_ids]
            
            result = {
                "organization_id": org_id,
                "total_applications": len(applications),
                "total_repositories": len(repositories),
                "total_connections": len(connections),
                "connections": connections,
                "coverage_stats": {
                    "connected_applications": len(connections),
                    "orphaned_applications": len(orphaned_apps),
                    "orphaned_repositories": len(orphaned_repos),
                    "connection_coverage": (len(connections) / max(len(applications), 1)) * 100
                },
                "timestamp": datetime.now().isoformat()
            }
            
            if not filter_connected_only:
                result["orphaned_applications"] = orphaned_apps
                result["orphaned_repositories"] = orphaned_repos
            
            # Add recommendations
            recommendations = []
            if orphaned_apps:
                recommendations.append(f"Consider connecting {len(orphaned_apps)} orphaned applications to their corresponding repositories")
            if orphaned_repos:
                recommendations.append(f"Consider creating applications for {len(orphaned_repos)} unmonitored repositories")
            if result["coverage_stats"]["connection_coverage"] < 50:
                recommendations.append("Low connection coverage detected. Review naming conventions and application-repository mappings")
            
            result["recommendations"] = recommendations
            
            return result
            
        except Exception as e:
            debug_print(f"Error in _list_application_repository_connections: {e}")
            return {
                "error": str(e),
                "message": "Failed to list application-repository connections",
                "organization_id": org_id
            }

    def _get_current_repository_name(self, repo_name: str = None) -> str:
        """Get repository name from parameter or auto-detect from current directory"""
        if repo_name:
            return repo_name
        return os.path.basename(os.getcwd())
    
    async def _check_endpoint_availability(self, endpoint: str, method: str = "GET") -> bool:
        """Check if an API endpoint is available by making a test request"""
        try:
            # Make a test request to see if the endpoint exists
            await self.client._make_request(method, endpoint)
            return True
        except Exception as e:
            # Check if it's a 404 (endpoint doesn't exist) vs other errors
            if "404" in str(e) or "Not Found" in str(e):
                return False
            # For other errors (auth, permissions, etc.), assume endpoint exists
            return True
    
    async def _get_organization_id(self, org_id: str = None) -> str:
        """Get organization ID from parameter or auto-detect from user info"""
        if org_id:
            return org_id
        
        user_info = await self.client.get_user_info()
        organizations = user_info.get("user", {}).get("external", {}).get("organizations", [])
        
        if not organizations:
            raise ValueError("No organizations found for user")
        
        return organizations[0]["organization"]["id"]
    
    async def _find_matching_repositories(self, repo_name: str, org_id: str) -> List[Dict[str, Any]]:
        """Find repositories matching the given name (case-insensitive)"""
        repos_response = await self.client.list_repositories(org_id, pageSize=1000)
        repositories = repos_response.get("repositories", [])
        
        # Find matching repositories (case-insensitive)
        return [
            repo for repo in repositories
            if repo.get("name", "").lower() == repo_name.lower()
        ]

    def _calculate_name_similarity(self, name1: str, name2: str) -> float:
        """Calculate similarity between two names using simple string matching"""
        if not name1 or not name2:
            return 0.0
        
        # Simple similarity calculation based on common words and substrings
        words1 = set(name1.lower().split('-'))
        words2 = set(name2.lower().split('-'))
        
        if not words1 or not words2:
            return 0.0
        
        common_words = words1.intersection(words2)
        total_words = words1.union(words2)
        
        return len(common_words) / len(total_words) if total_words else 0.0

    async def _get_comprehensive_sensitive_data_summary(self, org_id: str = None, time_period: str = "30d", include_trends: bool = True, include_critical_only: bool = False, include_recommendations: bool = True, group_by: str = "data_type", **kwargs) -> Dict[str, Any]:
        """Get a comprehensive sensitive data summary combining multiple analysis approaches"""
        try:
            # Get org_id using helper method
            org_id = await self._get_organization_id(org_id)

            # Get all sensitive data findings
            if time_period == "all":
                findings_response = await self.client.list_sensitive_data_findings(org_id, all_results=True)
            else:
                findings_response = await self.client.list_sensitive_data_findings(org_id, pageSize=1000)
            
            findings = findings_response.get("sensitiveDataFindings", [])
            
            # Filter for critical findings only if requested
            if include_critical_only:
                critical_data_types = ["PII", "PCI", "PHI"]
                findings = [f for f in findings if f.get("dataType") in critical_data_types]
            
            # Group findings based on the group_by parameter
            grouped_findings = {}
            for finding in findings:
                if group_by == "data_type":
                    key = finding.get("dataType", "Unknown")
                elif group_by == "application":
                    key = finding.get("applicationId", "Unknown")
                elif group_by == "repository":
                    key = finding.get("repositoryId", "Unknown")
                else:
                    key = finding.get("dataType", "Unknown")
                
                if key not in grouped_findings:
                    grouped_findings[key] = []
                grouped_findings[key].append(finding)
            
            # Build comprehensive summary
            summary = {
                "organization_id": org_id,
                "time_period": time_period,
                "analysis_type": "comprehensive",
                "total_findings": len(findings),
                "critical_only": include_critical_only,
                "group_by": group_by,
                "grouped_summary": {},
                "overall_risk_score": self._calculate_sensitive_data_risk_score(findings),
                "data_type_breakdown": self._calculate_data_type_breakdown(findings),
                "timestamp": datetime.now().isoformat()
            }
            
            # Create grouped summary
            for group_key, group_findings in grouped_findings.items():
                summary["grouped_summary"][group_key] = {
                    "count": len(group_findings),
                    "data_types": list(set(f.get("dataType", "Unknown") for f in group_findings)),
                    "risk_score": self._calculate_sensitive_data_risk_score(group_findings),
                    "applications": list(set(f.get("applicationId") for f in group_findings if f.get("applicationId"))),
                    "repositories": list(set(f.get("repositoryId") for f in group_findings if f.get("repositoryId")))
                }
            
            # Add trend analysis if requested
            if include_trends:
                try:
                    trend_analysis = await self._analyze_sensitive_data_trends(org_id, analysis_period="90d", include_applications=True, include_repositories=True)
                    summary["trend_analysis"] = trend_analysis.get("trends", {})
                except Exception as e:
                    debug_print(f"Could not include trend analysis: {e}")
                    summary["trend_analysis"] = {"error": str(e)}
            
            # Add recommendations if requested
            if include_recommendations:
                recommendations = []
                
                # Critical findings recommendations
                critical_count = len([f for f in findings if f.get("dataType") in ["PII", "PCI", "PHI"]])
                if critical_count > 0:
                    recommendations.append(f"Immediate attention required: {critical_count} critical sensitive data findings detected")
                
                # High-volume data types
                for data_type, type_findings in grouped_findings.items():
                    if len(type_findings) > 10:
                        recommendations.append(f"High volume of {data_type} findings ({len(type_findings)}) - consider implementing automated remediation")
                
                # Coverage recommendations
                unique_apps = len(set(f.get("applicationId") for f in findings if f.get("applicationId")))
                unique_repos = len(set(f.get("repositoryId") for f in findings if f.get("repositoryId")))
                
                if unique_apps > 0:
                    recommendations.append(f"Sensitive data detected across {unique_apps} applications - ensure consistent data handling policies")
                if unique_repos > 0:
                    recommendations.append(f"Sensitive data detected across {unique_repos} repositories - review code scanning configurations")
                
                summary["recommendations"] = recommendations
            
            return summary
            
        except Exception as e:
            debug_print(f"Error in _get_comprehensive_sensitive_data_summary: {e}")
            return {
                "error": str(e),
                "message": "Failed to generate comprehensive sensitive data summary",
                "organization_id": org_id
            }


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