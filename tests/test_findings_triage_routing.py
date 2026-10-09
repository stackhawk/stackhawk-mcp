"""
Tool routing tests — verify every MCP tool handler resolves to a real method
and calls it with the correct arguments.

These tests catch wiring bugs (e.g. calling self.foo() when foo lives on
self.client) without needing a live API key.

Any new tool added to handle_call_tool MUST have a corresponding test here.

The "internal logic" tests at the bottom exercise methods like
_get_application_vulnerabilities end-to-end with mocked API calls, catching
bugs like missing helper methods that routing tests alone can't find.
"""

import json
import sys
import os
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from stackhawk_mcp.server import StackHawkMCPServer
from mcp.types import CallToolRequest, CallToolRequestParams


async def _call_tool(server, name: str, arguments: dict):
    """Invoke a tool through the MCP server's registered handler."""
    handler = server.server.request_handlers.get(CallToolRequest)
    assert handler is not None, "CallToolRequest handler not registered"
    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name=name, arguments=arguments),
    )
    response = await handler(request)
    return json.loads(response.root.content[0].text)


# ---------------------------------------------------------------------------
# 1. get_organization_info
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_organization_info_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"orgId": "org-1", "name": "Test Org"}
    server._get_organization_info = AsyncMock(return_value=mock_result)

    body = await _call_tool(server, "get_organization_info", {"org_id": "org-1"})

    server._get_organization_info.assert_awaited_once_with(org_id="org-1")
    assert body["orgId"] == "org-1"


# ---------------------------------------------------------------------------
# 2. list_applications
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_list_applications_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"applications": [{"id": "app-1", "name": "My App"}]}
    server._list_applications = AsyncMock(return_value=mock_result)

    body = await _call_tool(server, "list_applications", {"org_id": "org-1"})

    server._list_applications.assert_awaited_once_with(org_id="org-1")
    assert len(body["applications"]) == 1


# ---------------------------------------------------------------------------
# 3. validate_stackhawk_config
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_validate_stackhawk_config_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"valid": True}
    server._validate_stackhawk_config = AsyncMock(return_value=mock_result)

    yaml_content = "app:\n  applicationId: abc-123"
    body = await _call_tool(
        server, "validate_stackhawk_config", {"yaml_content": yaml_content}
    )

    server._validate_stackhawk_config.assert_awaited_once_with(yaml_content=yaml_content)
    assert body["valid"] is True


# ---------------------------------------------------------------------------
# 4. validate_field_exists
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_validate_field_exists_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"exists": True, "field_path": "app.applicationId"}
    server._validate_field_exists = AsyncMock(return_value=mock_result)

    body = await _call_tool(
        server, "validate_field_exists", {"field_path": "app.applicationId"}
    )

    server._validate_field_exists.assert_awaited_once_with(field_path="app.applicationId")
    assert body["exists"] is True


# ---------------------------------------------------------------------------
# 5. setup_stackhawk_for_project
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_setup_stackhawk_for_project_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"status": "created", "config_path": "stackhawk.yml"}
    server._setup_stackhawk_for_project = AsyncMock(return_value=mock_result)

    body = await _call_tool(
        server,
        "setup_stackhawk_for_project",
        {"host": "http://localhost:8080", "environment": "dev"},
    )

    server._setup_stackhawk_for_project.assert_awaited_once_with(
        host="http://localhost:8080", environment="dev"
    )
    assert body["status"] == "created"


# ---------------------------------------------------------------------------
# 6. run_stackhawk_scan
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_run_stackhawk_scan_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"status": "complete", "findings": 3}
    server.client.run_stackhawk_scan = AsyncMock(return_value=mock_result)

    body = await _call_tool(
        server, "run_stackhawk_scan", {"config_path": "my-config.yml"}
    )

    server.client.run_stackhawk_scan.assert_awaited_once_with("my-config.yml")
    assert body["status"] == "complete"


@pytest.mark.asyncio
async def test_run_stackhawk_scan_default_config():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {"status": "complete"}
    server.client.run_stackhawk_scan = AsyncMock(return_value=mock_result)

    await _call_tool(server, "run_stackhawk_scan", {})

    server.client.run_stackhawk_scan.assert_awaited_once_with("stackhawk.yml")


# ---------------------------------------------------------------------------
# 7. get_app_findings_for_triage
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_app_findings_for_triage_routing():
    server = StackHawkMCPServer(api_key="dummy")
    mock_result = {
        "applicationName": "test-app",
        "totalFindings": 1,
        "findings": [{"findingName": "XSS", "findingRisk": "High"}],
    }
    server.client._get_application_vulnerabilities = AsyncMock(return_value=mock_result)

    body = await _call_tool(
        server, "get_app_findings_for_triage", {"app_id": "abc-123"}
    )

    server.client._get_application_vulnerabilities.assert_awaited_once_with(
        app_id="abc-123",
        config_path=None,
        config_content=None,
        triage_mode=True,
        failure_threshold=None,
    )
    assert body["applicationName"] == "test-app"
    assert body["totalFindings"] == 1


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unknown_tool_returns_error():
    server = StackHawkMCPServer(api_key="dummy")

    handler = server.server.request_handlers.get(CallToolRequest)
    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name="totally_fake_tool", arguments={}),
    )
    response = await handler(request)
    body = json.loads(response.root.content[0].text)
    assert "error" in body or "Unknown tool" in body.get("message", "")


# ===========================================================================
# Internal logic tests — exercise method internals with mocked API calls
# ===========================================================================

MOCK_FINDINGS = [
    {"findingName": "XSS", "findingRisk": "High", "status": "Open"},
    {"findingName": "SQLi", "findingRisk": "High", "status": "Open"},
    {"findingName": "CSRF", "findingRisk": "Medium", "status": "Open"},
    {"findingName": "Info Leak", "findingRisk": "Low", "status": "Open"},
]

MOCK_USER_INFO = {
    "user": {
        "external": {
            "organizations": [{"organization": {"id": "org-1", "name": "Test Org"}}]
        }
    }
}


def _mock_client_apis(client):
    """Mock all StackHawkClient API methods used by _get_application_vulnerabilities."""
    client.get_user_info = AsyncMock(return_value=MOCK_USER_INFO)
    client.get_application_findings = AsyncMock(
        return_value={"findings": MOCK_FINDINGS}
    )
    client.get_application = AsyncMock(
        return_value={"name": "My App", "id": "app-1"}
    )


# ---------------------------------------------------------------------------
# _get_application_vulnerabilities — with explicit app_id
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_application_vulnerabilities_with_app_id():
    """Exercise the full method with an explicit app_id — no config lookup needed."""
    server = StackHawkMCPServer(api_key="dummy")
    _mock_client_apis(server.client)

    result = await server.client._get_application_vulnerabilities(
        app_id="app-1",
        severity_filter="All",
    )

    assert result["applicationId"] == "app-1"
    assert result["applicationName"] == "My App"
    assert result["totalFindings"] == 4
    assert result["severityBreakdown"]["High"] == 2
    assert result["severityBreakdown"]["Medium"] == 1
    assert result["severityBreakdown"]["Low"] == 1


# ---------------------------------------------------------------------------
# _get_application_vulnerabilities — triage mode filters correctly
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_application_vulnerabilities_triage_mode():
    """Triage mode should filter to High/Medium only."""
    server = StackHawkMCPServer(api_key="dummy")
    _mock_client_apis(server.client)

    result = await server.client._get_application_vulnerabilities(
        app_id="app-1",
        triage_mode=True,
        failure_threshold="Medium",
    )

    assert result["triageMode"] is True
    assert result["totalFindings"] == 3  # 2 High + 1 Medium, no Low
    assert all(
        f["findingRisk"] in ["High", "Medium"] for f in result["findings"]
    )


# ---------------------------------------------------------------------------
# _get_application_vulnerabilities — severity filter (non-triage)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_application_vulnerabilities_severity_filter():
    """Non-triage severity filter should return only matching findings."""
    server = StackHawkMCPServer(api_key="dummy")
    _mock_client_apis(server.client)

    result = await server.client._get_application_vulnerabilities(
        app_id="app-1",
        severity_filter="High",
    )

    assert result["totalFindings"] == 2
    assert all(f["findingRisk"] == "High" for f in result["findings"])


# ---------------------------------------------------------------------------
# _get_application_vulnerabilities — triage via config_content
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_application_vulnerabilities_triage_from_config_content():
    """Triage mode should parse config_content for app_id and failureThreshold."""
    server = StackHawkMCPServer(api_key="dummy")
    _mock_client_apis(server.client)

    config_yaml = """
app:
  applicationId: app-from-config
hawk:
  failureThreshold: medium
"""
    result = await server.client._get_application_vulnerabilities(
        triage_mode=True,
        config_content=config_yaml,
    )

    assert result["applicationId"] == "app-from-config"
    assert result["failureThreshold"] == "Medium"
    assert result["triageMode"] is True


# ---------------------------------------------------------------------------
# _get_project_open_stackhawk_issues — exercises the other caller
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_project_open_stackhawk_issues(tmp_path):
    """Exercise _get_project_open_stackhawk_issues with a temp config file."""
    server = StackHawkMCPServer(api_key="dummy")
    _mock_client_apis(server.client)

    config_file = tmp_path / "stackhawk.yml"
    config_file.write_text(
        "app:\n  applicationId: app-1\nhawk:\n  failureThreshold: High\n"
    )

    result = await server.client._get_project_open_stackhawk_issues(
        config_path=str(config_file)
    )

    assert result["applicationId"] == "app-1"
    assert result["failureThreshold"] == "High"
    assert result["totalOpenIssues"] == 3  # 2 High + 1 Medium (always included)
    assert "open_issues_summary" in result
    assert result["open_issues_summary"]["High"] == 2
    assert result["open_issues_summary"]["Medium"] == 1
