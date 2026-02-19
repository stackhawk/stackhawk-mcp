#!/usr/bin/env python3
"""
Scenario tests that replay real user conversation flows through the full MCP call_tool path.

These tests exercise server.call_tool(name, arguments) → handle_call_tool → internal method → TextContent JSON response,
mirroring the exact sequence of tool calls an LLM agent would make.

Source: docs/user-feedback/chat_history.txt (Naveen Hebbar's session)
Broken YAML: docs/user-feedback/mcp-generated-stackhawk.yml
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import tempfile
import yaml
import pytest
from unittest.mock import AsyncMock
from stackhawk_mcp.server import StackHawkMCPServer


MOCK_SCHEMA = {
    "type": "object",
    "properties": {
        "app": {
            "type": "object",
            "properties": {
                "applicationId": {"type": "string"},
                "env": {"type": "string"},
                "host": {"type": "string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["applicationId", "env", "host"],
        },
        "hawk": {
            "type": "object",
            "properties": {
                "spider": {"type": "object"},
                "scan": {"type": "object"},
                "startupTimeoutMinutes": {"type": "integer"},
                "failureThreshold": {"type": "string"},
            },
        },
        "tags": {"type": "array", "items": {"type": "object"}},
    },
}

MOCK_USER_INFO = {
    "user": {
        "external": {
            "organizations": [
                {"organization": {"id": "org-123", "name": "Test Org"}}
            ]
        }
    }
}


def _parse_call_tool_response(response):
    """Parse the TextContent list returned by call_tool into a dict."""
    assert len(response) >= 1
    return json.loads(response[0].text)


def _make_server_with_mocks(
    *, apps=None, created_app=None, schema=None
):
    """Create a StackHawkMCPServer with common API mocks."""
    server = StackHawkMCPServer("mock-api-key")
    server.client.get_user_info = AsyncMock(return_value=MOCK_USER_INFO)
    server.client.list_applications = AsyncMock(
        return_value={"applications": apps or []}
    )
    if created_app is not None:
        server.client.create_application = AsyncMock(return_value=created_app)
    server._get_schema = AsyncMock(return_value=schema or MOCK_SCHEMA)
    return server


# ---------------------------------------------------------------------------
# Scenario 1: Happy path — setup generates runnable config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_happy_path_setup_generates_runnable_config():
    """Replay the ideal flow: setup → get YAML → validate YAML.
    This is the flow that should have worked for Naveen on the first try."""
    existing_app = {"id": "app-456", "name": "AgentApp"}
    server = _make_server_with_mocks(apps=[existing_app])

    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)

            # Step 1: setup_stackhawk_for_project via call_tool
            response = await server.call_tool(
                "setup_stackhawk_for_project",
                {
                    "host": "https://ginandjuice.shop/",
                    "environment": "Staging",
                    "app_name": "AgentApp",
                },
            )
            result = _parse_call_tool_response(response)

            assert result["success"] is True
            assert result["configGenerated"] is True
            assert result["applicationId"] == "app-456"

            config_yaml = result["configYaml"]
            parsed = yaml.safe_load(config_yaml)
            assert "app" in parsed
            assert parsed["app"]["applicationId"] == "app-456"
            assert "ginandjuice.shop" in parsed["app"]["host"]
            assert parsed["app"]["env"] == "Staging"

            # Step 2: validate the generated config via call_tool
            response = await server.call_tool(
                "validate_stackhawk_config",
                {"yaml_content": config_yaml},
            )
            validation = _parse_call_tool_response(response)
            assert validation["valid"] is True
        finally:
            os.chdir(original_cwd)


# ---------------------------------------------------------------------------
# Scenario 2: Tags-only config is caught by validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_tags_only_config_rejected_by_validation():
    """Replay the broken flow: a tags-only YAML (no app section) must fail validation.
    This is the exact bug from Naveen's session — the old validator said 'valid'."""
    tags_only_yaml = (
        "tags:\n"
        "- name: environment\n"
        "  value: dev\n"
        "- name: application\n"
        "  value: agentapp\n"
    )
    server = _make_server_with_mocks()

    response = await server.call_tool(
        "validate_stackhawk_config",
        {"yaml_content": tags_only_yaml},
    )
    result = _parse_call_tool_response(response)

    assert result["valid"] is False
    assert result["error_type"] == "MISSING_REQUIRED_FIELDS"
    assert any("app" in e.lower() for e in result["errors"])
    assert "fix_suggestion" in result


# ---------------------------------------------------------------------------
# Scenario 3: Setup with existing app still generates config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_setup_with_existing_app_generates_config():
    """When the app already exists (as in Naveen's session), setup should still
    generate a complete config with the app section."""
    existing_app = {"id": "existing-app-id", "name": "AgentApp"}
    server = _make_server_with_mocks(apps=[existing_app])

    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            response = await server.call_tool(
                "setup_stackhawk_for_project",
                {
                    "host": "https://ginandjuice.shop/",
                    "environment": "Staging",
                    "app_name": "AgentApp",
                },
            )
            result = _parse_call_tool_response(response)

            assert result["appStatus"] == "found"
            assert result["configGenerated"] is True
            assert result["applicationId"] == "existing-app-id"

            parsed = yaml.safe_load(result["configYaml"])
            assert "app" in parsed
            assert parsed["app"]["applicationId"] == "existing-app-id"
            assert parsed["app"]["env"] == "Staging"
            assert "ginandjuice.shop" in parsed["app"]["host"]
        finally:
            os.chdir(original_cwd)


# ---------------------------------------------------------------------------
# Scenario 4: Setup with new app creates app then generates config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_setup_creates_new_app_and_config():
    """When no matching app exists, setup should create the app then generate config."""
    new_app = {"id": "new-app-789", "name": "my-project"}
    server = _make_server_with_mocks(apps=[], created_app=new_app)

    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            response = await server.call_tool(
                "setup_stackhawk_for_project",
                {
                    "host": "http://localhost:8080",
                    "environment": "dev",
                },
            )
            result = _parse_call_tool_response(response)

            assert result["success"] is True
            assert result["appStatus"] == "created"
            assert result["configGenerated"] is True
            assert result["applicationId"] == "new-app-789"

            parsed = yaml.safe_load(result["configYaml"])
            assert "app" in parsed
            assert parsed["app"]["applicationId"] == "new-app-789"
            assert parsed["app"]["env"] == "dev"
            assert "localhost" in parsed["app"]["host"]
            assert "8080" in parsed["app"]["host"]
        finally:
            os.chdir(original_cwd)


# ---------------------------------------------------------------------------
# Scenario 5: Generated config validates successfully (end-to-end)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_generated_config_validates_end_to_end():
    """End-to-end: setup → extract YAML → validate. The generated config must pass validation."""
    existing_app = {"id": "e2e-app-id", "name": "e2e-test"}
    server = _make_server_with_mocks(apps=[existing_app])

    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)

            # Step 1: generate config
            setup_response = await server.call_tool(
                "setup_stackhawk_for_project",
                {
                    "host": "https://myapp.example.com",
                    "environment": "production",
                    "app_name": "e2e-test",
                },
            )
            setup_result = _parse_call_tool_response(setup_response)
            assert setup_result["configGenerated"] is True

            # Step 2: validate the generated YAML
            validate_response = await server.call_tool(
                "validate_stackhawk_config",
                {"yaml_content": setup_result["configYaml"]},
            )
            validate_result = _parse_call_tool_response(validate_response)
            assert validate_result["valid"] is True
        finally:
            os.chdir(original_cwd)


# ---------------------------------------------------------------------------
# Scenario 6: Exact broken YAML from user feedback fails validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_exact_broken_yaml_from_user_feedback_fails():
    """Validate the literal broken YAML from docs/user-feedback/mcp-generated-stackhawk.yml.
    This file was the actual output Naveen received — tags only, no app section."""
    broken_yaml_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "docs",
        "user-feedback",
        "mcp-generated-stackhawk.yml",
    )

    if not os.path.exists(broken_yaml_path):
        pytest.skip("docs/user-feedback/mcp-generated-stackhawk.yml not found")

    with open(broken_yaml_path) as f:
        broken_yaml = f.read()

    server = _make_server_with_mocks()

    response = await server.call_tool(
        "validate_stackhawk_config",
        {"yaml_content": broken_yaml},
    )
    result = _parse_call_tool_response(response)

    assert result["valid"] is False
    assert any("app" in e.lower() for e in result.get("errors", [result.get("error", "")]))
    assert "fix_suggestion" in result
