#!/usr/bin/env python3
"""
Tests for MCP UX improvements:
- Validation catches broken configs (missing app, applicationId, host, env)
- URL parsing for setup tool
- C#/.NET language detection
- Error responses include fix_suggestion
- Config creation includes next_steps
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import glob
import json
import tempfile
import yaml
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from stackhawk_mcp.server import StackHawkMCPServer


# --- Validation tests ---

@pytest.mark.asyncio
async def test_validate_rejects_tags_only_config():
    """A config with only tags and no app section should fail validation."""
    server = StackHawkMCPServer("mock-api-key")
    tags_only_config = """
tags:
  - name: environment
    value: dev
  - name: application
    value: my-app
"""
    result = await server._validate_stackhawk_config(tags_only_config)
    assert result["valid"] is False
    assert result["error_type"] == "MISSING_REQUIRED_FIELDS"
    assert any("app" in e.lower() for e in result["errors"])
    assert "fix_suggestion" in result


@pytest.mark.asyncio
async def test_validate_rejects_missing_application_id():
    """Config with app section but no applicationId should fail.
    May fail as SCHEMA_VALIDATION_ERROR or MISSING_REQUIRED_FIELDS depending on schema."""
    server = StackHawkMCPServer("mock-api-key")
    config = """
app:
  host: "https://localhost:3000"
  env: "dev"
"""
    result = await server._validate_stackhawk_config(config)
    assert result["valid"] is False
    assert result["error_type"] in ("MISSING_REQUIRED_FIELDS", "SCHEMA_VALIDATION_ERROR")
    assert "fix_suggestion" in result


@pytest.mark.asyncio
async def test_validate_rejects_missing_host():
    """Config with app section but no host should fail."""
    server = StackHawkMCPServer("mock-api-key")
    config = """
app:
  applicationId: "12345678-1234-1234-1234-123456789012"
  env: "dev"
"""
    result = await server._validate_stackhawk_config(config)
    assert result["valid"] is False
    assert result["error_type"] in ("MISSING_REQUIRED_FIELDS", "SCHEMA_VALIDATION_ERROR")
    assert "fix_suggestion" in result


@pytest.mark.asyncio
async def test_validate_rejects_missing_env():
    """Config with app section but no env should fail."""
    server = StackHawkMCPServer("mock-api-key")
    config = """
app:
  applicationId: "12345678-1234-1234-1234-123456789012"
  host: "https://localhost:3000"
"""
    result = await server._validate_stackhawk_config(config)
    assert result["valid"] is False
    assert result["error_type"] in ("MISSING_REQUIRED_FIELDS", "SCHEMA_VALIDATION_ERROR")
    assert "fix_suggestion" in result


@pytest.mark.asyncio
async def test_validate_accepts_complete_config():
    """A complete config with app.applicationId, host, and env should pass."""
    server = StackHawkMCPServer("mock-api-key")
    config = """
app:
  applicationId: "12345678-1234-1234-1234-123456789012"
  host: "https://localhost:3000"
  env: "dev"
"""
    result = await server._validate_stackhawk_config(config)
    assert result["valid"] is True
    assert "cli_validation" in result


@pytest.mark.asyncio
async def test_validate_error_responses_include_fix_suggestion():
    """All validation error responses should include fix_suggestion."""
    server = StackHawkMCPServer("mock-api-key")

    # YAML parse error
    result = await server._validate_stackhawk_config("invalid: yaml: :\n  bad")
    if not result["valid"]:
        assert "fix_suggestion" in result

    # Missing required fields
    result = await server._validate_stackhawk_config("tags:\n  - name: foo\n    value: bar")
    assert not result["valid"]
    assert "fix_suggestion" in result


# --- URL parsing tests ---

def test_parse_host_url_with_port():
    """Parse URL with explicit port."""
    result = StackHawkMCPServer._parse_host_url("https://localhost:3000")
    assert result["protocol"] == "https"
    assert result["hostname"] == "localhost"
    assert result["port"] == 3000


def test_parse_host_url_https_default_port():
    """Parse https URL without port defaults to 443."""
    result = StackHawkMCPServer._parse_host_url("https://example.com")
    assert result["protocol"] == "https"
    assert result["hostname"] == "example.com"
    assert result["port"] == 443


def test_parse_host_url_http_default_port():
    """Parse http URL without port defaults to 80."""
    result = StackHawkMCPServer._parse_host_url("http://myapp.local")
    assert result["protocol"] == "http"
    assert result["hostname"] == "myapp.local"
    assert result["port"] == 80


def test_parse_host_url_with_path():
    """Parse URL with path — hostname should not include path."""
    result = StackHawkMCPServer._parse_host_url("https://ginandjuice.shop/api")
    assert result["hostname"] == "ginandjuice.shop"
    assert result["protocol"] == "https"


# --- Config creation tests ---

@pytest.mark.asyncio
async def test_create_config_includes_next_steps():
    """Created config should include next_steps in response."""
    server = StackHawkMCPServer("mock-api-key")
    with tempfile.TemporaryDirectory() as tmpdir:
        result = await server._create_stackhawk_config(
            application_id="12345678-1234-1234-1234-123456789012",
            app_name="Test App",
            host="localhost",
            port=3000,
            environment="dev",
            protocol="http",
            config_path=os.path.join(tmpdir, "stackhawk.yml")
        )
        assert result["success"] is True
        assert "next_steps" in result
        assert len(result["next_steps"]) >= 2


@pytest.mark.asyncio
async def test_create_config_has_complete_app_section():
    """Generated config YAML should have complete app section even if schema doesn't require it."""
    server = StackHawkMCPServer("mock-api-key")
    # Mock schema that doesn't mark 'app' as required (reproducing the real bug)
    mock_schema = {
        "type": "object",
        "properties": {
            "app": {
                "type": "object",
                "properties": {
                    "applicationId": {"type": "string"},
                    "env": {"type": "string"},
                    "host": {"type": "string"},
                }
            },
            "tags": {"type": "array", "items": {"type": "object"}}
        }
    }
    server._get_schema = AsyncMock(return_value=mock_schema)
    with tempfile.TemporaryDirectory() as tmpdir:
        result = await server._create_stackhawk_config(
            application_id="test-app-id",
            app_name="My App",
            host="example.com",
            port=443,
            environment="staging",
            protocol="https",
            config_path=os.path.join(tmpdir, "stackhawk.yml")
        )
        assert result["success"] is True
        parsed = yaml.safe_load(result["yaml"])
        assert "app" in parsed
        assert parsed["app"]["applicationId"] == "test-app-id"
        assert parsed["app"]["env"] == "staging"
        assert "example.com" in parsed["app"]["host"]


# --- C#/.NET detection tests ---

def test_detect_csharp_from_csproj():
    """Should detect C# language from .csproj files."""
    server = StackHawkMCPServer("mock-api-key")
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a .csproj file
        csproj_path = os.path.join(tmpdir, "MyApp.csproj")
        with open(csproj_path, "w") as f:
            f.write('<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Microsoft.AspNetCore.Mvc" /></ItemGroup></Project>')

        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            result = server._detect_project_language_and_frameworks()
            assert result["language"] == "csharp"
            assert "aspnet-core" in result["frameworks"]
        finally:
            os.chdir(original_cwd)


def test_detect_csharp_blazor():
    """Should detect Blazor framework from .csproj."""
    server = StackHawkMCPServer("mock-api-key")
    with tempfile.TemporaryDirectory() as tmpdir:
        csproj_path = os.path.join(tmpdir, "BlazorApp.csproj")
        with open(csproj_path, "w") as f:
            f.write('<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Microsoft.AspNetCore.Components" /></ItemGroup></Project>')

        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            result = server._detect_project_language_and_frameworks()
            assert result["language"] == "csharp"
            assert "blazor" in result["frameworks"]
        finally:
            os.chdir(original_cwd)


def test_detect_csharp_from_sln():
    """Should detect C# from .sln file."""
    server = StackHawkMCPServer("mock-api-key")
    with tempfile.TemporaryDirectory() as tmpdir:
        sln_path = os.path.join(tmpdir, "MySolution.sln")
        with open(sln_path, "w") as f:
            f.write("Microsoft Visual Studio Solution File")

        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            result = server._detect_project_language_and_frameworks()
            assert result["language"] == "csharp"
        finally:
            os.chdir(original_cwd)


# --- Setup tool integration test ---

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
            "required": ["applicationId", "env", "host"]
        },
        "hawk": {
            "type": "object",
            "properties": {
                "spider": {"type": "object", "properties": {}},
                "scan": {"type": "object", "properties": {}},
                "startupTimeoutMinutes": {"type": "integer"},
                "failureThreshold": {"type": "string"},
            }
        },
        "tags": {
            "type": "array",
            "items": {"type": "object"}
        }
    }
}


@pytest.mark.asyncio
async def test_setup_tool_auto_generates_config():
    """setup_stackhawk_for_project should auto-generate a complete config."""
    server = StackHawkMCPServer("mock-api-key")

    # Mock the API calls
    server.client.get_user_info = AsyncMock(return_value={
        "user": {"external": {"organizations": [{"organization": {"id": "org-123", "name": "Test Org"}}]}}
    })
    server.client.list_applications = AsyncMock(return_value={
        "applications": [{"id": "app-456", "name": "my-existing-app"}]
    })
    server._get_schema = AsyncMock(return_value=MOCK_SCHEMA)

    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            result = await server._setup_stackhawk_for_project(
                host="https://localhost:3000",
                environment="dev",
                app_name="my-existing-app"
            )
            assert result["success"] is True
            assert result["configGenerated"] is True
            assert result["configYaml"] is not None
            assert result["applicationId"] == "app-456"
            assert "next_steps" in result

            # Verify the generated YAML has a complete app section
            parsed = yaml.safe_load(result["configYaml"])
            assert "app" in parsed
            assert parsed["app"]["applicationId"] == "app-456"
            assert parsed["app"]["env"] == "dev"
            assert "localhost" in parsed["app"]["host"]
        finally:
            os.chdir(original_cwd)


@pytest.mark.asyncio
async def test_run_scan_returns_install_instructions_when_cli_missing():
    """run_stackhawk_scan returns install instructions when hawk CLI is not found"""
    import tempfile, os, yaml, asyncio
    from stackhawk_mcp.server import StackHawkClient

    # Create a minimal config file so config-search succeeds
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', prefix='stackhawk', delete=False, dir='.') as f:
        yaml.dump({"app": {"applicationId": "test-id", "env": "dev", "host": "http://localhost:3000"}}, f)
        config_path = f.name

    try:
        client = StackHawkClient(api_key="fake-key")
        # Mock create_subprocess_exec to raise FileNotFoundError (hawk not installed)
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("[Errno 2] No such file or directory: 'hawk'")):
            result = await client.run_stackhawk_scan(config_path)
        assert not result.get("success")
        assert "install_instructions" in result
        assert "hawk" in result["install_instructions"].lower()
    finally:
        os.unlink(config_path)
        if hasattr(client, '_client') and client._client:
            await client._client.aclose()


@pytest.mark.asyncio
async def test_setup_tool_creates_new_app_and_config():
    """setup_stackhawk_for_project should create app then generate config."""
    server = StackHawkMCPServer("mock-api-key")

    server.client.get_user_info = AsyncMock(return_value={
        "user": {"external": {"organizations": [{"organization": {"id": "org-123", "name": "Test Org"}}]}}
    })
    server.client.list_applications = AsyncMock(return_value={"applications": []})
    server.client.create_application = AsyncMock(return_value={"id": "new-app-789", "name": "my-project"})
    server._get_schema = AsyncMock(return_value=MOCK_SCHEMA)

    with tempfile.TemporaryDirectory() as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            result = await server._setup_stackhawk_for_project(
                host="http://localhost:8080",
                environment="staging",
                app_name="my-project"
            )
            assert result["success"] is True
            assert result["appStatus"] == "created"
            assert result["configGenerated"] is True
            assert result["applicationId"] == "new-app-789"

            parsed = yaml.safe_load(result["configYaml"])
            assert parsed["app"]["env"] == "staging"
            assert "localhost" in parsed["app"]["host"]
            assert "8080" in parsed["app"]["host"]
        finally:
            os.chdir(original_cwd)
