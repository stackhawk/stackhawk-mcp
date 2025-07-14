# StackHawk MCP Server

**Current Version: 1.0.0**
_Requires Python 3.10 or higher_

A Model Context Protocol (MCP) server for integrating with StackHawk's security scanning platform. Provides security analytics, YAML configuration management, sensitive data/threat surface analysis, and anti-hallucination tools for LLMs.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Available Tools & API](#available-tools--api)
- [YAML & Anti-Hallucination](#yaml--anti-hallucination)
- [Sensitive Data & Threat Surface](#sensitive-data--threat-surface)
- [Testing & Development](#testing--development)
- [Example Configurations](#example-configurations)
- [Contributing](#contributing)
- [License](#license)
- [Integrating with LLMs and IDEs](#integrating-with-llms-and-ides)

---

## Features
- **Security Analytics:** Organization, application, and vulnerability tools
- **YAML Configuration Tools:** Creation, validation, schema reference, anti-hallucination field validation
- **Sensitive Data & Threat Surface Analysis:** Repository, application, and data exposure mapping
- **Custom User-Agent:** All API calls include a versioned `User-Agent` header
- **Comprehensive Test Suite:** Automated tests for all major features

---

## Installation

1. **Install via pip:**
   ```bash
   pip install stackhawk-mcp
   # Requires Python 3.10 or higher
   ```
2. **Install locally from the repo:**
   ```bash
   pip install --user .
   # Run this command from the root of the cloned repository
   ```
3. **Set your StackHawk API key:**
   ```bash
   export STACKHAWK_API_KEY="your-api-key-here"
   ```

---

## Usage

### Running the MCP Server
```bash
python -m stackhawk_mcp.server
```

### Running the HTTP Server (FastAPI)
```bash
python -m stackhawk_mcp.http_server
```

### Running Tests
```bash
pytest
```

### Integrating with LLMs and IDEs

StackHawk MCP can be used as a tool provider for AI coding assistants and LLM-powered developer environments, enabling security analytics, YAML validation, and anti-hallucination features directly in your workflow.

#### Cursor (AI Coding Editor)
- **Setup:**
  - You can install `stackhawk-mcp` globally with pip, or use [pipx](https://pipx.pypa.io/) for isolated environments (recommended for CLI tools):
    ```bash
    pipx install stackhawk-mcp
    ```
  - Run the MCP server locally: `python -m stackhawk_mcp.server` or the HTTP server: `python -m stackhawk_mcp.http_server`.
  - In Cursor, add a custom tool provider pointing to your local MCP server endpoint (e.g., `http://localhost:8080/mcp`).
  - Configure your API key as an environment variable: `export STACKHAWK_API_KEY=your-api-key`.
  - Example `cursor-mcp-config.json` using pipx:
    ```json
    {
      "mcpServers": {
        "stackhawk": {
          "command": "pipx",
          "args": ["run", "stackhawk-mcp", "-m", "stackhawk_mcp.server"],
          "env": {
            "STACKHAWK_API_KEY": "${env:STACKHAWK_API_KEY}"
          }
        }
      }
    }
    ```
  - Or, if `stackhawk-mcp` provides a CLI entry point:
    ```json
    {
      "mcpServers": {
        "stackhawk": {
          "command": "pipx",
          "args": ["run", "stackhawk-mcp"],
          "env": {
            "STACKHAWK_API_KEY": "${env:STACKHAWK_API_KEY}"
          }
        }
      }
    }
    ```
  - Example `cursor-mcp-config.json` using python directly:
    ```json
    {
      "mcpServers": {
        "stackhawk": {
          "command": "python3",
          "args": ["-m", "stackhawk_mcp.server"],
          "env": {
            "STACKHAWK_API_KEY": "${env:STACKHAWK_API_KEY}"
          }
        }
      }
    }
    ```
- **Usage:**
  - Use Cursor's tool invocation to call StackHawk MCP tools (e.g., vulnerability search, YAML validation).
  - Example prompt: `Validate this StackHawk YAML config for errors.`

#### OpenAI, Anthropic, and Other LLMs
- **Setup:**
  - Deploy the MCP HTTP server and expose it to your LLM system (local or cloud).
  - Use the LLM's tool-calling or function-calling API to connect to the MCP endpoint.
  - Pass the required arguments (e.g., org_id, yaml_content) as specified in the tool schemas.
- **Example API Call:**
  ```json
  {
    "method": "tools/call",
    "params": {
      "name": "validate_stackhawk_config",
      "arguments": {"yaml_content": "..."}
    }
  }
  ```
- **Best Practices:**
  - Use anti-hallucination tools to validate field names and schema compliance.
  - Always check the tool's output for warnings or suggestions.

#### IDEs like Windsurf
- **Setup:**
  - Add StackHawk MCP as a tool provider or extension in your IDE, pointing to the local or remote MCP server endpoint.
  - Configure environment variables as needed.
- **Usage:**
  - Invoke security analytics, YAML validation, or sensitive data tools directly from the IDE's command palette or tool integration panel.

#### General Tips
- Ensure the MCP server is running and accessible from your LLM or IDE environment.
- Review the [Available Tools & API](#available-tools--api) section for supported operations.
- For advanced integration, see the example tool usage in this README or explore the codebase for custom workflows.

---

## Configuration

- All HTTP requests include a custom `User-Agent` header:
  ```
  User-Agent: StackHawk-MCP/{version}
  ```
- The version is set in `stackhawk_mcp/server.py` as `STACKHAWK_MCP_VERSION`.
- Set your API key via the `STACKHAWK_API_KEY` environment variable.

---

## Available Tools & API

### Security Analytics
- **Organization Info:** Get details about StackHawk organizations
- **Application Management:** List/search applications with security status
- **Vulnerability Search:** Search for vulnerabilities across applications
- **Security Dashboard:** Generate executive dashboards
- **Vulnerability Reporting:** Generate detailed reports and analysis
- **Trend Analysis:** Analyze vulnerability trends
- **Critical Findings:** Get high-priority findings
- **Executive Summaries:** Generate executive-level summaries

### YAML Configuration Management
- **Create Config:** Generate StackHawk YAML config files
- **Validate Config:** Validate YAML against the official schema
- **Schema Reference:** Fetch the latest StackHawk schema
- **Schema Caching:** 24-hour TTL, manual refresh
- **Anti-Hallucination:** Field validation tools

### Sensitive Data & Threat Surface
- **Sensitive Data Reporting:** Organization, app, and repo-level
- **Trend Analysis:** Track sensitive data exposure
- **Critical Data Findings:** Identify high-risk data
- **Surface Mapping:** Map sensitive data and threat surfaces

### Example Tool Usage
```python
# Get organization info
org_info = await server._get_organization_info(org_id="your-org-id")

# Validate a YAML config
result = await server._validate_stackhawk_config(yaml_content="...")

# Get application vulnerabilities
vulns = await server._get_application_vulnerabilities(app_id="your-app-id")
```

---

## YAML & Anti-Hallucination
- **Field Validation:** Prevents LLMs from suggesting invalid fields
- **Schema Reference:** Always up-to-date with the official StackHawk schema
- **AI Suggestions:** Use `suggest_configuration` for YAML recommendations
- **YAML Validation:** Validate any config with `validate_stackhawk_config`

**Official Schema URL:** [https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json](https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json)

---

## Sensitive Data & Threat Surface
- **Data Type Categorization:** PII, PCI, PHI
- **Risk Assessment:** Risk scoring, levels, and factors
- **Exposure Mapping:** Application and repository analysis
- **Trend Analysis:** Time-based, app, repo, and data type trends
- **Surface Mapping:** Entry points, risk heatmap, exposure analysis

---

## Testing & Development

### Running All Tests
```bash
pytest
```

### Running Individual Tests
```bash
pytest tests/test_sensitive_data.py
pytest tests/test_repository_analysis.py
```

### Code Formatting
```bash
black stackhawk_mcp/
```

### Type Checking
```bash
mypy stackhawk_mcp/
```

---

## Example Configurations

### Basic Configuration
```yaml
app:
  applicationId: "12345678-1234-1234-1234-123456789012"
  env: "dev"
  host: "http://localhost:3000"
  name: "Development App"
  description: "Local development environment"
```

### Production Configuration with Authentication
```yaml
app:
  applicationId: "87654321-4321-4321-4321-210987654321"
  env: "prod"
  host: "https://myapp.com"
  name: "Production App"
  description: "Production environment"
  authentication:
    type: "form"
    username: "your-username"
    password: "your-password"
    loginUrl: "https://myapp.com/login"
    usernameField: "username"
    passwordField: "password"

hawk:
  spider:
    base: true
    ajax: false
    maxDurationMinutes: 30
  scan:
    maxDurationMinutes: 60
    threads: 10
  startupTimeoutMinutes: 5
  failureThreshold: "high"

tags:
  - name: "environment"
    value: "production"
  - name: "application"
    value: "myapp"
```

---

## Contributing

Contributions are welcome! Please open issues or pull requests for bug fixes, new features, or documentation improvements.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

## Release and Version Bumping

Version bumps are managed via the "Prepare Release" GitHub Actions workflow.
When triggering this workflow, you can select whether to bump the minor or major version.
The workflow will automatically update version files, commit, and push the changes to main.

> **Note:** The workflow is protected against infinite loops caused by automated version bump commits.

## GitHub Actions Authentication

All CI/CD git operations use a GitHub App token for authentication.
The git user and email are set from the repository secrets `HAWKY_APP_USER` and `HAWKY_APP_USER_EMAIL`.

## Workflow Protections

Workflows are designed to skip jobs if the latest commit is an automated version bump, preventing workflow loops.

## How to Trigger a Release

1. Go to the "Actions" tab on GitHub.
2. Select the "Prepare Release" workflow.
3. Click "Run workflow" and choose the desired bump type (minor or major).
4. The workflow will handle the rest!
