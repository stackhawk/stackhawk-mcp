# StackHawk MCP Server

**Current Version: 1.2.4**
_Requires Python 3.10 or higher_

A Model Context Protocol (MCP) server for integrating with StackHawk's security scanning platform. Helps developers set up StackHawk, run security scans, and triage findings to fix vulnerabilities — all from within an LLM-powered IDE or chat.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Available Tools](#available-tools)
- [Testing & Development](#testing--development)
- [Example Configurations](#example-configurations)
- [Integrating with LLMs and IDEs](#integrating-with-llms-and-ides)
- [Contributing](#contributing)
- [License](#license)

---

## Features
- **Setup:** Detect your project, create a StackHawk application, and generate a ready-to-scan `stackhawk.yml`
- **Scan:** Run StackHawk scans directly from your IDE or chat (with install help if the CLI is missing)
- **Triage:** Get actionable findings at or above your failure threshold for remediation
- **Validate:** Check YAML configs against the official schema and validate field paths to prevent hallucination
- **Custom User-Agent:** All API calls include a versioned `User-Agent` header

---

## Installation

1. **Install via pip (make sure you have write permission to your current python environment):**
   ```bash
   > pip install stackhawk-mcp
   # Requires Python 3.10 or higher
   ```
**Or Install via pip in a virtual env:**
   ```bash
   > python3 -m venv ~/.virtualenvs/mcp
   > source ~/.virtualenvs/mcp/bin/activate
   > (mcp) pip install stackhawk-mcp
   # Requires Python 3.10 or higher
   ```
**Or Install via pip using pyenv:**
   ```bash
   > pyenv shell 3.10.11
   > pip install stackhawk-mcp
   # Requires Python 3.10 or higher
   ```   
**Or Install locally from this repo:**
   ```bash
   > pip install --user .
   # Run this command from the root of the cloned repository
   ```
2. **Set your StackHawk API key:**
   ```bash
   > export STACKHAWK_API_KEY="your-api-key-here"
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

StackHawk MCP can be used as a tool provider for AI coding assistants and LLM-powered developer environments, enabling security scanning setup, YAML validation, and vulnerability triage directly in your workflow.

#### Cursor (AI Coding Editor)
- **Setup:**
  - Follow the installation instructions above to install `stackhawk-mcp` in your python environment.
  - In Cursor, go to `Cursor Settings->Tools & Integrations->MCP Tools`
  - Add a "New MCP Server" with the following json, depending on your setup:
    - Using a virtual env at `~/.virtualenvs/mcp`:
      ```json
      {
        "mcpServers": {
          "stackhawk": {
            "command": "/home/bobby/.virtualenvs/mcp/bin/python",
            "args": ["-m", "stackhawk_mcp.server"],
            "env": {
              "STACKHAWK_API_KEY": "${env:STACKHAWK_API_KEY}"
            },
            "disabled": false
          }
        }
      }
      ```
    - Using pyenv:
      ```json
      {
        "mcpServers": {
          "stackhawk": {
            "command": "/home/bobby/.pyenv/versions/3.10.11/bin/python3",
            "args": ["-m", "stackhawk_mcp.server"],
            "env": {
              "STACKHAWK_API_KEY": "${env:STACKHAWK_API_KEY}"
            },
            "disabled": false
          }
        }
      }
      ```
    - Or use python directly:
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
    - Then make sure the "stackhawk" MCP Tool is enabled
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
  - Invoke setup, scanning, validation, and triage tools directly from the IDE's command palette or tool integration panel.

#### General Tips
- Ensure the MCP server is running and accessible from your LLM or IDE environment.
- Review the [Available Tools & API](#available-tools--api) section for supported operations.
- For advanced integration, see the example tool usage in this README or explore the codebase for custom workflows.

### GitHub Copilot Agents

StackHawk can be added to the GitHub Coding Agent as an MCP server or as its own GitHub Custom Agent.

#### Add to GitHub Coding Agent

You can add StackHawk MCP to the GitHub Copilot Coding Agent. This gives the agent all the `stackhawk/` tools.

**StackHawk MCP installation into the Coding Agent**

[General instructions on GitHub](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/extend-coding-agent-with-mcp#adding-an-mcp-configuration-to-your-repository)

For StackHawk MCP, the MCP Configuration JSON should look something like this:

```yaml
{
  "mcpServers": {
    "stackhawk": {
      "type": "local",
      "tools": [
        "*"
      ],
      "command": "uvx",
      "args": [
        "stackhawk-mcp"
      ],
      "env": {
        "STACKHAWK_API_KEY": "COPILOT_MCP_STACKHAWK_API_KEY"
      }
    }
  }
}
```

Then in the Repository's `Settings->Environments->copilot->Environment Secrets`, add `COPILOT_MCP_STACKHAWK_API_KEY` with your StackHawk API Key.

[Installation verification instructions](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/extend-coding-agent-with-mcp#validating-your-mcp-configuration)

#### StackHawk Onboarding Agent as a GitHub Copilot Custom Agent

You can the StackHawk Onboarding Agent as a custom agent at the enterprise, organization, or repository level in GitHub.  When added, the StackHawk Onboarding Agent becomes a selectable option in the Copilot Agent Chat with context to help with onboarding, plus it installs `stackhawk-mcp` so the agent has access to all of those tools.

**StackHawk Onboarding Agent installation**

The general approach is to take the [StackHawk Onboarding Agent defintion](https://github.com/github/awesome-copilot/blob/main/agents/stackhawk-security-onboarding.agent.md) and apply it to either the desired repository, enterprise, or organization in GitHub.

- [Instructions for installing into a repository on GitHub](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/use-copilot-agents/coding-agent/create-custom-agents#creating-a-custom-agent-profile-for-a-repository)
- [Instructions for installing into an enterprise on GitHub](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-for-enterprise/manage-agents/prepare-for-custom-agents)
- [Instructions for installing into an organization GitHub](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-for-organization/prepare-for-custom-agents)

Note that the `mcp-servers` block in the StackHawk Onboarding Agent definition references an environment variable called `COPILOT_MCP_STACKHAWK_API_KEY`. Go to the Repository's `Settings->Environments->copilot->Environment Secrets`, add `COPILOT_MCP_STACKHAWK_API_KEY` with your StackHawk API Key.

---

## Configuration

- All HTTP requests include a custom `User-Agent` header:
  ```
  User-Agent: StackHawk-MCP/{version}
  ```
- The version is set in `stackhawk_mcp/server.py` as `STACKHAWK_MCP_VERSION`.
- Set your API key via the `STACKHAWK_API_KEY` environment variable.

---

## Available Tools

The MCP server exposes 7 tools organized around the developer workflow:

| Phase | Tool | Description |
|-------|------|-------------|
| **Discover** | `get_organization_info` | Get org details, teams, and applications |
| **Discover** | `list_applications` | List applications in an organization |
| **Setup** | `setup_stackhawk_for_project` | Detect language, find/create app, generate `stackhawk.yml` |
| **Validate** | `validate_stackhawk_config` | Validate YAML against the official StackHawk schema |
| **Validate** | `validate_field_exists` | Check if a field path is valid in the schema (anti-hallucination) |
| **Scan** | `run_stackhawk_scan` | Run a StackHawk scan via the CLI (returns install help if CLI is missing) |
| **Triage** | `get_app_findings_for_triage` | Get findings at/above the configured failure threshold |

### Example Tool Usage
```python
# Set up StackHawk for a project
result = await server.call_tool("setup_stackhawk_for_project", {"host": "http://localhost:3000"})

# Validate a YAML config
result = await server.call_tool("validate_stackhawk_config", {"yaml_content": "..."})

# Run a scan
result = await server.call_tool("run_stackhawk_scan", {})

# Get findings to triage
result = await server.call_tool("get_app_findings_for_triage", {})
```

**Official Schema URL:** [https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json](https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json)

---

## Testing & Development

### Running All Tests
```bash
pytest
```

### Running Individual Tests
```bash
pytest tests/test_ux_improvements.py
pytest tests/test_user_scenarios.py
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

<!-- mcp-name: com.stackhawk/stackhawk -->
