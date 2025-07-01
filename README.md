# StackHawk MCP Server

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

---

## Features
- **Security Analytics:** Organization, application, and vulnerability tools
- **YAML Configuration Tools:** Creation, validation, schema reference, anti-hallucination field validation
- **Sensitive Data & Threat Surface Analysis:** Repository, application, and data exposure mapping
- **Custom User-Agent:** All API calls include a versioned `User-Agent` header
- **Comprehensive Test Suite:** Automated tests for all major features

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd stackhawk-mcp
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
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

MIT License. See [LICENSE](LICENSE) for details.
