# StackHawk MCP Server

A Model Context Protocol (MCP) server that provides integration with StackHawk's security scanning platform. This server offers tools for security analytics, application monitoring, YAML configuration management, and anti-hallucination features for LLMs.

## Features

- **Security Analytics**: Organization, application, and vulnerability tools
- **YAML Configuration Tools**: Creation, validation, schema reference, and anti-hallucination field validation
- **Sensitive Data & Threat Surface Analysis**: Repository, application, and data exposure mapping
- **Custom User-Agent**: All API calls include a versioned `User-Agent` header for tracking
- **Comprehensive Test Suite**: Automated tests for all major features

---

## User-Agent and Versioning

All HTTP requests from this MCP server include a custom `User-Agent` header:

```
User-Agent: StackHawk-MCP/{version}
```

The version is set in `stackhawk_mcp/server.py` as `STACKHAWK_MCP_VERSION`. Update this constant to track deployments and usage in StackHawk logs and analytics.

---

## Test Suite

This project includes a comprehensive set of tests for all major features. To run all tests:

```bash
# Run all test scripts
python test_all_time_fix.py
python test_anti_hallucination.py
python test_api_calls.py
python test_application_vulnerabilities.py
python test_connection.py
python test_executive_summary_fix.py
python test_mcp_imports.py
python test_pagination_simple.py
python test_repository_analysis.py
python test_sensitive_data.py
python test_server_fix.py
python test_vulnerability_reporting.py
python test_yaml_tools.py
python quick_test.py
```

You can also run individual test files as needed. Each test covers a specific aspect of the MCP server, including API integration, YAML validation, anti-hallucination, and security analytics.

---

## Development Quickstart

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
4. **Run the MCP server:**
   ```bash
   python -m stackhawk_mcp.server
   ```
5. **Run the test suite:**
   ```bash
   python test_server_fix.py  # Or any other test_*.py file
   ```

---

## Anti-Hallucination & YAML Tools

- **Field Validation**: Prevents LLMs from suggesting invalid fields using `validate_field_exists` and `get_schema_fields`.
- **Schema Reference**: Always up-to-date with the official StackHawk schema.
- **AI-Powered Suggestions**: Use `suggest_configuration` for best-practice YAML recommendations.
- **YAML Validation**: Validate any config with `validate_stackhawk_config`.

---

## Features

### Security Analytics Tools
- **Organization Information**: Get detailed information about StackHawk organizations
- **Application Management**: List and search applications with security status
- **Vulnerability Search**: Search for specific vulnerabilities across applications
- **Security Dashboard**: Generate comprehensive security dashboards for executive reporting
- **Vulnerability Reporting**: Generate detailed vulnerability reports and analysis
- **Trend Analysis**: Analyze vulnerability trends and patterns over time
- **Critical Findings**: Get high-priority findings requiring immediate attention
- **Executive Summaries**: Generate executive-level security summaries and recommendations

### YAML Configuration Tools
- **Configuration Creation**: Create StackHawk YAML configuration files with best practices
- **Configuration Validation**: Validate YAML configurations against the official StackHawk schema
- **Schema Reference**: Get the complete StackHawk configuration schema from the official URL
- **Schema Caching**: Automatic caching of the schema with 24-hour TTL and manual refresh capability
- **Anti-Hallucination**: Prevent LLMs from suggesting invalid fields with field validation tools

**Official Schema URL**: [https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json](https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd stackhawk-mcp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up your StackHawk API key:
```bash
export STACKHAWK_API_KEY="your-api-key-here"
```

## Usage

### Running the MCP Server

```bash
python -m stackhawk_mcp.server
```

### Testing the YAML Tools

```bash
python test_yaml_tools.py
```

## Available Tools

### Security Analytics

#### `get_organization_info`
Get detailed information about a StackHawk organization.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)

#### `list_applications`
List applications with filtering and security status.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)
- `query` (string, optional): Search query for application names
- `page_size` (integer, optional): Number of results per page (default: 25)

#### `search_vulnerabilities`
Search for specific vulnerabilities across applications.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)
- `severity` (string, optional): Filter by severity level (High, Medium, Low)

#### `generate_security_dashboard`
Generate comprehensive security dashboard for executive reporting.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)

#### `get_vulnerability_report`
Generate comprehensive vulnerability report for an organization.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)
- `severity_filter` (string, optional): Filter by severity level (High, Medium, Low, All, default: All)
- `time_range` (string, optional): Time range for findings (7d, 30d, 90d, 1y, all, default: 30d)
- `include_remediation` (boolean, optional): Include remediation details (default: true)
- `group_by` (string, optional): Group findings by category (severity, application, vulnerability_type, status, default: severity)

**Example:**
```json
{
  "org_id": "12345678-1234-1234-1234-123456789012",
  "severity_filter": "High",
  "time_range": "30d",
  "include_remediation": true,
  "group_by": "application"
}
```

#### `analyze_vulnerability_trends`
Analyze vulnerability trends and patterns across applications.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)
- `analysis_period` (string, optional): Analysis period (30d, 90d, 180d, 1y, default: 90d)
- `include_applications` (boolean, optional): Include application-specific trends (default: true)
- `include_severity_breakdown` (boolean, optional): Include severity breakdown analysis (default: true)

**Example:**
```json
{
  "org_id": "12345678-1234-1234-1234-123456789012",
  "analysis_period": "90d",
  "include_applications": true,
  "include_severity_breakdown": true
}
```

#### `get_critical_findings`
Get critical and high-severity findings requiring immediate attention.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)
- `severity_levels` (array, optional): Severity levels to include (Critical, High, default: ["Critical", "High"])
- `include_remediation` (boolean, optional): Include remediation details (default: true)
- `max_results` (integer, optional): Maximum number of results (default: 50)

**Example:**
```json
{
  "org_id": "12345678-1234-1234-1234-123456789012",
  "severity_levels": ["Critical", "High"],
  "include_remediation": true,
  "max_results": 25
}
```

#### `generate_executive_summary`
Generate executive-level vulnerability summary and recommendations.

**Parameters:**
- `org_id` (string, required): Organization ID (UUID)
- `time_period` (string, optional): Time period for summary (7d, 30d, 90d, 1y, default: 30d)
- `include_recommendations` (boolean, optional): Include actionable recommendations (default: true)
- `include_risk_score` (boolean, optional): Include overall risk score (default: true)

**Example:**
```json
{
  "org_id": "12345678-1234-1234-1234-123456789012",
  "time_period": "30d",
  "include_recommendations": true,
  "include_risk_score": true
}
```

### YAML Configuration Management

#### `create_stackhawk_config`
Create a new StackHawk YAML configuration file with best practices.

**Parameters:**
- `application_id` (string, required): StackHawk application ID (UUID)
- `app_name` (string, required): Application name
- `host` (string, required): Application hostname or IP
- `port` (integer, required): Application port number
- `environment` (string, optional): Environment (dev, staging, prod, default: dev)
- `protocol` (string, optional): Application protocol (http, https, default: https)
- `scanner_mode` (string, optional): Scanner mode (standard, rapid, lightning, default: standard)
- `include_auth` (boolean, optional): Include authentication configuration template (default: false)
- `auth_type` (string, optional): Authentication type (form, header, json, basic)

**Example:**
```json
{
  "application_id": "12345678-1234-1234-1234-123456789012",
  "app_name": "My Web Application",
  "host": "myapp.com",
  "port": 443,
  "environment": "prod",
  "protocol": "https",
  "scanner_mode": "standard",
  "include_auth": true,
  "auth_type": "form"
}
```

#### `validate_stackhawk_config`
Validate a StackHawk YAML configuration against the official StackHawk schema.

**Parameters:**
- `yaml_content` (string, required): YAML configuration content to validate

**Example:**
```json
{
  "yaml_content": "app:\n  applicationId: \"test-app\"\n  env: \"dev\"\n  host: \"http://localhost:3000\"\n  name: \"Test App\""
}
```

#### `get_stackhawk_schema`
Get the complete StackHawk YAML configuration schema from the official URL.

**Parameters:** None

#### `refresh_schema_cache`
Force refresh the cached StackHawk YAML schema from the official URL.

**Parameters:** None

#### `validate_field_exists`
Check if a specific field path exists in the StackHawk schema and get its details.

**Parameters:**
- `field_path` (string, required): Field path to validate (e.g., 'app.applicationId', 'hawk.spider.base')

**Example:**
```json
{
  "field_path": "app.applicationId"
}
```

#### `get_schema_fields`
Get all available fields and their types from the StackHawk schema.

**Parameters:**
- `section` (string, optional): Section to filter by (app, hawk, hawkAddOn, tags)

**Example:**
```json
{
  "section": "app"
}
```

#### `suggest_configuration`
Get AI-powered configuration suggestions based on the actual StackHawk schema.

**Parameters:**
- `use_case` (string, required): Use case description (e.g., 'web application', 'API testing')
- `environment` (string, optional): Target environment (dev, staging, prod, default: dev)
- `include_advanced` (boolean, optional): Include advanced configuration options (default: false)

**Example:**
```json
{
  "use_case": "web application with authentication",
  "environment": "prod",
  "include_advanced": true
}
```

## API Endpoints

### Findings Endpoint
The MCP server integrates with StackHawk's findings endpoint for comprehensive vulnerability reporting:

**Endpoint**: `GET /api/v1/reports/org/{orgId}/findings`

**Features**:
- **Comprehensive Filtering**: Filter by severity, time range, application, and status
- **Pagination Support**: Handle large datasets efficiently
- **Detailed Information**: Include remediation details and vulnerability metadata
- **Real-time Data**: Access current vulnerability findings
- **Organization-wide**: Get findings across all applications in an organization

**Use Cases**:
- Generate vulnerability reports for compliance
- Track security trends over time
- Identify critical issues requiring immediate attention
- Create executive summaries for stakeholders
- Monitor application security posture

## Anti-Hallucination Features

The StackHawk MCP server includes several tools to prevent LLMs from suggesting invalid configuration fields that don't exist in the actual schema:

### Field Validation
- **`validate_field_exists`**: Check if a specific field path exists in the schema
- **`get_schema_fields`**: Get all available fields and their types
- **Real-time validation**: Always validate against the official schema

### Best Practices for LLMs
1. **Always validate fields** before suggesting them to users
2. **Use `get_schema_fields`** to see what's actually available
3. **Use `suggest_configuration`** for AI-powered recommendations
4. **Validate final configurations** before deployment

### Example Workflow
```python
# 1. Check if a field exists
result = await validate_field_exists("app.port")
if not result["success"]:
    # Field doesn't exist, suggest alternatives
    fields = await get_schema_fields("app")
    # Show available fields to user

# 2. Get AI suggestions
suggestions = await suggest_configuration("web application", "prod")

# 3. Validate final config
validation = await validate_stackhawk_config(yaml_content)
```

## Configuration Schema

The StackHawk YAML configuration follows the official schema provided by StackHawk at [https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json](https://download.stackhawk.com/hawk/jsonschema/hawkconfig.json). The schema is automatically fetched and cached for 24 hours to ensure you always have the latest version.

**Note:** The schema below is a simplified representation. For the complete and up-to-date schema, use the `get_stackhawk_schema` tool.

```yaml
app:                           # Required: Application configuration
  applicationId: string        # Required: StackHawk application ID
  env: string                  # Required: Environment (dev, staging, prod)
  host: string                 # Required: Application host URL
  name: string                 # Optional: Application name
  description: string          # Optional: Application description
  authentication: object       # Optional: Authentication configuration

hawk:                          # Optional: HawkScan settings
  spider: object               # Spider configuration
    base: boolean              # Enable base spider
    ajax: boolean              # Enable AJAX spider
    maxDurationMinutes: integer # Maximum crawl duration
  scan: object                 # Scan configuration
    maxDurationMinutes: integer # Maximum scan duration
    threads: integer           # Number of threads
  startupTimeoutMinutes: integer # Startup timeout
  failureThreshold: string     # Failure threshold (high, medium, low)

hawkAddOn:                     # Optional: Add-ons and custom scripts
  replacer: object             # Header replacement rules
  scripts: array               # Custom scripts

tags:                          # Optional: Metadata tags
  - name: string               # Tag name
    value: string              # Tag value
```

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

## Development

### Running Tests
```bash
python test_yaml_tools.py
python test_anti_hallucination.py
python test_vulnerability_reporting.py
```

### Code Formatting
```bash
black stackhawk_mcp/
```

### Type Checking
```bash
mypy stackhawk_mcp/
```

## Dependencies

- `mcp>=1.0.0`: Model Context Protocol
- `httpx>=0.27.0`: HTTP client
- `python-dotenv>=1.0.0`: Environment variable management
- `PyYAML>=6.0`: YAML parsing and generation
- `jsonschema>=4.0.0`: JSON schema validation

## License

MIT License

## Repository and Threat Surface Analysis

The StackHawk MCP server provides comprehensive repository analysis and threat surface mapping capabilities to help security teams understand their code security posture and identify potential attack vectors.

### Repository Analysis Tools

#### `analyze_threat_surface`
Analyze the complete threat surface across repositories, applications, and vulnerabilities.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `include_repositories` (optional): Include repository analysis (default: true)
- `include_applications` (optional): Include application analysis (default: true)
- `include_vulnerabilities` (optional): Include vulnerability analysis (default: true)
- `risk_assessment` (optional): Include risk assessment (default: true)

**Example:**
```python
# Analyze complete threat surface
threat_surface = await server._analyze_threat_surface(
    org_id="your-org-id",
    include_repositories=True,
    include_applications=True,
    include_vulnerabilities=True,
    risk_assessment=True
)
```

#### `get_repository_security_overview`
Get comprehensive security overview for all repositories in an organization.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `include_scan_results` (optional): Include security scan results (default: true)
- `include_vulnerabilities` (optional): Include vulnerability details (default: true)
- `filter_by_status` (optional): Filter by status - "active", "archived", "all" (default: "all")

**Example:**
```python
# Get repository security overview
overview = await server._get_repository_security_overview(
    org_id="your-org-id",
    include_scan_results=True,
    include_vulnerabilities=True,
    filter_by_status="active"
)
```

#### `identify_high_risk_repositories`
Identify repositories with high security risk or vulnerabilities.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `risk_threshold` (optional): Minimum risk level - "high", "medium", "low" (default: "high")
- `include_remediation` (optional): Include remediation recommendations (default: true)
- `max_results` (optional): Maximum number of results (default: 20)

**Example:**
```python
# Identify high-risk repositories
high_risk = await server._identify_high_risk_repositories(
    org_id="your-org-id",
    risk_threshold="high",
    include_remediation=True,
    max_results=10
)
```

#### `generate_code_security_report`
Generate comprehensive code security report across repositories.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `report_type` (optional): Report type - "summary", "detailed", "executive" (default: "summary")
- `include_trends` (optional): Include security trends (default: true)
- `include_comparison` (optional): Include industry comparison (default: false)

**Example:**
```python
# Generate executive security report
report = await server._generate_code_security_report(
    org_id="your-org-id",
    report_type="executive",
    include_trends=True,
    include_comparison=True
)
```

#### `map_attack_surface`
Map the complete attack surface including repositories, applications, and entry points.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `include_internal` (optional): Include internal systems (default: true)
- `include_external` (optional): Include external-facing systems (default: true)
- `include_third_party` (optional): Include third-party integrations (default: true)
- `risk_visualization` (optional): Include risk visualization data (default: true)

**Example:**
```python
# Map complete attack surface
attack_surface = await server._map_attack_surface(
    org_id="your-org-id",
    include_internal=True,
    include_external=True,
    include_third_party=True,
    risk_visualization=True
)
```

### Repository API Endpoints

The MCP server also provides direct access to StackHawk's repository API endpoints:

#### List Repositories
```python
repos_response = await client.list_repositories(org_id, pageSize=100)
```

#### Get Repository Details
```python
repo_details = await client.get_repository_details(org_id, repo_id)
```

#### Get Repository Security Scan
```python
scan_results = await client.get_repository_security_scan(org_id, repo_id)
```

### Sensitive Data API Endpoints

The MCP server provides access to StackHawk's sensitive data analysis endpoints:

#### List Sensitive Data Findings
```python
findings_response = await client.list_sensitive_data_findings(org_id, pageSize=100)
```

#### Get Sensitive Data Types
```python
types_response = await client.get_sensitive_data_types(org_id)
```

#### Get Sensitive Data Summary
```python
summary_response = await client.get_sensitive_data_summary(org_id)
```

#### Application-Specific Sensitive Data
```python
app_sensitive_data = await client.get_application_sensitive_data(app_id, org_id, pageSize=100)
```

#### Repository-Specific Sensitive Data
```python
repo_sensitive_data = await client.get_repository_sensitive_data(org_id, repo_id, pageSize=100)
```

### Threat Surface Analysis Features

#### Risk Assessment
- **Risk Scoring**: Calculates overall risk scores based on repository count, application count, and vulnerability count
- **Risk Factors**: Identifies key risk factors like critical vulnerabilities, large production footprint, and high repository count
- **Risk Levels**: Categorizes risk as High, Medium, or Low based on calculated scores

#### Security Metrics
- **Repository Security Scores**: Tracks security scores for individual repositories
- **Vulnerability Distribution**: Analyzes vulnerability distribution by severity
- **Scan Coverage**: Monitors security scan coverage across repositories
- **Trend Analysis**: Tracks security trends over time (when historical data is available)

#### Attack Surface Mapping
- **Entry Points**: Identifies potential attack entry points including external applications and public repositories
- **Risk Heatmap**: Generates risk heatmap data for visualization
- **Exposure Analysis**: Categorizes assets by internal/external exposure
- **Attack Vectors**: Maps different types of attack vectors (repositories, applications, services)

### Testing Repository Analysis

Run the repository analysis test suite:

```bash
python test_repository_analysis.py
```

## Sensitive Data Analysis

The StackHawk MCP server now includes comprehensive sensitive data analysis capabilities, allowing you to identify and monitor exposure of sensitive data types (PII, PCI, PHI) across your applications and repositories.

### Sensitive Data Tools

#### `get_sensitive_data_report`
Generate comprehensive sensitive data report for an organization.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `data_type_filter` (optional): Filter by data type - "PII", "PCI", "PHI", "All" (default: "All")
- `time_range` (optional): Time range - "7d", "30d", "90d", "1y", "all" (default: "30d")
- `include_details` (optional): Include detailed findings (default: true)
- `group_by` (optional): Group by - "data_type", "application", "repository", "severity" (default: "data_type")

**Example:**
```python
# Get comprehensive sensitive data report
report = await server._get_sensitive_data_report(
    org_id="your-org-id",
    data_type_filter="PII",
    time_range="30d",
    include_details=True,
    group_by="application"
)
```

#### `analyze_sensitive_data_trends`
Analyze sensitive data exposure trends and patterns.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `analysis_period` (optional): Analysis period - "30d", "90d", "180d", "1y" (default: "90d")
- `include_applications` (optional): Include application-specific trends (default: true)
- `include_repositories` (optional): Include repository-specific trends (default: true)

**Example:**
```python
# Analyze sensitive data trends
trends = await server._analyze_sensitive_data_trends(
    org_id="your-org-id",
    analysis_period="90d",
    include_applications=True,
    include_repositories=True
)
```

#### `get_critical_sensitive_data`
Get critical sensitive data findings requiring immediate attention.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `data_types` (optional): Data types to include - ["PII", "PCI", "PHI"] (default: ["PII", "PCI", "PHI"])
- `include_remediation` (optional): Include remediation details (default: true)
- `max_results` (optional): Maximum number of results (default: 50)

**Example:**
```python
# Get critical sensitive data findings
critical_data = await server._get_critical_sensitive_data(
    org_id="your-org-id",
    data_types=["PII", "PCI", "PHI"],
    include_remediation=True,
    max_results=25
)
```

#### `generate_sensitive_data_summary`
Generate executive-level sensitive data summary and recommendations.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `time_period` (optional): Time period - "7d", "30d", "90d", "1y" (default: "30d")
- `include_recommendations` (optional): Include actionable recommendations (default: true)
- `include_risk_assessment` (optional): Include risk assessment (default: true)

**Example:**
```python
# Generate executive summary
summary = await server._generate_sensitive_data_summary(
    org_id="your-org-id",
    time_period="30d",
    include_recommendations=True,
    include_risk_assessment=True
)
```

#### `get_application_sensitive_data`
Get sensitive data findings for a specific application.

**Parameters:**
- `app_id` (required): Application ID (UUID)
- `org_id` (optional): Organization ID (UUID) - will be auto-detected if not provided
- `data_type_filter` (optional): Filter by data type - "PII", "PCI", "PHI", "All" (default: "All")
- `include_details` (optional): Include detailed findings (default: true)
- `max_results` (optional): Maximum number of results (default: 100)

**Example:**
```python
# Get application-specific sensitive data
app_data = await server._get_application_sensitive_data(
    app_id="your-app-id",
    data_type_filter="PII",
    include_details=True,
    max_results=50
)
```

#### `get_repository_sensitive_data`
Get sensitive data findings for a specific repository.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `repo_id` (required): Repository ID (UUID)
- `data_type_filter` (optional): Filter by data type - "PII", "PCI", "PHI", "All" (default: "All")
- `include_details` (optional): Include detailed findings (default: true)
- `max_results` (optional): Maximum number of results (default: 100)

**Example:**
```python
# Get repository-specific sensitive data
repo_data = await server._get_repository_sensitive_data(
    org_id="your-org-id",
    repo_id="your-repo-id",
    data_type_filter="All",
    include_details=True,
    max_results=50
)
```

#### `get_sensitive_data_types`
Get available sensitive data types and categories.

**Parameters:**
- `org_id` (required): Organization ID (UUID)

**Example:**
```python
# Get sensitive data types
types = await server._get_sensitive_data_types(org_id="your-org-id")
```

#### `map_sensitive_data_surface`
Map sensitive data exposure across repositories and applications.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `include_applications` (optional): Include application analysis (default: true)
- `include_repositories` (optional): Include repository analysis (default: true)
- `risk_visualization` (optional): Include risk visualization data (default: true)

**Example:**
```python
# Map sensitive data surface
surface = await server._map_sensitive_data_surface(
    org_id="your-org-id",
    include_applications=True,
    include_repositories=True,
    risk_visualization=True
)
```

### Sensitive Data Analysis Features

#### Data Type Categorization
- **PII (Personally Identifiable Information)**: Names, addresses, social security numbers, etc.
- **PCI (Payment Card Industry)**: Credit card numbers, payment information
- **PHI (Protected Health Information)**: Medical records, health insurance information

#### Risk Assessment
- **Risk Scoring**: Calculates risk scores based on data type weights (PHI > PCI > PII)
- **Risk Levels**: Categorizes exposure as High, Medium, or Low risk
- **Risk Factors**: Identifies key risk factors like PHI exposure or high data counts

#### Exposure Mapping
- **Application Analysis**: Maps sensitive data exposure across applications
- **Repository Analysis**: Maps sensitive data exposure across repositories
- **Risk Heatmap**: Generates risk heatmap data for visualization
- **Data Type Distribution**: Calculates overall data type distribution

#### Trend Analysis
- **Time-based Trends**: Analyzes sensitive data exposure over time
- **Application Trends**: Tracks sensitive data patterns by application
- **Repository Trends**: Tracks sensitive data patterns by repository
- **Data Type Trends**: Monitors changes in data type exposure

### Testing Sensitive Data Analysis

Run the sensitive data analysis test suite:

```bash
python test_sensitive_data.py
```

This will test all repository and threat surface analysis features and save detailed results to `repository_analysis_results.json`.

### Use Cases

#### Security Teams
- **Threat Assessment**: Understand the complete threat surface across all repositories and applications
- **Risk Prioritization**: Identify high-risk repositories that require immediate attention
- **Compliance Reporting**: Generate comprehensive security reports for compliance requirements
- **Attack Surface Reduction**: Map attack vectors to identify areas for security improvement

#### Development Teams
- **Code Security**: Monitor security scores across repositories
- **Vulnerability Management**: Track and prioritize vulnerability remediation
- **Security Integration**: Integrate security scanning into development workflows

#### Executive Management
- **Security Dashboards**: Generate executive-level security reports
- **Risk Metrics**: Track overall security posture and risk levels
- **Strategic Planning**: Use threat surface analysis for security strategy planning

## Vulnerability Reporting and Analysis

The StackHawk MCP server provides comprehensive vulnerability reporting and analysis capabilities using the StackHawk findings API endpoint.

### ⚠️ Important: Vulnerability Scoping

**The Issue**: Previous versions of this MCP server used organization-wide vulnerability data, which could cause confusion when LLMs interpreted this as application-specific data. For example, if your organization has 1000 vulnerabilities across 10 applications, an LLM might incorrectly report that a single application has 1000 vulnerabilities.

**The Solution**: The MCP server now provides both organization-wide and application-specific vulnerability tools with clear disclaimers. Application-specific data is filtered from organization-wide findings using the `app_id` parameter.

### Application-Specific Vulnerability Tools

**Note**: These tools filter organization-wide findings by application ID to provide application-specific data.

#### `get_application_vulnerabilities`
Get vulnerabilities for a specific application (not organization-wide).

**Parameters:**
- `app_id` (required): Application ID (UUID)
- `org_id` (optional): Organization ID (UUID) - will be auto-detected if not provided
- `severity_filter` (optional): Filter by severity - "High", "Medium", "Low", "All" (default: "All")
- `include_remediation` (optional): Include remediation details (default: true)
- `max_results` (optional): Maximum number of results (default: 100)

**Example:**
```python
# Get application-specific vulnerabilities
app_vulns = await server._get_application_vulnerabilities(
    app_id="your-app-id",
    org_id="your-org-id",  # Optional, will be auto-detected if not provided
    severity_filter="High",
    include_remediation=True,
    max_results=50
)
```

#### `get_application_security_summary`
Get security summary for a specific application.

**Parameters:**
- `app_id` (required): Application ID (UUID)
- `org_id` (required): Organization ID (UUID)
- `include_trends` (optional): Include security trends (default: false)
- `include_recommendations` (optional): Include security recommendations (default: true)

**Example:**
```python
# Get application security summary
app_summary = await server._get_application_security_summary(
    app_id="your-app-id",
    org_id="your-org-id",  # Optional, will be auto-detected if not provided
    include_trends=False,
    include_recommendations=True
)
```

#### `compare_application_security`
Compare security posture across multiple applications.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `app_ids` (required): List of application IDs to compare
- `comparison_metrics` (optional): Metrics to compare - ["vulnerability_count", "severity_distribution", "security_score", "remediation_status"] (default: ["vulnerability_count", "severity_distribution"])

**Example:**
```python
# Compare multiple applications
comparison = await server._compare_application_security(
    org_id="your-org-id",
    app_ids=["app1-id", "app2-id", "app3-id"],
    comparison_metrics=["vulnerability_count", "security_score"]
)
```

### Organization-Wide Vulnerability Tools

**Note**: These tools return data across ALL applications in the organization and include clear disclaimers.

#### `get_vulnerability_report`
Generate comprehensive vulnerability report for an organization.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `severity_filter` (optional): Filter by severity - "High", "Medium", "Low", "All" (default: "All")
- `time_range` (optional): Time range - "7d", "30d", "90d", "1y", "all" (default: "30d")
- `include_remediation` (optional): Include remediation details (default: true)
- `group_by` (optional): Group by - "severity", "application", "vulnerability_type", "status" (default: "severity")

**Example:**
```python
# Get organization-wide vulnerability report
org_report = await server._get_vulnerability_report(
    org_id="your-org-id",
    severity_filter="High",
    time_range="30d",
    include_remediation=True,
    group_by="application"
)
```

#### `analyze_vulnerability_trends`
Analyze vulnerability trends and patterns across applications.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `analysis_period` (optional): Analysis period - "30d", "90d", "180d", "1y" (default: "90d")
- `include_applications` (optional): Include application-specific trends (default: true)
- `include_severity_breakdown` (optional): Include severity breakdown analysis (default: true)

**Example:**
```python
# Analyze vulnerability trends
trends = await server._analyze_vulnerability_trends(
    org_id="your-org-id",
    analysis_period="90d",
    include_applications=True,
    include_severity_breakdown=True
)
```

#### `get_critical_findings`
Get critical and high-severity findings requiring immediate attention.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `severity_levels` (optional): Severity levels to include - ["Critical", "High"] (default: ["Critical", "High"])
- `include_remediation` (optional): Include remediation details (default: true)
- `max_results` (optional): Maximum number of results (default: 50)

**Example:**
```python
# Get critical findings across organization
critical = await server._get_critical_findings(
    org_id="your-org-id",
    severity_levels=["Critical", "High"],
    include_remediation=True,
    max_results=50
)
```

#### `generate_executive_summary`
Generate executive-level vulnerability summary and recommendations.

**Parameters:**
- `org_id` (required): Organization ID (UUID)
- `time_period` (optional): Time period - "7d", "30d", "90d", "1y" (default: "30d")
- `include_recommendations` (optional): Include actionable recommendations (default: true)
- `include_risk_score` (optional): Include overall risk score (default: true)

**Example:**
```python
# Generate executive summary
exec_summary = await server._generate_executive_summary(
    org_id="your-org-id",
    time_period="30d",
    include_recommendations=True,
    include_risk_score=True
)
```

### Vulnerability API Endpoints

The MCP server provides access to StackHawk's vulnerability findings API:

#### Organization-Wide Findings
```python
# Get all organization findings (use with caution)
findings_response = await client.list_organization_findings(org_id, pageSize=100)

# Get detailed organization findings
detailed_findings = await client.get_organization_findings_detailed(org_id, pageSize=100)
```

#### Application-Specific Findings
```python
# Get findings for a specific application (filtered from org-wide data)
app_findings = await client.get_application_findings(app_id, org_id, pageSize=100)

# Get summary of findings for a specific application (filtered from org-wide data)
app_summary = await client.get_application_findings_summary(app_id, org_id, pageSize=50)
```

**Note**: Application-specific findings are filtered from organization-wide data using the `app_id` parameter, not from a separate endpoint.

### Testing Vulnerability Scoping

Run the vulnerability scoping test to understand the difference:

```bash
python test_application_vulnerabilities.py
```

This will demonstrate:
- Organization-wide vs application-specific vulnerability counts
- Clear disclaimers in responses
- Proper scoping for accurate vulnerability reporting

### Best Practices for LLMs

#### ✅ Do This:
- Use `get_application_vulnerabilities()` for app-specific analysis
- Use `get_application_security_summary()` for app-specific summaries
- Always specify the application ID when asking about vulnerabilities
- Check the 'note' field in responses for clarification

#### ❌ Don't Do This:
- Assume organization-wide data is application-specific
- Use organization-wide tools for detailed app analysis
- Ignore the disclaimers in response notes

### Use Cases

#### Development Teams
- **Application Security**: Get vulnerabilities specific to your application
- **CI/CD Integration**: Monitor security scores for specific apps
- **Remediation Planning**: Focus on app-specific vulnerabilities

#### Security Teams
- **Risk Assessment**: Compare security posture across applications
- **Trend Analysis**: Track vulnerability trends organization-wide
- **Executive Reporting**: Generate high-level summaries for leadership

#### Executive Management
- **Security Dashboards**: Get organization-wide security overview
- **Risk Metrics**: Track overall security posture
- **Strategic Planning**: Use trends for security strategy

## Repository and Threat Surface Analysis