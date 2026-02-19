# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python-based MCP (Model Context Protocol) server that helps developers set up StackHawk, run security scans, and triage findings to fix vulnerabilities. The server integrates with StackHawk's API and exposes 7 focused tools for the setup → scan → triage → fix workflow.

## Development Commands

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_<name>.py

# Run with asyncio mode (already configured in pyproject.toml)
pytest -v
```

### Code Quality
```bash
# Format code with Black
black stackhawk_mcp/

# Type checking with mypy
mypy stackhawk_mcp/

# Both formatting and type checking should be run before commits
```

### Running the Server
```bash
# Run MCP server (stdio mode)
python -m stackhawk_mcp.server

# Run HTTP server (FastAPI)
python -m stackhawk_mcp.http_server

# CLI entry point
stackhawk-mcp
```

### Environment Setup
```bash
# Install in development mode
pip install -e .

# Install with dev dependencies
pip install -e .[dev]

# Set required environment variable
export STACKHAWK_API_KEY="your-api-key-here"
```

## Architecture

### Core Components

- **`stackhawk_mcp/server.py`**: Main MCP server implementation with all tool handlers
- **`stackhawk_mcp/http_server.py`**: FastAPI HTTP wrapper for the MCP server
- **`stackhawk_mcp/__main__.py`**: CLI entry point and argument parsing
- **`stackhawk_mcp/__init__.py`**: Package initialization and version management

### Key Features (7 MCP Tools)

1. **Discover**: `get_organization_info`, `list_applications` — orient the LLM on org/app context
2. **Setup**: `setup_stackhawk_for_project` — detect language, find/create app, generate stackhawk.yml
3. **Validate**: `validate_stackhawk_config`, `validate_field_exists` — schema validation and anti-hallucination
4. **Scan**: `run_stackhawk_scan` — run scans via CLI (with install help fallback)
5. **Triage**: `get_app_findings_for_triage` — get findings at/above failure threshold for remediation

### API Integration

- All API calls to StackHawk include custom User-Agent header: `StackHawk-MCP/{version}`
- Version is managed in `stackhawk_mcp/__init__.py` and referenced in server.py
- Authentication via `STACKHAWK_API_KEY` environment variable
- Schema caching with 24-hour TTL for YAML validation

### Testing Strategy

- Comprehensive test suite in `tests/` directory covering all major features
- Tests use pytest with asyncio mode enabled
- Individual test files for each major feature area
- API integration tests and schema validation tests included

## Development Notes

### Python Requirements
- Requires Python 3.10 or higher
- Uses modern Python features and type hints throughout
- Async/await pattern for API calls and MCP operations

### Code Style
- Black formatting with 100 character line length
- mypy type checking with strict settings
- Comprehensive docstrings for all public functions

### MCP Integration
- Uses the `mcp` library for server implementation
- Supports both stdio and HTTP modes
- Tool schemas defined inline with handlers
- Proper error handling and logging throughout

### Version Management
- Version bumping handled via GitHub Actions "Prepare Release" workflow
- Supports minor and major version bumps
- Automated commit and push to main branch
- Version stored in `stackhawk_mcp/__init__.py`

## Key Configuration Files

- **`pyproject.toml`**: Project metadata, dependencies, and tool configuration
- **`pytest.ini`**: Additional pytest configuration for deprecation warnings
- **`cursor-mcp-config.json`**: Example MCP configuration for Cursor IDE integration
- **`requirements.txt`**: Runtime dependencies list

## Security Considerations

- API key management via environment variables only
- No secrets should be committed to the repository
- All API interactions are read-only analytics operations
- Input validation on all user-provided data (YAML, search queries, etc.)