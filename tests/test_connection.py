#!/usr/bin/env python3
"""
Simple test script to verify StackHawk MCP server setup and connection.
Run this after setting up the project to ensure everything works.
"""

import asyncio
import os
import sys
from pathlib import Path
import pytest

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
from stackhawk_mcp.server import StackHawkMCPServer


@pytest.mark.asyncio
async def test_authentication():
    """Test basic authentication with StackHawk API"""
    print("🔍 Testing StackHawk API authentication...")

    # Load environment variables
    load_dotenv()
    api_key = os.environ.get("STACKHAWK_API_KEY")

    if not api_key:
        print("❌ STACKHAWK_API_KEY not found in environment variables")
        print("   Please set it in your .env file")
        return False

    try:
        server = StackHawkMCPServer(api_key)

        # Test authentication
        user_info = await server.client.get_user_info()
        user_email = user_info['user']['external']['email']
        user_name = user_info['user']['external']['fullName']

        print(f"✅ Successfully authenticated!")
        print(f"   User: {user_name} ({user_email})")

        # Test organization access
        organizations = user_info['user']['external']['organizations']
        print(f"   Organizations: {len(organizations)}")

        for org in organizations:
            org_name = org['organization']['name']
            org_id = org['organization']['id']
            print(f"   - {org_name} ({org_id})")

        await server.cleanup()
        return True

    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return False


@pytest.mark.asyncio
async def test_basic_functionality():
    """Test basic MCP server functionality"""
    print("\n🔧 Testing MCP server functionality...")

    load_dotenv()
    api_key = os.environ.get("STACKHAWK_API_KEY")

    try:
        server = StackHawkMCPServer(api_key)

        # Get user info to find an organization
        user_info = await server.client.get_user_info()

        if not user_info['user']['external']['organizations']:
            print("❌ No organizations found for this user")
            await server.cleanup()
            return False

        org = user_info['user']['external']['organizations'][0]
        org_id = org['organization']['id']
        org_name = org['organization']['name']

        print(f"✅ Testing with organization: {org_name}")

        # Test getting organization info
        org_info = await server._get_organization_info(org_id)
        print(f"   Applications: {org_info.get('totalApplications', 0)}")
        print(f"   Teams: {org_info.get('totalTeams', 0)}")

        # Test listing applications
        apps_response = await server._list_applications(org_id, page_size=5)
        app_count = len(apps_response.get('applications', []))
        print(f"   Retrieved {app_count} applications with security status")

        await server.cleanup()
        return True

    except Exception as e:
        print(f"❌ Functionality test failed: {e}")
        return False


@pytest.mark.asyncio
async def test_mcp_resources():
    """Test MCP resource reading"""
    print("\n📚 Testing MCP resources...")

    load_dotenv()
    api_key = os.environ.get("STACKHAWK_API_KEY")

    try:
        server = StackHawkMCPServer(api_key)

        # Test user resource
        user_resource = await server._generate_vulnerability_summary()
        print("✅ User vulnerability summary generated")

        # Test dashboard resource
        dashboard_resource = await server._generate_security_dashboard()
        print("✅ Security dashboard generated")

        await server.cleanup()
        return True

    except Exception as e:
        print(f"❌ Resource test failed: {e}")
        return False


async def main():
    """Run all tests"""
    print("🚀 StackHawk MCP Server Test Suite")
    print("=" * 50)

    # Check Python version
    python_version = sys.version_info
    if python_version < (3, 8):
        print(f"❌ Python {python_version.major}.{python_version.minor} detected")
        print("   Python 3.8+ required")
        return
    else:
        print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")

    # Check if .env file exists
    env_file = project_root / ".env"
    if not env_file.exists():
        print("❌ .env file not found")
        print("   Please copy .env.example to .env and add your API key")
        return
    else:
        print("✅ .env file found")

    # Run tests
    tests = [
        ("Authentication", test_authentication),
        ("Basic Functionality", test_basic_functionality),
        ("MCP Resources", test_mcp_resources)
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 30)
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")

    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
        if result:
            passed += 1

    print(f"\nOverall: {passed}/{len(results)} tests passed")

    if passed == len(results):
        print("\n🎉 All tests passed! Your StackHawk MCP server is ready to use.")
        print("\nNext steps:")
        print("1. Configure your MCP client (like Claude Desktop)")
        print("2. Try asking questions about your applications")
        print("3. Explore the security analytics features")
    else:
        print("\n⚠️  Some tests failed. Please check the error messages above.")


if __name__ == "__main__":
    asyncio.run(main())