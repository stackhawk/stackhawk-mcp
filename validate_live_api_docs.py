#!/usr/bin/env python3
"""
Live StackHawk API Documentation Validation

This script validates API endpoints against the live StackHawk API documentation
at apidocs.stackhawk.com to ensure our implementation matches the actual API.
"""

import requests
import re
import json
from typing import Dict, List, Tuple
from urllib.parse import urljoin

class StackHawkAPIValidator:
    def __init__(self):
        self.base_docs_url = "https://apidocs.stackhawk.com/reference/"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'StackHawk-MCP-Validator/1.0'
        })
    
    def get_endpoint_docs(self, endpoint_name: str) -> str:
        """Get documentation content for a specific endpoint"""
        try:
            url = urljoin(self.base_docs_url, endpoint_name)
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except Exception as e:
            return f"Error fetching {endpoint_name}: {str(e)}"
    
    def extract_endpoint_info(self, html_content: str, endpoint_name: str) -> Dict:
        """Extract API endpoint information from HTML documentation"""
        info = {
            "endpoint_name": endpoint_name,
            "method": "Unknown",
            "path": "Unknown",
            "available": False,
            "description": "",
            "parameters": [],
            "notes": []
        }
        
        # Check if page exists and has content
        if "404" in html_content or "Page not found" in html_content:
            info["notes"].append("Documentation page not found")
            return info
        
        # Extract method and path from title or content
        method_match = re.search(r'<title>([A-Z]+)\s+([^<]+)</title>', html_content, re.IGNORECASE)
        if method_match:
            info["method"] = method_match.group(1).upper()
            info["available"] = True
        
        # Extract description
        desc_match = re.search(r'<p[^>]*>([^<]+)</p>', html_content)
        if desc_match:
            info["description"] = desc_match.group(1).strip()
        
        # Look for API path patterns
        path_patterns = [
            r'/api/v\d+/[^"\s<>]+',
            r'"path":\s*"([^"]+)"',
            r'<code[^>]*>([^<]*api/v\d+[^<]*)</code>'
        ]
        
        for pattern in path_patterns:
            path_match = re.search(pattern, html_content)
            if path_match:
                info["path"] = path_match.group(1) if path_match.lastindex else path_match.group(0)
                break
        
        return info
    
    def validate_repository_endpoints(self) -> Dict:
        """Validate repository-related endpoints specifically"""
        endpoints_to_check = [
            ("listrepositories", "List repositories"),
            ("listrepos", "List repositories (alternative)"),
            ("getrepository", "Get repository details"),
            ("getrepo", "Get repository details (alternative)"),
            ("listrepositorydata", "Repository data"),
            ("listreposensitivedata", "Repository sensitive data"),
            ("repositorysensitivedata", "Repository sensitive data"),
        ]
        
        results = {}
        print("🔍 Validating Repository Endpoints Against Live API Documentation")
        print("=" * 70)
        
        for endpoint_name, description in endpoints_to_check:
            print(f"\n📋 Checking: {description} ({endpoint_name})")
            
            html_content = self.get_endpoint_docs(endpoint_name)
            endpoint_info = self.extract_endpoint_info(html_content, endpoint_name)
            
            if endpoint_info["available"]:
                print(f"   ✅ FOUND: {endpoint_info['method']} {endpoint_info['path']}")
                if endpoint_info["description"]:
                    print(f"   📝 Description: {endpoint_info['description']}")
            else:
                print(f"   ❌ NOT FOUND: Documentation not available")
            
            results[endpoint_name] = endpoint_info
        
        return results
    
    def validate_sensitive_data_endpoints(self) -> Dict:
        """Validate sensitive data endpoints specifically"""
        endpoints_to_check = [
            ("listsensitivedata", "Organization sensitive data"),
            ("getsensitivedata", "Get sensitive data"),
            ("sensitivedata", "Sensitive data"),
            ("repositorysensitivedata", "Repository sensitive data"),
            ("listrepositorydata", "Repository data"),
        ]
        
        results = {}
        print("\n🔍 Validating Sensitive Data Endpoints Against Live API Documentation")
        print("=" * 70)
        
        for endpoint_name, description in endpoints_to_check:
            print(f"\n📋 Checking: {description} ({endpoint_name})")
            
            html_content = self.get_endpoint_docs(endpoint_name)
            endpoint_info = self.extract_endpoint_info(html_content, endpoint_name)
            
            if endpoint_info["available"]:
                print(f"   ✅ FOUND: {endpoint_info['method']} {endpoint_info['path']}")
                if endpoint_info["description"]:
                    print(f"   📝 Description: {endpoint_info['description']}")
            else:
                print(f"   ❌ NOT FOUND: Documentation not available")
            
            results[endpoint_name] = endpoint_info
        
        return results
    
    def validate_specific_endpoints(self) -> Dict:
        """Validate the specific endpoints used in our implementation"""
        our_endpoints = [
            # Repository endpoints we're using
            ("/api/v1/org/{orgId}/repos", "GET", "List repositories"),
            ("/api/v1/org/{orgId}/repo/{repoId}/sensitive/list", "GET", "Repository sensitive data"),
            ("/api/v1/org/{orgId}/repos/{repoId}/security-scan", "GET", "Repository security scan"),
            
            # Organization endpoints we're using  
            ("/api/v1/org/{orgId}/sensitive-data", "GET", "Organization sensitive data"),
            ("/api/v1/org/{orgId}/sensitive-data/types", "GET", "Sensitive data types"),
            ("/api/v1/org/{orgId}/sensitive-data/summary", "GET", "Sensitive data summary"),
        ]
        
        # Try common documentation page names for these endpoints
        doc_mappings = {
            "/api/v1/org/{orgId}/repos": ["listrepositories", "listrepos"],
            "/api/v1/org/{orgId}/repo/{repoId}/sensitive/list": ["listrepositorydata", "repositorysensitivedata", "listreposensitivedata"],
            "/api/v1/org/{orgId}/repos/{repoId}/security-scan": ["repositorysecurityscan", "getreposecurityscan"],
            "/api/v1/org/{orgId}/sensitive-data": ["listsensitivedata", "getsensitivedata"],
            "/api/v1/org/{orgId}/sensitive-data/types": ["getsensitivedatatypes", "sensitivedata"],
            "/api/v1/org/{orgId}/sensitive-data/summary": ["getsensitivedatasummary", "sensitivedata"],
        }
        
        results = {}
        print("\n🔍 Validating Our Implementation Endpoints Against Live Documentation")
        print("=" * 70)
        
        for endpoint, method, description in our_endpoints:
            print(f"\n📋 Validating: {method} {endpoint}")
            print(f"   Purpose: {description}")
            
            found = False
            doc_pages = doc_mappings.get(endpoint, [])
            
            for doc_page in doc_pages:
                html_content = self.get_endpoint_docs(doc_page)
                endpoint_info = self.extract_endpoint_info(html_content, doc_page)
                
                if endpoint_info["available"]:
                    print(f"   ✅ DOCUMENTATION FOUND: {doc_page}")
                    print(f"   📝 {endpoint_info['description']}")
                    found = True
                    results[endpoint] = {
                        "status": "documented",
                        "doc_page": doc_page,
                        "info": endpoint_info
                    }
                    break
            
            if not found:
                print(f"   ❌ DOCUMENTATION NOT FOUND")
                results[endpoint] = {
                    "status": "not_documented",
                    "doc_page": None,
                    "info": None
                }
        
        return results
    
    def generate_validation_report(self) -> Dict:
        """Generate a comprehensive validation report"""
        print("🚀 Starting Live StackHawk API Documentation Validation")
        print("=" * 70)
        
        # Validate different endpoint categories
        repo_results = self.validate_repository_endpoints()
        sensitive_results = self.validate_sensitive_data_endpoints()
        implementation_results = self.validate_specific_endpoints()
        
        # Generate summary
        print("\n📊 Validation Summary")
        print("=" * 70)
        
        # Count documented vs undocumented endpoints
        documented_count = 0
        total_count = 0
        
        for endpoint, result in implementation_results.items():
            total_count += 1
            if result["status"] == "documented":
                documented_count += 1
        
        success_rate = (documented_count / total_count * 100) if total_count > 0 else 0
        
        print(f"Implementation Endpoints Validated: {documented_count}/{total_count}")
        print(f"Documentation Coverage: {success_rate:.1f}%")
        
        # Provide recommendations
        print(f"\n💡 Recommendations:")
        undocumented = [ep for ep, result in implementation_results.items() if result["status"] == "not_documented"]
        
        if undocumented:
            print(f"   ⚠️  {len(undocumented)} endpoints lack documentation:")
            for endpoint in undocumented:
                print(f"      - {endpoint}")
            print(f"   ✅ Continue using robust fallback mechanisms for these endpoints")
        else:
            print(f"   ✅ All implementation endpoints have documentation")
        
        return {
            "repository_endpoints": repo_results,
            "sensitive_data_endpoints": sensitive_results,
            "implementation_validation": implementation_results,
            "summary": {
                "total_endpoints": total_count,
                "documented_endpoints": documented_count,
                "success_rate": success_rate
            }
        }

def main():
    """Main validation function"""
    validator = StackHawkAPIValidator()
    
    try:
        report = validator.generate_validation_report()
        
        # Save detailed report
        with open('/home/runner/work/stackhawk-mcp/stackhawk-mcp/live_api_validation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed validation report saved to live_api_validation_report.json")
        
        # Final assessment
        success_rate = report["summary"]["success_rate"]
        print(f"\n🎯 Final Assessment:")
        if success_rate >= 80:
            print("   ✅ EXCELLENT - High documentation coverage")
        elif success_rate >= 60:
            print("   ✅ GOOD - Most endpoints documented")
        elif success_rate >= 40:
            print("   ⚠️  MODERATE - Some endpoints lack documentation")
        else:
            print("   ❌ POOR - Many endpoints lack documentation")
        
        print(f"\n✅ Live API documentation validation complete!")
        
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()