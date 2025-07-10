#!/usr/bin/env python3
"""Test script for the enhanced vulnerability parser"""

import json
from parser_enhanced import VulnerabilityParser

def test_requirements_parsing():
    """Test requirements.txt parsing"""
    requirements_content = """
# This is a comment
requests>=2.31.0
flask==2.3.2
numpy
django>=4.0.0,<5.0.0
"""
    parser = VulnerabilityParser()
    result = parser.parse(requirements_content, 'requirements')
    print("Requirements.txt parsing result:")
    print(json.dumps(result, indent=2))
    print("-" * 50)

def test_package_json_parsing():
    """Test package.json parsing"""
    package_json_content = """{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17.21",
    "axios": "1.4.0"
  },
  "devDependencies": {
    "jest": "^29.5.0",
    "typescript": "~5.0.0"
  }
}"""
    parser = VulnerabilityParser()
    result = parser.parse(package_json_content, 'package_json')
    print("Package.json parsing result:")
    print(json.dumps(result, indent=2))
    print("-" * 50)

def test_dockerfile_parsing():
    """Test Dockerfile parsing"""
    dockerfile_content = """FROM ubuntu:20.04
RUN apt-get update && apt-get install -y \\
    python3 \\
    python3-pip \\
    curl \\
    wget
RUN yum install -y nodejs
RUN apk add --no-cache git
COPY . /app
WORKDIR /app
"""
    parser = VulnerabilityParser()
    result = parser.parse(dockerfile_content, 'dockerfile')
    print("Dockerfile parsing result:")
    print(json.dumps(result, indent=2))
    print("-" * 50)

def test_sarif_parsing():
    """Test SARIF parsing"""
    sarif_content = """{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Bandit"
        }
      },
      "results": [
        {
          "ruleId": "B101",
          "level": "error",
          "message": {
            "text": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "test.py"
                },
                "region": {
                  "startLine": 10,
                  "startColumn": 5
                }
              }
            }
          ]
        }
      ]
    }
  ]
}"""
    parser = VulnerabilityParser()
    result = parser.parse(sarif_content, 'sarif')
    print("SARIF parsing result:")
    print(json.dumps(result, indent=2))
    print("-" * 50)

def test_nmap_text_parsing():
    """Test Nmap text parsing"""
    nmap_content = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
443/tcp  open  https   Apache httpd 2.4.18 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.7.31
"""
    parser = VulnerabilityParser()
    result = parser.parse(nmap_content, 'nmap_text')
    print("Nmap text parsing result:")
    print(json.dumps(result, indent=2))
    print("-" * 50)

if __name__ == "__main__":
    print("Testing Enhanced Vulnerability Parser")
    print("=" * 60)
    
    test_requirements_parsing()
    test_package_json_parsing()
    test_dockerfile_parsing()
    test_sarif_parsing()
    test_nmap_text_parsing()
    
    print("All tests completed!")
