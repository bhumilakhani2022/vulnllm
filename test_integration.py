#!/usr/bin/env python3
"""End-to-end integration test for AutoPatchAI"""

import os
from parser_enhanced import VulnerabilityParser
from ai_module import VulnerabilityAnalyzer

def test_requirements_analysis():
    """Test analyzing a requirements.txt file"""
    print("Testing requirements.txt analysis...")
    
    # Read the sample requirements file
    with open("test_files/sample_requirements.txt", "r") as f:
        requirements_content = f.read()
    
    # Parse the file
    parser = VulnerabilityParser()
    parsed_data = parser.parse(requirements_content, 'requirements')
    
    print(f"✅ Parsed {len(parsed_data['dependencies'])} dependencies")
    
    # Analyze vulnerabilities
    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze_vulnerabilities(
        parsed_data,
        business_context="Test Python application",
        include_cvss=True,
        include_exploits=True
    )
    
    print(f"✅ Generated analysis with {len(analysis.get('recommendations', []))} recommendations")
    return True

def test_package_json_analysis():
    """Test analyzing a package.json file"""
    print("Testing package.json analysis...")
    
    # Read the sample package.json file
    with open("test_files/sample_package.json", "r") as f:
        package_content = f.read()
    
    # Parse the file
    parser = VulnerabilityParser()
    parsed_data = parser.parse(package_content, 'package_json')
    
    print(f"✅ Parsed {len(parsed_data['dependencies'])} dependencies")
    
    # Analyze vulnerabilities
    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze_vulnerabilities(
        parsed_data,
        business_context="Test Node.js application",
        include_cvss=True,
        include_exploits=True
    )
    
    print(f"✅ Generated analysis with {len(analysis.get('recommendations', []))} recommendations")
    return True

def test_sarif_analysis():
    """Test analyzing a SARIF file"""
    print("Testing SARIF analysis...")
    
    # Read the sample SARIF file
    with open("test_files/sample_sarif.json", "r") as f:
        sarif_content = f.read()
    
    # Parse the file
    parser = VulnerabilityParser()
    parsed_data = parser.parse(sarif_content, 'sarif')
    
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    
    # Analyze vulnerabilities
    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze_vulnerabilities(
        parsed_data,
        business_context="Test application with SAST findings",
        include_cvss=True,
        include_exploits=True
    )
    
    print(f"✅ Generated analysis with {len(analysis.get('recommendations', []))} recommendations")
    return True

def test_dockerfile_analysis():
    """Test analyzing a Dockerfile"""
    print("Testing Dockerfile analysis...")
    
    # Read the sample Dockerfile
    with open("test_files/Dockerfile", "r") as f:
        dockerfile_content = f.read()
    
    # Parse the file
    parser = VulnerabilityParser()
    parsed_data = parser.parse(dockerfile_content, 'dockerfile')
    
    print(f"✅ Parsed {len(parsed_data['base_images'])} base images and {len(parsed_data['packages'])} packages")
    
    # Analyze vulnerabilities
    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze_vulnerabilities(
        parsed_data,
        business_context="Test containerized application",
        include_cvss=True,
        include_exploits=True
    )
    
    print(f"✅ Generated analysis with {len(analysis.get('recommendations', []))} recommendations")
    return True

if __name__ == "__main__":
    print("Running AutoPatchAI Integration Tests")
    print("=" * 60)
    
    tests = [
        test_requirements_analysis,
        test_package_json_analysis,
        test_sarif_analysis,
        test_dockerfile_analysis
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
                print("✅ PASSED\n")
            else:
                print("❌ FAILED\n")
        except Exception as e:
            print(f"❌ FAILED: {e}\n")
    
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The enhanced AutoPatchAI is working correctly.")
    else:
        print("💥 Some tests failed. Please check the errors above.")
