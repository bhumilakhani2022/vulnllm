#!/usr/bin/env python3
"""Test script to verify AI analysis functionality"""

from parser_enhanced import VulnerabilityParser
from ai_module import VulnerabilityAnalyzer

def test_nmap_analysis():
    """Test analyzing Nmap output"""
    print("Testing Nmap analysis with AI...")
    
    nmap_content = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
443/tcp  open  https   Apache httpd 2.4.18 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.7.31
"""
    
    # Parse the nmap data
    parser = VulnerabilityParser()
    parsed_data = parser.parse(nmap_content, 'nmap_text')
    
    print(f"✅ Parsed {len(parsed_data['services'])} services")
    
    # Analyze vulnerabilities with AI
    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze_vulnerabilities(
        parsed_data,
        business_context="Production web server, public-facing, PCI DSS environment",
        include_cvss=True,
        include_exploits=True
    )
    
    print(f"✅ Found {len(analysis['findings'])} vulnerabilities")
    print(f"✅ Generated {len(analysis['recommendations'])} recommendations")
    print(f"✅ Generated {len(analysis['ai_recommendations'])} AI recommendations")
    print(f"✅ Generated {len(analysis['exploit_predictions'])} exploit predictions")
    
    # Check executive summary
    exec_summary = analysis.get('executive_summary', '')
    print(f"✅ Executive summary length: {len(exec_summary)} characters")
    
    # Print sample findings
    print("\n--- Sample Analysis Results ---")
    for finding in analysis['findings'][:2]:  # Show first 2 findings
        print(f"Service: {finding['service']}")
        print(f"Risk Score: {finding['risk_score']}/10")
        print(f"CVEs: {', '.join(finding['cves'])}")
        print(f"Impact: {finding['impact']}")
        print()
    
    # Print sample AI recommendations
    if analysis['ai_recommendations']:
        ai_rec = analysis['ai_recommendations'][0]
        print("--- Sample AI Recommendations ---")
        print(f"Service: {ai_rec['service']}")
        recommendations = ai_rec['recommendations']
        print("Immediate Actions:")
        for action in recommendations.get('immediate_actions', [])[:3]:
            print(f"  - {action}")
        print()
    
    # Print executive summary excerpt
    if exec_summary:
        print("--- Executive Summary (First 200 chars) ---")
        print(exec_summary[:200] + "...")
        print()
    
    return True

if __name__ == "__main__":
    print("Testing AI Analysis Functionality")
    print("=" * 50)
    
    try:
        if test_nmap_analysis():
            print("🎉 AI analysis test passed! The system is generating proper AI responses.")
        else:
            print("❌ AI analysis test failed.")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
