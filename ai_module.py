import json
import requests
from typing import Dict, List, Any, Optional
from config import Config
import time
import random


class VulnerabilityAnalyzer:
    """AI-powered vulnerability analyzer that provides comprehensive security analysis"""
    
    def __init__(self):
        self.config = Config()
        
    def analyze_vulnerabilities(self, parsed_data: Dict[str, Any], 
                              business_context: str = "", 
                              include_cvss: bool = True,
                              include_exploits: bool = True) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using AI and provide comprehensive recommendations
        
        Args:
            parsed_data: Parsed Nmap scan data
            business_context: Business context for the analysis
            include_cvss: Whether to include CVSS scores
            include_exploits: Whether to include exploit predictions
            
        Returns:
            Dict containing comprehensive vulnerability analysis
        """
        
        # Extract services from parsed data
        services = parsed_data.get('services', [])
        
        # Create base analysis structure
        analysis = {
            'executive_summary': '',
            'findings': [],
            'exploit_predictions': [],
            'ai_recommendations': [],
            'recommendations': [],
            'business_impact': '',
            'action_plan': [],
            'risk_metrics': {}
        }
        
        # If no services found, return empty analysis
        if not services:
            analysis['executive_summary'] = "No services detected in the scan. Please ensure the target is reachable and responsive."
            return analysis
        
        # Try to get AI analysis if API key is available
        if Config.validate_api_key():
            try:
                ai_analysis = self._get_ai_analysis(services, business_context, include_cvss, include_exploits)
                analysis.update(ai_analysis)
            except Exception as e:
                print(f"AI analysis failed: {e}")
                # Fall back to basic analysis
                analysis = self._get_basic_analysis(services, business_context)
        else:
            # Use basic analysis if no API key
            analysis = self._get_basic_analysis(services, business_context)
        
        # Calculate risk metrics
        analysis['risk_metrics'] = self._calculate_risk_metrics(analysis['findings'])
        
        return analysis
    
    def _get_ai_analysis(self, services: List[Dict], business_context: str, 
                        include_cvss: bool, include_exploits: bool) -> Dict[str, Any]:
        """Get AI-powered vulnerability analysis"""
        
        # Prepare the prompt for AI analysis
        prompt = self._create_analysis_prompt(services, business_context, include_cvss, include_exploits)
        
        # Call OpenAI API
        response = self._call_openai_api(prompt)
        
        # Parse AI response
        return self._parse_ai_response(response, services)
    
    def _get_basic_analysis(self, services: List[Dict], business_context: str) -> Dict[str, Any]:
        """Get basic vulnerability analysis without AI"""
        
        findings = []
        recommendations = []
        ai_recommendations = []
        
        for service in services:
            # Create basic finding
            finding = {
                'service': f"{service.get('service', 'Unknown')} on port {service.get('port', 'Unknown')}",
                'risk_score': self._calculate_basic_risk_score(service),
                'cves': service.get('cves', []),
                'impact': self._get_basic_impact(service)
            }
            findings.append(finding)
            
            # Create basic recommendation
            recommendation = {
                'service': service.get('service', 'Unknown'),
                'action': 'Update Service',
                'current_version': service.get('version', 'Unknown'),
                'target_version': 'Latest',
                'command': f"# Update {service.get('service', 'service')} to latest version",
                'priority': 'High' if finding['risk_score'] >= 7 else 'Medium' if finding['risk_score'] >= 4 else 'Low'
            }
            recommendations.append(recommendation)
            
            # Create basic AI recommendation
            ai_rec = {
                'service': service.get('service', 'Unknown'),
                'recommendations': {
                    'immediate_actions': [
                        f"Update {service.get('service', 'service')} to the latest version",
                        "Review service configuration for security hardening"
                    ],
                    'configuration_changes': [
                        "Disable unnecessary features",
                        "Enable security logging"
                    ],
                    'security_measures': [
                        "Implement network segmentation",
                        "Use firewall rules to restrict access"
                    ],
                    'monitoring_actions': [
                        "Monitor service logs for suspicious activity",
                        "Set up alerts for failed authentication attempts"
                    ]
                }
            }
            ai_recommendations.append(ai_rec)
        
        # Create executive summary
        high_risk_count = len([f for f in findings if f['risk_score'] >= 7])
        medium_risk_count = len([f for f in findings if 4 <= f['risk_score'] < 7])
        low_risk_count = len([f for f in findings if f['risk_score'] < 4])
        
        executive_summary = f"""
**Security Assessment Summary**

This analysis identified {len(services)} services across the target infrastructure. 
The overall security posture shows {high_risk_count} high-risk, {medium_risk_count} medium-risk, and {low_risk_count} low-risk services.

**Key Findings:**
- Total services analyzed: {len(services)}
- High-risk services requiring immediate attention: {high_risk_count}
- Medium-risk services needing scheduled updates: {medium_risk_count}
- Low-risk services with minimal security concerns: {low_risk_count}

**Recommendations:**
- Prioritize patching high-risk services immediately
- Schedule regular security updates for all services
- Implement network segmentation and monitoring
- Review service configurations for security hardening
        """.strip()
        
        # Create business impact
        business_impact = f"""
**Business Impact Analysis**

The identified vulnerabilities pose varying levels of risk to business operations:

**High-Risk Impact:** {high_risk_count} services could lead to data breaches, service disruption, or compliance violations.
**Medium-Risk Impact:** {medium_risk_count} services may result in limited data exposure or service degradation.
**Low-Risk Impact:** {low_risk_count} services present minimal business risk but should be monitored.

**Business Context:** {business_context if business_context else "No specific business context provided."}
        """.strip()
        
        # Create action plan
        action_plan = [
            {
                'step': 'Immediate Security Review',
                'timeline': 'Within 24 hours',
                'description': 'Review and address all high-risk vulnerabilities'
            },
            {
                'step': 'Patch Management',
                'timeline': 'Within 1 week',
                'description': 'Apply security patches to all identified vulnerabilities'
            },
            {
                'step': 'Security Hardening',
                'timeline': 'Within 2 weeks',
                'description': 'Implement recommended configuration changes'
            },
            {
                'step': 'Monitoring Setup',
                'timeline': 'Within 1 month',
                'description': 'Establish continuous security monitoring'
            }
        ]
        
        return {
            'executive_summary': executive_summary,
            'findings': findings,
            'exploit_predictions': [],  # Basic analysis doesn't include exploit predictions
            'ai_recommendations': ai_recommendations,
            'recommendations': recommendations,
            'business_impact': business_impact,
            'action_plan': action_plan
        }
    
    def _calculate_basic_risk_score(self, service: Dict) -> float:
        """Calculate basic risk score for a service"""
        score = 3.0  # Base score
        
        # Add score for known vulnerabilities
        if service.get('cves'):
            score += len(service.get('cves', [])) * 0.5
        
        # Add score for common vulnerable services
        vulnerable_services = ['ssh', 'ftp', 'telnet', 'http', 'https', 'mysql', 'postgresql']
        if any(vuln in service.get('service', '').lower() for vuln in vulnerable_services):
            score += 2.0
        
        # Add score for old versions (if version contains old indicators)
        version = service.get('version', '').lower()
        if any(old in version for old in ['old', 'legacy', 'deprecated']):
            score += 1.5
        
        return min(score, 10.0)  # Cap at 10
    
    def _get_basic_impact(self, service: Dict) -> str:
        """Get basic impact assessment for a service"""
        service_name = service.get('service', '').lower()
        
        if 'ssh' in service_name:
            return "Potential remote access and system compromise"
        elif 'http' in service_name or 'web' in service_name:
            return "Web application vulnerabilities and data exposure"
        elif 'database' in service_name or 'mysql' in service_name or 'postgresql' in service_name:
            return "Database access and data breach potential"
        elif 'ftp' in service_name:
            return "File transfer vulnerabilities and data leakage"
        else:
            return "Service-specific vulnerabilities and potential exploitation"
    
    def _create_analysis_prompt(self, services: List[Dict], business_context: str, 
                              include_cvss: bool, include_exploits: bool) -> str:
        """Create prompt for AI analysis"""
        
        services_text = "\n".join([
            f"- {service.get('service', 'Unknown')} on port {service.get('port', 'Unknown')} "
            f"(Version: {service.get('version', 'Unknown')})" +
            (f" CVEs: {', '.join(service.get('cves', []))}" if service.get('cves') else "")
            for service in services
        ])
        
        prompt = f"""
As a cybersecurity expert, analyze the following network services and provide a comprehensive security assessment:

**Detected Services:**
{services_text}

**Business Context:**
{business_context if business_context else "General security assessment"}

Please provide a detailed analysis in JSON format with the following structure:
{{
    "executive_summary": "Executive summary of findings and recommendations",
    "findings": [
        {{
            "service": "service name and port",
            "risk_score": 8.5,
            "cves": ["CVE-2023-1234", "CVE-2023-5678"],
            "impact": "description of potential impact"
        }}
    ],
    "exploit_predictions": [
        {{
            "service": "service name",
            "prediction": {{
                "exploit_likelihood": 0.8,
                "time_to_exploit": "Hours",
                "confidence_score": 0.9,
                "mitigation_priority": "Critical",
                "attack_vectors": ["description of attack vectors"]
            }}
        }}
    ],
    "ai_recommendations": [
        {{
            "service": "service name",
            "recommendations": {{
                "immediate_actions": ["list of immediate actions"],
                "configuration_changes": ["list of configuration changes"],
                "security_measures": ["list of security measures"],
                "monitoring_actions": ["list of monitoring actions"],
                "rollback_plan": "rollback plan if needed"
            }}
        }}
    ],
    "business_impact": "detailed business impact analysis",
    "action_plan": [
        {{
            "step": "action step",
            "timeline": "timeframe",
            "description": "detailed description"
        }}
    ]
}}

Focus on:
- Accurate risk scoring (0-10 scale)
- Specific CVEs and vulnerabilities
- Practical remediation steps
- Business impact assessment
{'- CVSS scores and detailed vulnerability analysis' if include_cvss else ''}
{'- Exploit likelihood and attack vector analysis' if include_exploits else ''}
"""
        
        return prompt
    
    def _call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API with the analysis prompt"""
        
        headers = {
            'Authorization': f'Bearer {Config.OPENAI_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': Config.OPENAI_MODEL,
            'messages': [
                {
                    'role': 'system',
                    'content': 'You are a cybersecurity expert providing detailed vulnerability analysis.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'max_tokens': Config.DEFAULT_MAX_TOKENS,
            'temperature': Config.DEFAULT_TEMPERATURE
        }
        
        response = requests.post(
            Config.OPENAI_API_URL,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"OpenAI API call failed with status {response.status_code}: {response.text}")
        
        response_data = response.json()
        return response_data['choices'][0]['message']['content']
    
    def _parse_ai_response(self, response: str, services: List[Dict]) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        
        try:
            # Try to parse as JSON
            if response.strip().startswith('{'):
                return json.loads(response)
            else:
                # If not JSON, try to extract JSON from markdown code blocks
                import re
                json_match = re.search(r'```json\n(.*?)\n```', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(1))
                else:
                    # Fall back to basic analysis if parsing fails
                    raise Exception("Could not parse AI response")
        
        except Exception as e:
            print(f"Failed to parse AI response: {e}")
            # Fall back to basic analysis
            return self._get_basic_analysis(services, "")
    
    def _calculate_risk_metrics(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate risk metrics from findings"""
        
        if not findings:
            return {
                'total_findings': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'average_risk_score': 0
            }
        
        high_risk = len([f for f in findings if f.get('risk_score', 0) >= 7])
        medium_risk = len([f for f in findings if 4 <= f.get('risk_score', 0) < 7])
        low_risk = len([f for f in findings if f.get('risk_score', 0) < 4])
        
        total_risk = sum(f.get('risk_score', 0) for f in findings)
        avg_risk = total_risk / len(findings) if findings else 0
        
        return {
            'total_findings': len(findings),
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'average_risk_score': round(avg_risk, 1)
        }
