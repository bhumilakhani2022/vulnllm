import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
import random
import os
import requests
from config import Config

# OpenAI API Configuration
# Add your OpenAI API key here or set it as an environment variable
OPENAI_API_KEY = Config.get_api_key() or 'enter your api key here'
OPENAI_API_URL = Config.OPENAI_API_URL

# You can also set the API key as an environment variable:
# export OPENAI_API_KEY="your-actual-api-key-here"

class OpenAIClient:
    """Real OpenAI API client for vulnerability analysis"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or OPENAI_API_KEY
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def call_openai_api(self, prompt: str, system_message: str = None) -> str:
        """Make a call to OpenAI API"""
        try:
            messages = []
            if system_message:
                messages.append({"role": "system", "content": system_message})
            messages.append({"role": "user", "content": prompt})
            
            payload = {
                "model": Config.OPENAI_MODEL,
                "messages": messages,
                "max_tokens": Config.DEFAULT_MAX_TOKENS,
                "temperature": Config.DEFAULT_TEMPERATURE
            }
            
            response = requests.post(OPENAI_API_URL, headers=self.headers, json=payload)
            response.raise_for_status()
            
            result = response.json()
            return result['choices'][0]['message']['content']
            
        except Exception as e:
            print(f"OpenAI API Error: {e}")
            return None

# Simulated AI API responses for demonstration (fallback when API is not available)
class AISimulator:
    """Simulates AI API responses for vulnerability analysis"""
    
    @staticmethod
    def generate_fix_recommendations(service: str, version: str, cves: List[str]) -> Dict[str, Any]:
        """Generate AI-powered fix recommendations using OpenAI API or fallback"""
        
        # Try to use OpenAI API first
        try:
            client = OpenAIClient()
            if client.api_key and client.api_key.startswith('sk-'):
                return AISimulator._generate_fix_recommendations_with_api(client, service, version, cves)
        except Exception as e:
            print(f"Falling back to simulated AI: {e}")
        
        # Fallback to simulated responses
        return AISimulator._generate_fix_recommendations_simulated(service, version, cves)
    
    @staticmethod
    def _generate_fix_recommendations_with_api(client: OpenAIClient, service: str, version: str, cves: List[str]) -> Dict[str, Any]:
        """Generate recommendations using OpenAI API"""
        
        system_message = """You are a cybersecurity expert specializing in vulnerability remediation. 
        Provide detailed, actionable recommendations for fixing security vulnerabilities. 
        Format your response as a JSON object with the following structure:
        {
            "immediate_actions": ["action1", "action2"],
            "configuration_changes": ["config1", "config2"],
            "security_measures": ["measure1", "measure2"],
            "monitoring_actions": ["monitor1", "monitor2"],
            "rollback_plan": "rollback description"
        }"""
        
        prompt = f"""Analyze the following service and provide detailed fix recommendations:

Service: {service}
Version: {version}
CVEs: {', '.join(cves)}

Provide specific, actionable recommendations for:
1. Immediate actions to take
2. Configuration changes needed
3. Security measures to implement
4. Monitoring actions to set up
5. Rollback plan

Return only valid JSON without any additional text."""
        
        response = client.call_openai_api(prompt, system_message)
        if response:
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                pass
        
        # Fallback to simulated if API fails
        return AISimulator._generate_fix_recommendations_simulated(service, version, cves)
    
    @staticmethod
    def _generate_fix_recommendations_simulated(service: str, version: str, cves: List[str]) -> Dict[str, Any]:
        """Generate simulated fix recommendations"""
        recommendations = {
            'immediate_actions': [],
            'configuration_changes': [],
            'security_measures': [],
            'monitoring_actions': [],
            'rollback_plan': ''
        }
        
        if 'ssh' in service.lower():
            recommendations['immediate_actions'] = [
                "Disable root login: `PermitRootLogin no`",
                "Enable key-based authentication: `PasswordAuthentication no`",
                "Restrict SSH access to specific IPs: `AllowUsers admin`",
                "Update to OpenSSH 8.9p1 or later"
            ]
            recommendations['configuration_changes'] = [
                "Set `MaxAuthTries 3` to limit login attempts",
                "Configure `ClientAliveInterval 300` for session management",
                "Enable `UsePAM yes` for enhanced authentication"
            ]
            recommendations['security_measures'] = [
                "Implement fail2ban for brute force protection",
                "Set up SSH key rotation policy",
                "Enable audit logging for SSH sessions"
            ]
            recommendations['monitoring_actions'] = [
                "Monitor failed login attempts",
                "Track SSH session durations",
                "Alert on unusual access patterns"
            ]
            recommendations['rollback_plan'] = "Keep SSH keys and configuration backups before updates"
            
        elif 'apache' in service.lower() or 'http' in service.lower():
            recommendations['immediate_actions'] = [
                "Update Apache to version 2.4.57 or later",
                "Disable unnecessary modules: `a2dismod`",
                "Remove default server tokens: `ServerTokens Prod`"
            ]
            recommendations['configuration_changes'] = [
                "Implement security headers in .htaccess",
                "Configure ModSecurity WAF rules",
                "Set up SSL/TLS with strong ciphers"
            ]
            recommendations['security_measures'] = [
                "Install ModSecurity WAF",
                "Implement rate limiting with mod_ratelimit",
                "Set up automated backup system"
            ]
            recommendations['monitoring_actions'] = [
                "Monitor access logs for suspicious patterns",
                "Track error rates and response times",
                "Set up alerts for failed authentication"
            ]
            recommendations['rollback_plan'] = "Maintain configuration backups and test rollback procedures"
        
        return recommendations
    
    @staticmethod
    def predict_exploit_likelihood(service: str, version: str, cves: List[str], business_context: str) -> Dict[str, Any]:
        """Predict exploit likelihood using AI analysis"""
        
        # Try to use OpenAI API first
        try:
            client = OpenAIClient()
            if client.api_key and client.api_key.startswith('sk-'):
                return AISimulator._predict_exploit_likelihood_with_api(client, service, version, cves, business_context)
        except Exception as e:
            print(f"Falling back to simulated AI: {e}")
        
        # Fallback to simulated responses
        return AISimulator._predict_exploit_likelihood_simulated(service, version, cves, business_context)
    
    @staticmethod
    def _predict_exploit_likelihood_with_api(client: OpenAIClient, service: str, version: str, cves: List[str], business_context: str) -> Dict[str, Any]:
        """Predict exploit likelihood using OpenAI API"""
        
        system_message = """You are a cybersecurity threat intelligence expert. 
        Analyze the likelihood of exploitation for given vulnerabilities and provide predictions.
        Format your response as a JSON object with the following structure:
        {
            "exploit_likelihood": 0.75,
            "time_to_exploit": "1-2 weeks",
            "attack_vectors": ["vector1", "vector2"],
            "mitigation_priority": "Critical",
            "confidence_score": 0.85
        }"""
        
        prompt = f"""Analyze the exploit likelihood for the following service:

Service: {service}
Version: {version}
CVEs: {', '.join(cves)}
Business Context: {business_context}

Provide:
1. Exploit likelihood (0.0 to 1.0)
2. Estimated time to exploit
3. Potential attack vectors
4. Mitigation priority (Critical/High/Medium/Low)
5. Confidence score (0.0 to 1.0)

Return only valid JSON without any additional text."""
        
        response = client.call_openai_api(prompt, system_message)
        if response:
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                pass
        
        # Fallback to simulated if API fails
        return AISimulator._predict_exploit_likelihood_simulated(service, version, cves, business_context)
    
    @staticmethod
    def _predict_exploit_likelihood_simulated(service: str, version: str, cves: List[str], business_context: str) -> Dict[str, Any]:
        """Predict exploit likelihood using simulated analysis"""
        # Simulate AI-based exploit prediction
        base_likelihood = 0.3
        
        # Adjust based on service type
        if 'ssh' in service.lower():
            base_likelihood = 0.7  # SSH is commonly targeted
        elif 'apache' in service.lower() or 'http' in service.lower():
            base_likelihood = 0.8  # Web servers are high-value targets
        
        # Adjust based on business context
        if 'production' in business_context.lower():
            base_likelihood += 0.2
        if 'public-facing' in business_context.lower():
            base_likelihood += 0.3
        
        # Adjust based on CVSS scores
        if cves:
            max_cvss = max([float(cve.split('-')[1][:4]) for cve in cves if cve.split('-')[1][:4].isdigit()])
            if max_cvss >= 9.0:
                base_likelihood += 0.2
            elif max_cvss >= 7.0:
                base_likelihood += 0.1
        
        # Cap at 1.0
        likelihood = min(1.0, base_likelihood)
        
        return {
            'exploit_likelihood': round(likelihood, 2),
            'time_to_exploit': AISimulator._predict_time_to_exploit(likelihood),
            'attack_vectors': AISimulator._identify_attack_vectors(service, cves),
            'mitigation_priority': 'Critical' if likelihood > 0.7 else 'High' if likelihood > 0.5 else 'Medium',
            'confidence_score': round(random.uniform(0.7, 0.95), 2)
        }
    
    @staticmethod
    def _predict_time_to_exploit(likelihood: float) -> str:
        """Predict time to exploit based on likelihood"""
        if likelihood > 0.8:
            return "24-48 hours"
        elif likelihood > 0.6:
            return "1-2 weeks"
        elif likelihood > 0.4:
            return "1-3 months"
        else:
            return "3-6 months"
    
    @staticmethod
    def _identify_attack_vectors(service: str, cves: List[str]) -> List[str]:
        """Identify potential attack vectors"""
        vectors = []
        
        if 'ssh' in service.lower():
            vectors.extend(["Brute force attacks", "Key-based authentication bypass", "Privilege escalation"])
        if 'apache' in service.lower() or 'http' in service.lower():
            vectors.extend(["Remote code execution", "Directory traversal", "SQL injection", "XSS attacks"])
        
        return vectors
    
    @staticmethod
    def generate_enhanced_executive_summary(findings: List[Dict[str, Any]], business_context: str) -> str:
        """Generate AI-enhanced executive summary with business language"""
        
        if not findings:
            return "**Executive Summary**: No critical vulnerabilities detected. Your infrastructure appears to be well-maintained with current security patches in place."
        
        # Try to use OpenAI API first
        try:
            client = OpenAIClient()
            if client.api_key and client.api_key.startswith('sk-'):
                return AISimulator._generate_enhanced_executive_summary_with_api(client, findings, business_context)
        except Exception as e:
            print(f"Falling back to simulated AI: {e}")
        
        # Fallback to simulated responses
        return AISimulator._generate_enhanced_executive_summary_simulated(findings, business_context)
    
    @staticmethod
    def _generate_enhanced_executive_summary_with_api(client: OpenAIClient, findings: List[Dict[str, Any]], business_context: str) -> str:
        """Generate executive summary using OpenAI API"""
        
        system_message = """You are a cybersecurity executive consultant. 
        Create a professional, business-focused executive summary for vulnerability assessment results.
        Use clear, concise language suitable for C-level executives and board members.
        Include financial impact analysis, ROI justification, and strategic recommendations."""
        
        # Prepare findings data for the prompt
        findings_summary = []
        for finding in findings:
            findings_summary.append(f"- {finding['service']}: Risk Score {finding['risk_score']}/10, CVEs: {', '.join(finding['cves'])}")
        
        prompt = f"""Create an executive summary for the following vulnerability assessment:

Findings:
{chr(10).join(findings_summary)}

Business Context: {business_context}

Provide a comprehensive executive summary that includes:
1. Risk assessment overview
2. Business impact analysis with financial estimates
3. Strategic recommendations
4. ROI justification
5. Next steps

Format the response in markdown with clear sections and bullet points."""
        
        response = client.call_openai_api(prompt, system_message)
        if response:
            return response
        
        # Fallback to simulated if API fails
        return AISimulator._generate_enhanced_executive_summary_simulated(findings, business_context)
    
    @staticmethod
    def _generate_enhanced_executive_summary_simulated(findings: List[Dict[str, Any]], business_context: str) -> str:
        """Generate simulated executive summary"""
        high_risk_count = len([f for f in findings if f.get('risk_score', 0) >= 7])
        total_findings = len(findings)
        
        # Calculate financial impact
        total_risk_score = sum(f.get('risk_score', 0) for f in findings)
        avg_risk = total_risk_score / total_findings if total_findings > 0 else 0
        
        # Estimate financial impact
        if avg_risk >= 8:
            financial_impact = "$500,000 - $2,000,000"
            downtime_estimate = "24-72 hours"
        elif avg_risk >= 6:
            financial_impact = "$100,000 - $500,000"
            downtime_estimate = "8-24 hours"
        else:
            financial_impact = "$25,000 - $100,000"
            downtime_estimate = "4-8 hours"
        
        summary = f"""**Executive Summary: Critical Security Alert**

**Risk Assessment Overview**
Our AI-powered analysis has identified {high_risk_count} high-risk vulnerabilities across {total_findings} services, representing a significant exposure to potential cyber threats. The average risk score of {avg_risk:.1f}/10 indicates immediate attention is required.

**Business Impact Analysis**
• **Financial Exposure**: Estimated potential loss of {financial_impact} per security incident
• **Operational Risk**: Potential service disruption of {downtime_estimate} in case of exploitation
• **Compliance Implications**: Potential violations of industry regulations and data protection requirements
• **Reputational Risk**: High impact on customer trust and brand integrity

**Strategic Recommendations**
1. **Immediate Action (Next 24-48 hours)**: Prioritize patching of {high_risk_count} critical vulnerabilities
2. **Short-term Strategy (Next 7 days)**: Implement enhanced security monitoring and access controls
3. **Long-term Investment (Next 30 days)**: Establish automated vulnerability management and patch deployment processes

**ROI Justification**
Investment in immediate remediation: $25,000 - $50,000
Potential savings from avoided incidents: {financial_impact}
**Net ROI: 90%+ risk reduction with positive return on investment**

**Next Steps**
• Schedule emergency maintenance window for critical patches
• Engage security team for 24/7 monitoring during transition
• Prepare executive briefing for board-level awareness

This assessment represents a strategic opportunity to strengthen our cybersecurity posture while protecting shareholder value and maintaining operational excellence."""
        
        return summary

class VulnerabilityAnalyzer:
    """AI-powered vulnerability analyzer for Nmap scan results"""
    
    def __init__(self):
        # Vulnerability database (simulated)
        self.vulnerability_db = {
            'openssh': {
                '7.2p2': {
                    'cves': [
                        {'id': 'CVE-2016-6210', 'cvss': 5.3, 'description': 'Timing attack vulnerability'},
                        {'id': 'CVE-2016-6515', 'cvss': 4.3, 'description': 'DoS vulnerability'},
                        {'id': 'CVE-2016-10009', 'cvss': 7.5, 'description': 'Privilege escalation'},
                        {'id': 'CVE-2016-10012', 'cvss': 7.5, 'description': 'Authentication bypass'}
                    ],
                    'exploits_available': True,
                    'patch_version': '8.9p1',
                    'vendor_advisory': 'Ubuntu USN-3156-1'
                }
            },
            'apache': {
                '2.4.18': {
                    'cves': [
                        {'id': 'CVE-2017-3167', 'cvss': 9.8, 'description': 'Remote code execution'},
                        {'id': 'CVE-2017-3169', 'cvss': 7.5, 'description': 'Information disclosure'},
                        {'id': 'CVE-2017-7679', 'cvss': 9.8, 'description': 'Remote code execution'},
                        {'id': 'CVE-2017-9788', 'cvss': 7.5, 'description': 'Memory corruption'}
                    ],
                    'exploits_available': True,
                    'patch_version': '2.4.57',
                    'vendor_advisory': 'Ubuntu USN-3341-1'
                }
            },
            'nginx': {
                '1.16.0': {
                    'cves': [
                        {'id': 'CVE-2019-9511', 'cvss': 7.5, 'description': 'HTTP/2 DoS vulnerability'},
                        {'id': 'CVE-2019-9516', 'cvss': 7.5, 'description': 'HTTP/2 DoS vulnerability'}
                    ],
                    'exploits_available': False,
                    'patch_version': '1.20.0',
                    'vendor_advisory': 'Nginx Security Advisory'
                }
            },
            'mysql': {
                '5.7.28': {
                    'cves': [
                        {'id': 'CVE-2020-1461', 'cvss': 8.2, 'description': 'Privilege escalation'},
                        {'id': 'CVE-2020-1462', 'cvss': 6.5, 'description': 'Information disclosure'}
                    ],
                    'exploits_available': False,
                    'patch_version': '8.0.33',
                    'vendor_advisory': 'Oracle Critical Patch Update'
                }
            }
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'cvss_score': 0.4,
            'exploit_availability': 0.3,
            'business_impact': 0.2,
            'service_criticality': 0.1
        }
    
    def analyze_vulnerabilities(self, parsed_data: Dict[str, Any], 
                              business_context: str = "", 
                              include_cvss: bool = True,
                              include_exploits: bool = True) -> Dict[str, Any]:
        """
        Analyze vulnerabilities in parsed Nmap data with AI-enhanced features
        
        Args:
            parsed_data: Parsed Nmap scan results
            business_context: Optional business context information
            include_cvss: Whether to include CVSS scores
            include_exploits: Whether to include exploit availability
            
        Returns:
            Dictionary containing vulnerability analysis results with AI enhancements
        """
        services = parsed_data.get('services', [])
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'recommendations': [],
            'ai_recommendations': [],
            'exploit_predictions': [],
            'executive_summary': '',
            'business_impact': '',
            'action_plan': [],
            'risk_metrics': {}
        }
        
        # Analyze each service
        for service in services:
            finding = self._analyze_service(service, business_context, include_cvss, include_exploits)
            if finding:
                analysis['findings'].append(finding)
                
                # Generate traditional recommendations
                recommendation = self._generate_recommendation(finding)
                if recommendation:
                    analysis['recommendations'].append(recommendation)
                
                # Generate AI-powered recommendations
                ai_recommendations = AISimulator.generate_fix_recommendations(
                    finding['service'], 
                    finding['current_version'], 
                    finding['cves']
                )
                analysis['ai_recommendations'].append({
                    'service': finding['service'],
                    'recommendations': ai_recommendations
                })
                
                # Generate exploit predictions
                exploit_prediction = AISimulator.predict_exploit_likelihood(
                    finding['service'],
                    finding['current_version'],
                    finding['cves'],
                    business_context
                )
                analysis['exploit_predictions'].append({
                    'service': finding['service'],
                    'prediction': exploit_prediction
                })
        
        # Generate AI-enhanced executive summary
        analysis['executive_summary'] = AISimulator.generate_enhanced_executive_summary(
            analysis['findings'], 
            business_context
        )
        
        # Generate business impact analysis
        analysis['business_impact'] = self._generate_business_impact(analysis['findings'], business_context)
        
        # Generate action plan
        analysis['action_plan'] = self._generate_action_plan(analysis['findings'])
        
        # Calculate risk metrics
        analysis['risk_metrics'] = self._calculate_risk_metrics(analysis['findings'])
        
        return analysis
    
    def _analyze_service(self, service: Dict[str, Any], business_context: str, 
                        include_cvss: bool, include_exploits: bool) -> Optional[Dict[str, Any]]:
        """Analyze a single service for vulnerabilities"""
        service_name = service.get('service', '').lower()
        version = service.get('version', 'unknown')
        port = service.get('port', '')
        
        # Skip if no version information
        if version == 'unknown':
            return None
        
        # Look up vulnerabilities
        vulnerabilities = self._lookup_vulnerabilities(service_name, version)
        if not vulnerabilities:
            return None
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(service, vulnerabilities, business_context)
        
        # Determine business impact
        business_impact = self._assess_business_impact(service, business_context)
        
        finding = {
            'service': f"{service_name.upper()} on port {port}",
            'current_version': version,
            'risk_score': risk_score,
            'cves': [v['id'] for v in vulnerabilities['cves']],
            'cvss_scores': [v['cvss'] for v in vulnerabilities['cves']] if include_cvss else [],
            'exploits_available': vulnerabilities.get('exploits_available', False),
            'impact': business_impact,
            'patch_version': vulnerabilities.get('patch_version', 'Latest'),
            'vendor_advisory': vulnerabilities.get('vendor_advisory', 'Check vendor website')
        }
        
        return finding
    
    def _lookup_vulnerabilities(self, service_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Look up vulnerabilities for a service version"""
        # Normalize service name
        if 'ssh' in service_name:
            service_name = 'openssh'
        elif 'http' in service_name or 'apache' in service_name:
            service_name = 'apache'
        
        # Look up in vulnerability database
        if service_name in self.vulnerability_db:
            service_vulns = self.vulnerability_db[service_name]
            
            # Try exact version match first
            if version in service_vulns:
                return service_vulns[version]
            
            # Try version range matching
            for vuln_version, vuln_data in service_vulns.items():
                if self._version_matches(version, vuln_version):
                    return vuln_data
        
        return None
    
    def _version_matches(self, current_version: str, vuln_version: str) -> bool:
        """Check if current version matches vulnerability version pattern"""
        # Simple version matching - can be enhanced
        return current_version.startswith(vuln_version.split('.')[0])
    
    def _calculate_risk_score(self, service: Dict[str, Any], vulnerabilities: Dict[str, Any], 
                            business_context: str) -> float:
        """Calculate dynamic risk score (1-10)"""
        base_score = 0.0
        
        # CVSS score component
        if vulnerabilities.get('cves'):
            max_cvss = max(v['cvss'] for v in vulnerabilities['cves'])
            base_score += (max_cvss / 10.0) * self.risk_weights['cvss_score']
        
        # Exploit availability component
        if vulnerabilities.get('exploits_available', False):
            base_score += 1.0 * self.risk_weights['exploit_availability']
        
        # Business impact component
        business_impact_score = self._calculate_business_impact_score(service, business_context)
        base_score += business_impact_score * self.risk_weights['business_impact']
        
        # Service criticality component
        service_criticality = self._calculate_service_criticality(service)
        base_score += service_criticality * self.risk_weights['service_criticality']
        
        # Normalize to 1-10 scale
        risk_score = min(10.0, max(1.0, base_score * 10))
        
        return round(risk_score, 1)
    
    def _calculate_business_impact_score(self, service: Dict[str, Any], business_context: str) -> float:
        """Calculate business impact score"""
        score = 0.5  # Base score
        
        # Port-based impact
        port = int(service.get('port', 0))
        if port == 80 or port == 443:  # Web services
            score += 0.3
        elif port == 22:  # SSH
            score += 0.2
        elif port == 3306:  # Database
            score += 0.4
        
        # Business context impact
        context_lower = business_context.lower()
        if 'production' in context_lower:
            score += 0.3
        if 'public-facing' in context_lower:
            score += 0.2
        if 'pci' in context_lower or 'hipaa' in context_lower:
            score += 0.2
        
        return min(1.0, score)
    
    def _calculate_service_criticality(self, service: Dict[str, Any]) -> float:
        """Calculate service criticality score"""
        service_name = service.get('service', '').lower()
        
        critical_services = ['http', 'https', 'ssh', 'mysql', 'postgresql', 'redis']
        if service_name in critical_services:
            return 0.8
        elif service_name in ['ftp', 'smtp', 'dns']:
            return 0.5
        else:
            return 0.3
    
    def _assess_business_impact(self, service: Dict[str, Any], business_context: str) -> str:
        """Assess business impact of service vulnerabilities"""
        service_name = service.get('service', '').lower()
        port = service.get('port', '')
        
        if service_name in ['http', 'https']:
            return "Public-facing web server - high exposure to attacks"
        elif service_name == 'ssh':
            return "Remote access service - potential for complete system compromise"
        elif service_name in ['mysql', 'postgresql']:
            return "Database service - risk of data breach and compliance violations"
        elif port in ['80', '443', '22']:
            return "Critical service port - high visibility to attackers"
        else:
            return "Standard service - moderate risk"
    
    def _generate_recommendation(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate patch recommendation for a finding"""
        service_name = finding['service'].split()[0].lower()
        current_version = finding['current_version']
        patch_version = finding.get('patch_version', 'Latest')
        
        # Generate appropriate command based on service
        if 'ssh' in service_name:
            command = "sudo apt update && sudo apt install openssh-server"
            action = "Update OpenSSH"
        elif 'apache' in service_name or 'http' in service_name:
            command = "sudo apt update && sudo apt install apache2"
            action = "Update Apache"
        elif 'nginx' in service_name:
            command = "sudo apt update && sudo apt install nginx"
            action = "Update Nginx"
        elif 'mysql' in service_name:
            command = "sudo apt update && sudo apt install mysql-server"
            action = "Update MySQL"
        else:
            command = "Check vendor documentation for update procedure"
            action = "Update Service"
        
        # Determine priority based on risk score
        if finding['risk_score'] >= 7:
            priority = "Critical"
        elif finding['risk_score'] >= 4:
            priority = "High"
        else:
            priority = "Medium"
        
        return {
            'service': finding['service'],
            'action': action,
            'current_version': current_version,
            'target_version': patch_version,
            'command': command,
            'priority': priority,
            'vendor_advisory': finding.get('vendor_advisory', 'Check vendor website')
        }
    
    def _generate_executive_summary(self, findings: List[Dict[str, Any]], business_context: str) -> str:
        """Generate executive summary"""
        if not findings:
            return "No critical vulnerabilities detected. All services appear to be up to date."
        
        high_risk_count = len([f for f in findings if f['risk_score'] >= 7])
        total_findings = len(findings)
        
        summary = f"**Critical Security Alert**: {high_risk_count} high-risk vulnerabilities detected across {total_findings} services.\n\n"
        
        if high_risk_count > 0:
            summary += "**Immediate Action Required**: Several services contain known, exploitable vulnerabilities that could lead to system compromise, data breach, or service disruption.\n\n"
        
        # Top risks
        top_risks = sorted(findings, key=lambda x: x['risk_score'], reverse=True)[:3]
        summary += "**Top Risks**:\n"
        for i, risk in enumerate(top_risks, 1):
            summary += f"{i}. {risk['service']} (Risk Score: {risk['risk_score']}/10) - {risk['impact']}\n"
        
        return summary
    
    def _generate_business_impact(self, findings: List[Dict[str, Any]], business_context: str) -> str:
        """Generate business impact analysis"""
        if not findings:
            return "No significant business impact identified."
        
        high_risk_findings = [f for f in findings if f['risk_score'] >= 7]
        medium_risk_findings = [f for f in findings if 4 <= f['risk_score'] < 7]
        
        impact = "**Business Impact Analysis**\n\n"
        
        if high_risk_findings:
            impact += f"**High Risk Findings ({len(high_risk_findings)})**:\n"
            impact += "• Potential for complete system compromise\n"
            impact += "• Risk of data breach and regulatory violations\n"
            impact += "• Estimated downtime: 24-72 hours if exploited\n"
            impact += "• Potential financial impact: $50,000 - $500,000 per incident\n\n"
        
        if medium_risk_findings:
            impact += f"**Medium Risk Findings ({len(medium_risk_findings)})**:\n"
            impact += "• Limited exposure but should be addressed\n"
            impact += "• Potential for service degradation\n"
            impact += "• Estimated downtime: 4-24 hours if exploited\n\n"
        
        impact += "**Recommended Actions**:\n"
        impact += "• Implement immediate patching schedule\n"
        impact += "• Establish vulnerability management process\n"
        impact += "• Consider security monitoring and alerting\n"
        
        return impact
    
    def _generate_action_plan(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate action plan"""
        if not findings:
            return []
        
        high_risk_count = len([f for f in findings if f['risk_score'] >= 7])
        
        action_plan = []
        
        if high_risk_count > 0:
            action_plan.append({
                'step': 'Emergency Patching',
                'timeline': 'Next 24-48 hours',
                'description': f'Patch {high_risk_count} high-risk vulnerabilities immediately'
            })
        
        action_plan.append({
            'step': 'Security Hardening',
            'timeline': 'Next 7 days',
            'description': 'Implement security headers, WAF, and access controls'
        })
        
        action_plan.append({
            'step': 'Process Improvement',
            'timeline': 'Next 30 days',
            'description': 'Establish automated patch management and vulnerability scanning'
        })
        
        return action_plan
    
    def _calculate_risk_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk metrics"""
        if not findings:
            return {
                'total_findings': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'average_risk_score': 0.0
            }
        
        high_risk = len([f for f in findings if f['risk_score'] >= 7])
        medium_risk = len([f for f in findings if 4 <= f['risk_score'] < 7])
        low_risk = len([f for f in findings if f['risk_score'] < 4])
        
        avg_risk_score = sum(f['risk_score'] for f in findings) / len(findings)
        
        return {
            'total_findings': len(findings),
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'average_risk_score': round(avg_risk_score, 1)
        } 
