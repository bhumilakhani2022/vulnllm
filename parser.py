import xml.etree.ElementTree as ET
import re
import json
from typing import Dict, List, Any, Optional

class NmapParser:
    """Parser for Nmap scan results in XML and plain text formats"""
    
    def __init__(self):
        self.service_patterns = {
            'ssh': r'OpenSSH\s+(\d+\.\d+[a-z]?\d*)',
            'http': r'Apache\s+httpd\s+(\d+\.\d+\.\d+)',
            'https': r'Apache\s+httpd\s+(\d+\.\d+\.\d+)',
            'ftp': r'vsftpd\s+(\d+\.\d+\.\d+)',
            'smtp': r'Postfix\s+(\d+\.\d+\.\d+)',
            'dns': r'BIND\s+(\d+\.\d+\.\d+)',
            'mysql': r'MySQL\s+(\d+\.\d+\.\d+)',
            'postgresql': r'PostgreSQL\s+(\d+\.\d+\.\d+)',
            'redis': r'Redis\s+(\d+\.\d+\.\d+)',
            'mongodb': r'MongoDB\s+(\d+\.\d+\.\d+)',
            'nginx': r'nginx\s+(\d+\.\d+\.\d+)',
            'iis': r'IIS\s+(\d+\.\d+)',
            'tomcat': r'Apache\s+Tomcat\s+(\d+\.\d+\.\d+)',
            'jboss': r'JBoss\s+(\d+\.\d+\.\d+)',
            'weblogic': r'WebLogic\s+(\d+\.\d+\.\d+)',
            'websphere': r'WebSphere\s+(\d+\.\d+\.\d+)',
        }
    
    def parse(self, nmap_data: str) -> Dict[str, Any]:
        """
        Parse Nmap scan data in XML or plain text format
        
        Args:
            nmap_data: Nmap scan output as string
            
        Returns:
            Dictionary containing parsed scan results
        """
        # Try to parse as XML first
        if nmap_data.strip().startswith('<?xml') or nmap_data.strip().startswith('<nmaprun'):
            return self._parse_xml(nmap_data)
        else:
            return self._parse_plain_text(nmap_data)
    
    def _parse_xml(self, xml_data: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_data)
            
            results = {
                'scan_info': {},
                'services': [],
                'hosts': []
            }
            
            # Parse scan information
            scan_info = root.find('.//scaninfo')
            if scan_info is not None:
                results['scan_info'] = {
                    'protocol': scan_info.get('protocol', 'unknown'),
                    'scan_type': scan_info.get('type', 'unknown'),
                    'start_time': scan_info.get('start', 'unknown')
                }
            
            # Parse hosts and services
            for host in root.findall('.//host'):
                host_info = self._parse_host_element(host)
                results['hosts'].append(host_info)
                
                # Extract services from host
                for service in host_info.get('services', []):
                    results['services'].append(service)
            
            return results
            
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {str(e)}")
    
    def _parse_host_element(self, host_elem) -> Dict[str, Any]:
        """Parse individual host element from XML"""
        host_info = {
            'address': '',
            'hostname': '',
            'services': []
        }
        
        # Get address
        address_elem = host_elem.find('.//address')
        if address_elem is not None:
            host_info['address'] = address_elem.get('addr', '')
        
        # Get hostname
        hostname_elem = host_elem.find('.//hostname')
        if hostname_elem is not None:
            host_info['hostname'] = hostname_elem.get('name', '')
        
        # Get services
        for port_elem in host_elem.findall('.//port'):
            service_info = self._parse_port_element(port_elem)
            if service_info:
                host_info['services'].append(service_info)
        
        return host_info
    
    def _parse_port_element(self, port_elem) -> Optional[Dict[str, Any]]:
        """Parse individual port element from XML"""
        port_id = port_elem.get('portid', '')
        protocol = port_elem.get('protocol', 'tcp')
        state = port_elem.find('.//state')
        service_elem = port_elem.find('.//service')
        
        if state is None or state.get('state') != 'open':
            return None
        
        service_info = {
            'port': port_id,
            'protocol': protocol,
            'state': 'open',
            'service': 'unknown',
            'version': 'unknown'
        }
        
        if service_elem is not None:
            service_info['service'] = service_elem.get('name', 'unknown')
            service_info['version'] = service_elem.get('version', 'unknown')
            service_info['product'] = service_elem.get('product', '')
        
        return service_info
    
    def _parse_plain_text(self, text_data: str) -> Dict[str, Any]:
        """Parse Nmap plain text output"""
        lines = text_data.strip().split('\n')
        
        results = {
            'scan_info': {},
            'services': [],
            'hosts': []
        }
        
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and headers
            if not line or line.startswith('Starting') or line.startswith('Nmap scan report'):
                continue
            
            # Parse port/service lines
            if re.match(r'^\d+/\w+\s+\w+\s+\w+', line):
                service_info = self._parse_service_line(line)
                if service_info:
                    results['services'].append(service_info)
                    
                    # Add to current host if we have one
                    if current_host:
                        current_host['services'].append(service_info)
        
        # If we found services but no host info, create a default host
        if results['services'] and not results['hosts']:
            results['hosts'].append({
                'address': 'unknown',
                'hostname': 'unknown',
                'services': results['services']
            })
        
        return results
    
    def _parse_service_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single service line from plain text output"""
        # Pattern: PORT STATE SERVICE VERSION
        # Example: 22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
        pattern = r'^(\d+)/(\w+)\s+(\w+)\s+(\w+)(?:\s+(.+))?$'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        port, protocol, state, service, version_info = match.groups()
        
        if state != 'open':
            return None
        
        service_info = {
            'port': port,
            'protocol': protocol,
            'state': state,
            'service': service,
            'version': version_info.strip() if version_info else 'unknown'
        }
        
        # Try to extract version information
        if version_info:
            service_info.update(self._extract_version_info(service, version_info))
        
        return service_info
    
    def _extract_version_info(self, service: str, version_text: str) -> Dict[str, str]:
        """Extract detailed version information from version text"""
        version_info = {
            'product': '',
            'version': 'unknown',
            'extra': ''
        }
        
        # Try to match known service patterns
        for service_name, pattern in self.service_patterns.items():
            if service.lower() == service_name:
                match = re.search(pattern, version_text, re.IGNORECASE)
                if match:
                    version_info['version'] = match.group(1)
                    version_info['product'] = service_name
                    # Extract additional info
                    extra_parts = version_text.split(match.group(1))
                    if len(extra_parts) > 1:
                        version_info['extra'] = extra_parts[1].strip()
                    break
        
        # If no specific pattern matched, try to extract version numbers
        if version_info['version'] == 'unknown':
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)', version_text)
            if version_match:
                version_info['version'] = version_match.group(1)
                version_info['product'] = service
        
        return version_info
    
    def get_service_summary(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of detected services"""
        services = parsed_data.get('services', [])
        
        summary = {
            'total_services': len(services),
            'service_types': {},
            'open_ports': [],
            'version_info': {}
        }
        
        for service in services:
            service_name = service.get('service', 'unknown')
            port = service.get('port', 'unknown')
            version = service.get('version', 'unknown')
            
            # Count service types
            if service_name in summary['service_types']:
                summary['service_types'][service_name] += 1
            else:
                summary['service_types'][service_name] = 1
            
            # Track open ports
            summary['open_ports'].append(f"{port}/{service.get('protocol', 'tcp')}")
            
            # Track version information
            if version != 'unknown':
                key = f"{service_name}_{version}"
                if key in summary['version_info']:
                    summary['version_info'][key] += 1
                else:
                    summary['version_info'][key] = 1
        
        return summary
    
    def export_json(self, parsed_data: Dict[str, Any]) -> str:
        """Export parsed data as JSON"""
        return json.dumps(parsed_data, indent=2)
    
    def export_csv(self, parsed_data: Dict[str, Any]) -> str:
        """Export parsed data as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Port', 'Protocol', 'Service', 'Version', 'State'])
        
        # Write data
        for service in parsed_data.get('services', []):
            writer.writerow([
                service.get('port', ''),
                service.get('protocol', ''),
                service.get('service', ''),
                service.get('version', ''),
                service.get('state', '')
            ])
        
        return output.getvalue() 