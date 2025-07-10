import xml.etree.ElementTree as ET
import re
import json
from typing import Dict, List, Any, Optional

class VulnerabilityParser:
    """Enhanced parser for vulnerability scans and dependency files"""
    
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
    
    def parse(self, data: str, file_type: str) -> Dict[str, Any]:
        """
        Parse various vulnerability and dependency files
        
        Args:
            data: Input data as a string
            file_type: Type of file ('nmap_xml', 'nmap_text', 'requirements', 'package_json', 
                      'composer_json', 'gemfile', 'pom_xml', 'sarif', 'dockerfile')
            
        Returns:
            Dictionary containing parsed results
        """
        if file_type == 'nmap_xml':
            return self._parse_xml(data)
        elif file_type == 'nmap_text':
            return self._parse_plain_text(data)
        elif file_type == 'requirements':
            return self._parse_requirements(data)
        elif file_type == 'package_json':
            return self._parse_package_json(data)
        elif file_type == 'composer_json':
            return self._parse_composer_json(data)
        elif file_type == 'gemfile':
            return self._parse_gemfile(data)
        elif file_type == 'pom_xml':
            return self._parse_pom_xml(data)
        elif file_type == 'sarif':
            return self._parse_sarif(data)
        elif file_type == 'dockerfile':
            return self._parse_dockerfile(data)
        elif file_type == 'yarn_lock':
            return self._parse_yarn_lock(data)
        elif file_type == 'pipfile':
            return self._parse_pipfile(data)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
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
        pattern = r'^(\d+)/(\w+)\s+(\w+)\s+(\w+)(?:\s+(.+))?'
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

    def _parse_requirements(self, data: str) -> Dict[str, Any]:
        """Parse requirements.txt file"""
        dependencies = []
        for line in data.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Handle various operators
                operators = ['==', '>=', '<=', '>', '<', '~=', '!=']
                for op in operators:
                    if op in line:
                        parts = line.split(op)
                        dependencies.append({
                            'name': parts[0].strip(), 
                            'version': parts[1].strip() if len(parts) > 1 else 'latest',
                            'type': 'python'
                        })
                        break
                else:
                    # No operator found, package name only
                    dependencies.append({
                        'name': line.strip(),
                        'version': 'latest',
                        'type': 'python'
                    })
        return {'dependencies': dependencies}

    def _parse_package_json(self, data: str) -> Dict[str, Any]:
        """Parse package.json file"""
        dependencies = []
        try:
            package_data = json.loads(data)
            for name, version in package_data.get('dependencies', {}).items():
                dependencies.append({
                    'name': name, 
                    'version': version.replace('^', '').replace('~', ''),
                    'type': 'npm'
                })
            for name, version in package_data.get('devDependencies', {}).items():
                dependencies.append({
                    'name': name, 
                    'version': version.replace('^', '').replace('~', ''),
                    'type': 'npm-dev'
                })
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid package.json format: {e}")
        return {'dependencies': dependencies}

    def _parse_composer_json(self, data: str) -> Dict[str, Any]:
        """Parse composer.json file"""
        dependencies = []
        try:
            composer_data = json.loads(data)
            for name, version in composer_data.get('require', {}).items():
                dependencies.append({
                    'name': name, 
                    'version': version.replace('^', '').replace('~', ''),
                    'type': 'php'
                })
            for name, version in composer_data.get('require-dev', {}).items():
                dependencies.append({
                    'name': name, 
                    'version': version.replace('^', '').replace('~', ''),
                    'type': 'php-dev'
                })
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid composer.json format: {e}")
        return {'dependencies': dependencies}

    def _parse_gemfile(self, data: str) -> Dict[str, Any]:
        """Parse Gemfile"""
        dependencies = []
        for line in data.strip().split('\n'):
            line = line.strip()
            if line.startswith('gem'):
                # Extract gem name and version
                matches = re.findall(r"'([^']+)'|\"([^\"]+)\"|(\S+)", line)
                gem_parts = [match[0] or match[1] or match[2] for match in matches if any(match)]
                if len(gem_parts) >= 2:  # gem name found
                    name = gem_parts[1]  # Skip 'gem' keyword
                    version = gem_parts[2] if len(gem_parts) > 2 else 'latest'
                    dependencies.append({
                        'name': name,
                        'version': version,
                        'type': 'ruby'
                    })
        return {'dependencies': dependencies}

    def _parse_pom_xml(self, data: str) -> Dict[str, Any]:
        """Parse POM XML file"""
        dependencies = []
        try:
            root = ET.fromstring(data)
            namespaces = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
            
            for dependency in root.findall('.//mvn:dependency', namespaces):
                group_id_elem = dependency.find('mvn:groupId', namespaces)
                artifact_id_elem = dependency.find('mvn:artifactId', namespaces)
                version_elem = dependency.find('mvn:version', namespaces)
                
                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text
                    version = version_elem.text if version_elem is not None else 'latest'
                    
                    dependencies.append({
                        'name': f'{group_id}:{artifact_id}',
                        'version': version,
                        'type': 'maven'
                    })
        except ET.ParseError as e:
            raise ValueError(f"Invalid POM XML format: {str(e)}")
        return {'dependencies': dependencies}

    def _parse_sarif(self, data: str) -> Dict[str, Any]:
        """Parse SARIF file"""
        vulnerabilities = []
        try:
            sarif_data = json.loads(data)
            for run in sarif_data.get('runs', []):
                tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Unknown')
                
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'Unknown')
                    message = result.get('message', {}).get('text', '')
                    level = result.get('level', 'warning')
                    
                    # Extract location information
                    locations = []
                    for location in result.get('locations', []):
                        physical_location = location.get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        locations.append({
                            'file': artifact_location.get('uri', ''),
                            'line': region.get('startLine', 0),
                            'column': region.get('startColumn', 0)
                        })
                    
                    vulnerabilities.append({
                        'tool': tool_name,
                        'rule_id': rule_id,
                        'message': message,
                        'level': level,
                        'locations': locations
                    })
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SARIF format: {e}")
        return {'vulnerabilities': vulnerabilities}

    def _parse_dockerfile(self, data: str) -> Dict[str, Any]:
        """Parse Dockerfile for base images and commands"""
        dockerfile_info = {
            'base_images': [],
            'packages': [],
            'commands': []
        }
        
        for line in data.strip().split('\n'):
            line = line.strip()
            if line.upper().startswith('FROM'):
                # Extract base image
                parts = line.split()
                if len(parts) > 1:
                    dockerfile_info['base_images'].append(parts[1])
            elif line.upper().startswith('RUN'):
                # Extract packages from apt, yum, apk commands
                if 'apt-get install' in line or 'apt install' in line:
                    packages = re.findall(r'(?:apt-get install|apt install)\s+(?:-y\s+)?(.+)', line)
                    if packages:
                        for pkg_line in packages[0].split():
                            if pkg_line not in ['-y', '&&', '\\']:
                                dockerfile_info['packages'].append({
                                    'name': pkg_line,
                                    'type': 'debian'
                                })
                elif 'yum install' in line:
                    packages = re.findall(r'yum install\s+(?:-y\s+)?(.+)', line)
                    if packages:
                        for pkg_line in packages[0].split():
                            if pkg_line not in ['-y', '&&', '\\']:
                                dockerfile_info['packages'].append({
                                    'name': pkg_line,
                                    'type': 'rpm'
                                })
                elif 'apk add' in line:
                    packages = re.findall(r'apk add\s+(.+)', line)
                    if packages:
                        for pkg_line in packages[0].split():
                            if pkg_line not in ['--no-cache', '&&', '\\']:
                                dockerfile_info['packages'].append({
                                    'name': pkg_line,
                                    'type': 'alpine'
                                })
                dockerfile_info['commands'].append(line)
            else:
                dockerfile_info['commands'].append(line)
        
        return dockerfile_info

    def _parse_yarn_lock(self, data: str) -> Dict[str, Any]:
        """Parse yarn.lock file (simplified)"""
        dependencies = []
        current_package = None
        
        for line in data.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if line.endswith(':'):
                    # Package declaration
                    package_name = line.split('@')[0].strip('"')
                    current_package = package_name
                elif line.startswith('version') and current_package:
                    version = line.split('"')[1] if '"' in line else 'unknown'
                    dependencies.append({
                        'name': current_package,
                        'version': version,
                        'type': 'yarn'
                    })
                    current_package = None
        
        return {'dependencies': dependencies}

    def _parse_pipfile(self, data: str) -> Dict[str, Any]:
        """Parse Pipfile"""
        dependencies = []
        try:
            # Try to parse as TOML-like format
            current_section = None
            for line in data.strip().split('\n'):
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                elif '=' in line and current_section in ['packages', 'dev-packages']:
                    parts = line.split('=', 1)
                    name = parts[0].strip()
                    version = parts[1].strip().strip('"\'')
                    dep_type = 'pip-dev' if current_section == 'dev-packages' else 'pip'
                    dependencies.append({
                        'name': name,
                        'version': version,
                        'type': dep_type
                    })
        except Exception as e:
            raise ValueError(f"Invalid Pipfile format: {e}")
        
        return {'dependencies': dependencies}

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
        
        # Handle different data types
        if 'services' in parsed_data:
            # Network services CSV
            writer.writerow(['Port', 'Protocol', 'Service', 'Version', 'State'])
            for service in parsed_data.get('services', []):
                writer.writerow([
                    service.get('port', ''),
                    service.get('protocol', ''),
                    service.get('service', ''),
                    service.get('version', ''),
                    service.get('state', '')
                ])
        elif 'dependencies' in parsed_data:
            # Dependencies CSV
            writer.writerow(['Name', 'Version', 'Type'])
            for dep in parsed_data.get('dependencies', []):
                writer.writerow([
                    dep.get('name', ''),
                    dep.get('version', ''),
                    dep.get('type', '')
                ])
        elif 'vulnerabilities' in parsed_data:
            # Vulnerabilities CSV
            writer.writerow(['Tool', 'Rule ID', 'Level', 'Message', 'File', 'Line'])
            for vuln in parsed_data.get('vulnerabilities', []):
                for location in vuln.get('locations', [{}]):
                    writer.writerow([
                        vuln.get('tool', ''),
                        vuln.get('rule_id', ''),
                        vuln.get('level', ''),
                        vuln.get('message', ''),
                        location.get('file', ''),
                        location.get('line', '')
                    ])
        
        return output.getvalue()

# For backward compatibility
NmapParser = VulnerabilityParser
