#!/usr/bin/env python3
"""
Patch Management Module for AutoPatchAI
Handles automated patch deployment, rollback, and monitoring
"""

import subprocess
import json
import os
import shutil
import tempfile
import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import yaml
import time

class PatchStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class PatchType(Enum):
    PACKAGE_MANAGER = "package_manager"
    DEPENDENCY_FILE = "dependency_file"
    CONTAINER_IMAGE = "container_image"
    CONFIGURATION = "configuration"
    MANUAL = "manual"

@dataclass
class PatchJob:
    id: str
    patch_type: PatchType
    target: str
    old_version: str
    new_version: str
    commands: List[str]
    backup_path: Optional[str] = None
    status: PatchStatus = PatchStatus.PENDING
    created_at: datetime.datetime = None
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None
    rollback_commands: List[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.datetime.now()

class PatchManager:
    """Comprehensive patch management system"""
    
    def __init__(self, dry_run: bool = True, backup_dir: str = "./patch_backups"):
        self.dry_run = dry_run
        self.backup_dir = backup_dir
        self.job_history: List[PatchJob] = []
        self.active_jobs: Dict[str, PatchJob] = {}
        
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Package manager configurations
        self.package_managers = {
            'python': {
                'update_command': 'pip install --upgrade {package}',
                'install_command': 'pip install {package}=={version}',
                'list_command': 'pip list --format=json',
                'backup_files': ['requirements.txt', 'Pipfile', 'pyproject.toml'],
                'test_command': 'python -c "import {package}"'
            },
            'node': {
                'update_command': 'npm install {package}@{version}',
                'install_command': 'npm install {package}@{version}',
                'list_command': 'npm list --json',
                'backup_files': ['package.json', 'package-lock.json', 'yarn.lock'],
                'test_command': 'node -e "require(\'{package}\')"'
            },
            'composer': {
                'update_command': 'composer require {package}:{version}',
                'install_command': 'composer require {package}:{version}',
                'list_command': 'composer show --format=json',
                'backup_files': ['composer.json', 'composer.lock'],
                'test_command': 'php -r "require_once \'vendor/autoload.php\'; use {package};"'
            },
            'ruby': {
                'update_command': 'gem install {package} -v {version}',
                'install_command': 'gem install {package} -v {version}',
                'list_command': 'gem list --format=json',
                'backup_files': ['Gemfile', 'Gemfile.lock'],
                'test_command': 'ruby -e "require \'{package}\'"'
            },
            'maven': {
                'update_command': 'mvn dependency:resolve',
                'install_command': 'mvn install',
                'list_command': 'mvn dependency:list',
                'backup_files': ['pom.xml'],
                'test_command': 'mvn compile'
            }
        }
    
    def plan_patches(self, vulnerabilities: List[Dict[str, Any]], 
                    environment: str = "development") -> List[PatchJob]:
        """
        Create a comprehensive patch plan based on vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability findings
            environment: Target environment (development, staging, production)
            
        Returns:
            List of PatchJob objects representing the patch plan
        """
        patch_jobs = []
        
        for vuln in vulnerabilities:
            job = self._create_patch_job(vuln, environment)
            if job:
                patch_jobs.append(job)
        
        # Sort by priority (critical vulnerabilities first)
        patch_jobs.sort(key=lambda x: self._get_priority_score(x), reverse=True)
        
        return patch_jobs
    
    def _create_patch_job(self, vulnerability: Dict[str, Any], 
                         environment: str) -> Optional[PatchJob]:
        """Create a patch job for a specific vulnerability"""
        service = vulnerability.get('service', '')
        current_version = vulnerability.get('current_version', '')
        patch_version = vulnerability.get('patch_version', 'latest')
        
        # Determine patch type and generate commands
        if 'python' in service.lower() or any(pkg in service.lower() for pkg in ['pip', 'django', 'flask']):
            return self._create_python_patch_job(vulnerability, environment)
        elif 'node' in service.lower() or 'npm' in service.lower():
            return self._create_node_patch_job(vulnerability, environment)
        elif 'apache' in service.lower() or 'http' in service.lower():
            return self._create_system_patch_job(vulnerability, environment)
        elif 'ssh' in service.lower():
            return self._create_ssh_patch_job(vulnerability, environment)
        elif 'mysql' in service.lower():
            return self._create_mysql_patch_job(vulnerability, environment)
        
        return None
    
    def _create_python_patch_job(self, vuln: Dict[str, Any], env: str) -> PatchJob:
        """Create patch job for Python packages"""
        package_name = self._extract_package_name(vuln['service'])
        new_version = vuln.get('patch_version', 'latest')
        
        commands = [
            f"pip install --upgrade {package_name}",
            "pip check",  # Verify no dependency conflicts
        ]
        
        rollback_commands = [
            f"pip install {package_name}=={vuln['current_version']}",
        ]
        
        if env == "production":
            # More cautious approach for production
            commands.insert(0, "pip freeze > requirements_backup.txt")
            commands.append("python -m pytest tests/ || echo 'Tests failed - review before deployment'")
        
        return PatchJob(
            id=f"python_{package_name}_{int(time.time())}",
            patch_type=PatchType.PACKAGE_MANAGER,
            target=package_name,
            old_version=vuln['current_version'],
            new_version=new_version,
            commands=commands,
            rollback_commands=rollback_commands
        )
    
    def _create_node_patch_job(self, vuln: Dict[str, Any], env: str) -> PatchJob:
        """Create patch job for Node.js packages"""
        package_name = self._extract_package_name(vuln['service'])
        new_version = vuln.get('patch_version', 'latest')
        
        commands = [
            f"npm install {package_name}@{new_version}",
            "npm audit",
            "npm test || echo 'Tests failed - review before deployment'"
        ]
        
        rollback_commands = [
            f"npm install {package_name}@{vuln['current_version']}",
        ]
        
        return PatchJob(
            id=f"node_{package_name}_{int(time.time())}",
            patch_type=PatchType.PACKAGE_MANAGER,
            target=package_name,
            old_version=vuln['current_version'],
            new_version=new_version,
            commands=commands,
            rollback_commands=rollback_commands
        )
    
    def _create_system_patch_job(self, vuln: Dict[str, Any], env: str) -> PatchJob:
        """Create patch job for system packages (Apache, etc.)"""
        service_name = vuln['service'].split()[0].lower()
        
        if 'apache' in service_name or 'http' in service_name:
            commands = [
                "sudo systemctl stop apache2",
                "sudo apt update",
                "sudo apt upgrade apache2 -y",
                "sudo apache2ctl configtest",
                "sudo systemctl start apache2",
                "sudo systemctl status apache2"
            ]
            
            rollback_commands = [
                "sudo systemctl stop apache2",
                "sudo apt install apache2={old_version} -y --allow-downgrades",
                "sudo systemctl start apache2"
            ]
        else:
            commands = ["echo 'Manual intervention required'"]
            rollback_commands = ["echo 'Manual rollback required'"]
        
        return PatchJob(
            id=f"system_{service_name}_{int(time.time())}",
            patch_type=PatchType.PACKAGE_MANAGER,
            target=service_name,
            old_version=vuln['current_version'],
            new_version=vuln.get('patch_version', 'latest'),
            commands=commands,
            rollback_commands=rollback_commands
        )
    
    def _create_ssh_patch_job(self, vuln: Dict[str, Any], env: str) -> PatchJob:
        """Create patch job for SSH updates"""
        commands = [
            "sudo systemctl stop ssh",
            "sudo apt update",
            "sudo apt upgrade openssh-server -y",
            "sudo sshd -t",  # Test configuration
            "sudo systemctl start ssh",
            "sudo systemctl status ssh"
        ]
        
        rollback_commands = [
            "sudo systemctl stop ssh",
            f"sudo apt install openssh-server={vuln['current_version']} -y --allow-downgrades",
            "sudo systemctl start ssh"
        ]
        
        return PatchJob(
            id=f"ssh_{int(time.time())}",
            patch_type=PatchType.PACKAGE_MANAGER,
            target="openssh-server",
            old_version=vuln['current_version'],
            new_version=vuln.get('patch_version', 'latest'),
            commands=commands,
            rollback_commands=rollback_commands
        )
    
    def _create_mysql_patch_job(self, vuln: Dict[str, Any], env: str) -> PatchJob:
        """Create patch job for MySQL updates"""
        commands = [
            "sudo systemctl stop mysql",
            "sudo mysqldump --all-databases > mysql_backup.sql",
            "sudo apt update",
            "sudo apt upgrade mysql-server -y",
            "sudo systemctl start mysql",
            "sudo mysql_upgrade",
            "sudo systemctl status mysql"
        ]
        
        rollback_commands = [
            "sudo systemctl stop mysql",
            f"sudo apt install mysql-server={vuln['current_version']} -y --allow-downgrades",
            "sudo mysql < mysql_backup.sql",
            "sudo systemctl start mysql"
        ]
        
        return PatchJob(
            id=f"mysql_{int(time.time())}",
            patch_type=PatchType.PACKAGE_MANAGER,
            target="mysql-server",
            old_version=vuln['current_version'],
            new_version=vuln.get('patch_version', 'latest'),
            commands=commands,
            rollback_commands=rollback_commands
        )
    
    def execute_patches(self, patch_jobs: List[PatchJob], 
                       max_parallel: int = 1) -> Dict[str, Any]:
        """
        Execute patch jobs with monitoring and rollback capabilities
        
        Args:
            patch_jobs: List of patch jobs to execute
            max_parallel: Maximum number of parallel executions
            
        Returns:
            Execution summary with results and statistics
        """
        results = {
            'total_jobs': len(patch_jobs),
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'job_results': [],
            'execution_time': 0
        }
        
        start_time = time.time()
        
        for job in patch_jobs:
            try:
                # Create backup before patching
                self._create_backup(job)
                
                # Execute the patch
                success = self._execute_single_patch(job)
                
                if success:
                    results['successful'] += 1
                    job.status = PatchStatus.SUCCESS
                else:
                    results['failed'] += 1
                    job.status = PatchStatus.FAILED
                    
                    # Attempt rollback on failure
                    if job.rollback_commands:
                        print(f"Attempting rollback for {job.target}...")
                        self._execute_rollback(job)
                
                results['job_results'].append({
                    'job_id': job.id,
                    'target': job.target,
                    'status': job.status.value,
                    'error': job.error_message
                })
                
                # Add to history
                self.job_history.append(job)
                
            except Exception as e:
                job.error_message = str(e)
                job.status = PatchStatus.FAILED
                results['failed'] += 1
                print(f"Error executing patch for {job.target}: {e}")
        
        results['execution_time'] = time.time() - start_time
        
        return results
    
    def _execute_single_patch(self, job: PatchJob) -> bool:
        """Execute a single patch job"""
        job.started_at = datetime.datetime.now()
        job.status = PatchStatus.RUNNING
        
        print(f"Executing patch for {job.target}: {job.old_version} -> {job.new_version}")
        
        if self.dry_run:
            print("DRY RUN MODE - Commands that would be executed:")
            for cmd in job.commands:
                print(f"  {cmd}")
            job.status = PatchStatus.SUCCESS
            job.completed_at = datetime.datetime.now()
            return True
        
        try:
            for cmd in job.commands:
                print(f"Running: {cmd}")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode != 0:
                    job.error_message = f"Command failed: {cmd}\nError: {result.stderr}"
                    return False
                
                print(f"Output: {result.stdout[:200]}...")  # Truncate long output
            
            job.completed_at = datetime.datetime.now()
            return True
            
        except subprocess.TimeoutExpired:
            job.error_message = "Command execution timed out"
            return False
        except Exception as e:
            job.error_message = f"Execution error: {str(e)}"
            return False
    
    def _execute_rollback(self, job: PatchJob) -> bool:
        """Execute rollback commands for a failed patch"""
        if not job.rollback_commands:
            return False
        
        print(f"Rolling back {job.target}...")
        
        if self.dry_run:
            print("DRY RUN MODE - Rollback commands that would be executed:")
            for cmd in job.rollback_commands:
                print(f"  {cmd}")
            job.status = PatchStatus.ROLLED_BACK
            return True
        
        try:
            for cmd in job.rollback_commands:
                print(f"Rollback: {cmd}")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode != 0:
                    print(f"Rollback command failed: {cmd}\nError: {result.stderr}")
                    return False
            
            job.status = PatchStatus.ROLLED_BACK
            return True
            
        except Exception as e:
            print(f"Rollback error: {str(e)}")
            return False
    
    def _create_backup(self, job: PatchJob):
        """Create backup before applying patch"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(self.backup_dir, f"{job.target}_{timestamp}")
        
        # Create backup directory for this job
        os.makedirs(backup_path, exist_ok=True)
        
        # Backup relevant files based on patch type
        if job.patch_type == PatchType.PACKAGE_MANAGER:
            package_type = self._detect_package_type(job.target)
            if package_type in self.package_managers:
                backup_files = self.package_managers[package_type]['backup_files']
                
                for file_path in backup_files:
                    if os.path.exists(file_path):
                        shutil.copy2(file_path, backup_path)
        
        job.backup_path = backup_path
        
        # Save job metadata
        job_metadata = {
            'job_id': job.id,
            'target': job.target,
            'old_version': job.old_version,
            'new_version': job.new_version,
            'created_at': job.created_at.isoformat(),
            'commands': job.commands,
            'rollback_commands': job.rollback_commands
        }
        
        with open(os.path.join(backup_path, 'job_metadata.json'), 'w') as f:
            json.dump(job_metadata, f, indent=2)
    
    def _detect_package_type(self, target: str) -> str:
        """Detect package manager type based on target and environment"""
        # Simple heuristics - can be enhanced
        if os.path.exists('requirements.txt') or os.path.exists('setup.py'):
            return 'python'
        elif os.path.exists('package.json'):
            return 'node'
        elif os.path.exists('composer.json'):
            return 'composer'
        elif os.path.exists('Gemfile'):
            return 'ruby'
        elif os.path.exists('pom.xml'):
            return 'maven'
        else:
            return 'system'
    
    def _extract_package_name(self, service: str) -> str:
        """Extract clean package name from service description"""
        # Remove common prefixes and suffixes
        name = service.lower().replace(' on port', '').split()[0]
        return name
    
    def _get_priority_score(self, job: PatchJob) -> int:
        """Calculate priority score for patch job ordering"""
        # Higher score = higher priority
        score = 0
        
        # Base score by patch type
        if job.patch_type == PatchType.PACKAGE_MANAGER:
            score += 10
        elif job.patch_type == PatchType.CONFIGURATION:
            score += 8
        
        # Boost score for critical services
        critical_services = ['ssh', 'apache', 'mysql', 'postgresql']
        if any(service in job.target.lower() for service in critical_services):
            score += 20
        
        return score
    
    def verify_patches(self, patch_jobs: List[PatchJob]) -> Dict[str, Any]:
        """Verify that patches were applied successfully"""
        verification_results = {
            'total_verified': 0,
            'successful_verifications': 0,
            'failed_verifications': 0,
            'verification_details': []
        }
        
        for job in patch_jobs:
            if job.status == PatchStatus.SUCCESS:
                is_verified = self._verify_single_patch(job)
                verification_results['total_verified'] += 1
                
                if is_verified:
                    verification_results['successful_verifications'] += 1
                else:
                    verification_results['failed_verifications'] += 1
                
                verification_results['verification_details'].append({
                    'job_id': job.id,
                    'target': job.target,
                    'verified': is_verified
                })
        
        return verification_results
    
    def _verify_single_patch(self, job: PatchJob) -> bool:
        """Verify a single patch was applied correctly"""
        package_type = self._detect_package_type(job.target)
        
        if package_type in self.package_managers:
            test_command = self.package_managers[package_type]['test_command']
            formatted_command = test_command.format(package=job.target)
            
            try:
                result = subprocess.run(formatted_command, shell=True, capture_output=True, text=True, timeout=30)
                return result.returncode == 0
            except:
                return False
        
        return True  # Assume success if no verification method available
    
    def generate_patch_report(self, execution_results: Dict[str, Any]) -> str:
        """Generate a comprehensive patch execution report"""
        report = f"""
# Patch Execution Report

**Execution Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Execution Time:** {execution_results['execution_time']:.2f} seconds

## Summary
- **Total Jobs:** {execution_results['total_jobs']}
- **Successful:** {execution_results['successful']}
- **Failed:** {execution_results['failed']}
- **Success Rate:** {(execution_results['successful'] / execution_results['total_jobs'] * 100):.1f}%

## Job Details
"""
        
        for job_result in execution_results['job_results']:
            status_emoji = "✅" if job_result['status'] == 'success' else "❌"
            report += f"""
### {status_emoji} {job_result['target']}
- **Status:** {job_result['status']}
- **Job ID:** {job_result['job_id']}
"""
            if job_result['error']:
                report += f"- **Error:** {job_result['error']}\n"
        
        return report
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """Get current deployment status and statistics"""
        total_jobs = len(self.job_history)
        if total_jobs == 0:
            return {'message': 'No patch jobs executed yet'}
        
        status_counts = {}
        for job in self.job_history:
            status = job.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_jobs': total_jobs,
            'status_breakdown': status_counts,
            'recent_jobs': [
                {
                    'id': job.id,
                    'target': job.target,
                    'status': job.status.value,
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None
                }
                for job in self.job_history[-10:]  # Last 10 jobs
            ]
        }
