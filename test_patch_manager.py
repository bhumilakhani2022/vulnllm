import unittest
from unittest.mock import patch, MagicMock
from patch_manager import PatchManager, PatchJob, PatchStatus, PatchType

class TestPatchManager(unittest.TestCase):

    def setUp(self):
        """Setup test dependencies and mock objects."""
        self.patch_manager = PatchManager(dry_run=True)

    @patch('patch_manager.subprocess.run')
    def test_execute_patch(self, mock_run):
        mock_run.return_value.returncode = 0
        vulnerability = {
            'service': 'python package',
            'current_version': '1.0.0',
            'patch_version': '1.0.1'
        }
        job = self.patch_manager._create_python_patch_job(vulnerability, "development")
        result = self.patch_manager._execute_single_patch(job)
        self.assertTrue(result)
        self.assertEqual(job.status, PatchStatus.SUCCESS)

    def test_execute_patch_dry_run(self):
        # Test dry run mode - should always succeed
        vulnerability = {
            'service': 'python package',
            'current_version': '1.0.0',
            'patch_version': '1.0.1'
        }
        job = self.patch_manager._create_python_patch_job(vulnerability, "development")
        result = self.patch_manager._execute_single_patch(job)
        self.assertTrue(result)
        self.assertEqual(job.status, PatchStatus.SUCCESS)
    
    @patch('patch_manager.subprocess.run')
    def test_execute_patch_real_failure(self, mock_run):
        # Test real execution mode with failure
        patch_manager = PatchManager(dry_run=False)
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Package not found"
        
        vulnerability = {
            'service': 'python package',
            'current_version': '1.0.0',
            'patch_version': '1.0.1'
        }
        job = patch_manager._create_python_patch_job(vulnerability, "development")
        result = patch_manager._execute_single_patch(job)
        self.assertFalse(result)
        self.assertEqual(job.status, PatchStatus.RUNNING)

    def test_plan_patches(self):
        vulnerabilities = [
            {
                'service': 'python package',
                'current_version': '1.0.0',
                'patch_version': '1.0.1'
            },
            {
                'service': 'node package',
                'current_version': '2.0.0',
                'patch_version': '2.1.0'
            }
        ]
        patch_jobs = self.patch_manager.plan_patches(vulnerabilities)
        self.assertEqual(len(patch_jobs), 2)
        self.assertEqual(patch_jobs[0].patch_type, PatchType.PACKAGE_MANAGER)

if __name__ == '__main__':
    unittest.main()
