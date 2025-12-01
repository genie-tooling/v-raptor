import unittest
from unittest.mock import patch, MagicMock
from src import worker
from src.database import Repository, Scan, ScanStatus
from datetime import datetime, timedelta

class TestWorker(unittest.TestCase):

    @patch('src.worker.di.get_worker_orchestrator')
    def test_run_deep_scan_job(self, mock_get_orchestrator):
        """Test that the run_deep_scan_job function calls the orchestrator correctly."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        worker.run_deep_scan_job('test_url', 1, auto_patch=True)

        mock_orchestrator.run_deep_scan.assert_called_once_with('test_url', 1, auto_patch=True, include_tests=False, branch=None)
        mock_orchestrator.db_session.close.assert_called_once()

    @patch('src.worker.di.get_worker_orchestrator')
    def test_run_quality_scan_job(self, mock_get_orchestrator):
        """Test that the run_quality_scan_job function calls the orchestrator correctly."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        worker.run_quality_scan_job(1)

        mock_orchestrator.run_quality_scan_for_repo.assert_called_once_with(1)
        mock_orchestrator.db_session.close.assert_called_once()

    @patch('src.worker.di.get_worker_orchestrator')
    def test_run_analysis_job(self, mock_get_orchestrator):
        """Test that the run_analysis_job function calls the orchestrator correctly."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        worker.run_analysis_job('test_url', 'test_hash', 1, auto_patch=True)

        mock_orchestrator.run_analysis_on_commit.assert_called_once_with('test_url', 'test_hash', 1, auto_patch=True, wait_for_completion=True)
        mock_orchestrator.db_session.close.assert_called_once()

    @patch('src.worker.di.get_worker_orchestrator')
    def test_check_for_new_commits_job(self, mock_get_orchestrator):
        """Test that the check_for_new_commits_job function correctly identifies new commits and enqueues new scans."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator
        
        repo = Repository(id=1, url='test_url', primary_branch='main', last_commit_hash='old_hash', periodic_scan_enabled=False)
        mock_orchestrator.db_session.query.return_value.all.return_value = [repo]
        mock_orchestrator.vcs_service.get_latest_commit_hash.return_value = 'new_hash'

        worker.check_for_new_commits_job()

        self.assertEqual(repo.last_commit_hash, 'new_hash')
        self.assertTrue(repo.needs_scan)
        mock_orchestrator.db_session.commit.assert_called()
        mock_orchestrator.db_session.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
