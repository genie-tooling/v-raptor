import unittest
from unittest.mock import patch, MagicMock

from src import worker

class TestWorker(unittest.TestCase):

    @patch('src.worker.Connection')
    @patch('src.worker.Queue')
    @patch('src.worker.Worker')
    def test_start_worker(self, mock_worker_class, mock_queue_class, mock_connection_class):
        """Test that the start_worker function initializes the RQ Worker correctly."""
        mock_worker_instance = mock_worker_class.return_value
        worker.start_worker()

        # Check that a connection was made
        mock_connection_class.assert_called_once()

        # Check that the Worker was initialized
        mock_worker_class.assert_called_once()
        
        # Check that the worker's work method was called
        mock_worker_instance.work.assert_called_once_with()

    @patch('src.worker._get_orchestrator')
    def test_run_deep_scan_job(self, mock_get_orchestrator):
        """Test that the run_deep_scan_job function calls the orchestrator correctly."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        worker.run_deep_scan_job('test_url', 1, auto_patch=True)

        mock_orchestrator.run_deep_scan.assert_called_once_with('test_url', 1, auto_patch=True, include_tests=False)
        mock_orchestrator.db_session.close.assert_called_once()

    @patch('src.worker._get_orchestrator')
    def test_run_quality_scan_job(self, mock_get_orchestrator):
        """Test that the run_quality_scan_job function calls the orchestrator correctly."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        worker.run_quality_scan_job(1)

        mock_orchestrator.run_quality_scan_for_repo.assert_called_once_with(1)
        mock_orchestrator.db_session.close.assert_called_once()

        @patch('src.worker._get_orchestrator')

        def test_link_cves_to_findings_job(self, mock_get_orchestrator):

            """Test that the link_cves_to_findings_job function calls the orchestrator correctly."""

            mock_orchestrator = MagicMock()

            mock_get_orchestrator.return_value = mock_orchestrator

    

            worker.link_cves_to_findings_job(1, 1) # Pass a dummy scan_id

            mock_orchestrator.link_cves_to_findings.assert_called_once_with(1, 1)
        mock_orchestrator.db_session.close.assert_called_once()

    @patch('src.worker._get_orchestrator')
    def test_run_analysis_job(self, mock_get_orchestrator):
        """Test that the run_analysis_job function calls the orchestrator correctly."""
        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        worker.run_analysis_job('test_url', 'test_hash', 1, auto_patch=True)

        mock_orchestrator.run_analysis_on_commit.assert_called_once_with('test_url', 'test_hash', 1, auto_patch=True, wait_for_completion=True)
        mock_orchestrator.db_session.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
