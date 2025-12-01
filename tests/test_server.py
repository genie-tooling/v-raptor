import unittest
from unittest.mock import patch, MagicMock
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database import Base, Repository, Scan, Finding, QualityMetric
import json

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

# Import app after all mocks are set up
from src.server import app

class TestServer(unittest.TestCase):

    def setUp(self):
        # Set up an in-memory SQLite database
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

        # Patch get_session to return our in-memory session
        self.get_session_patcher = patch('src.server.get_session')
        self.mock_get_session = self.get_session_patcher.start()
        self.mock_get_session.return_value.return_value = self.session

        # Patch the RQ Queue to avoid connecting to Redis
        self.q_patcher = patch('src.server.q')
        self.mock_q = self.q_patcher.start()
        self.mock_q.enqueue.return_value.id = 'test_job_id' # Ensure job_id is a string

        # Patch Orchestrator to avoid real LLM calls and VCS operations
        self.orchestrator_patcher = patch('src.server.Orchestrator')
        self.mock_orchestrator_class = self.orchestrator_patcher.start()
        self.mock_orchestrator_instance = self.mock_orchestrator_class.return_value

        # Patch LLMService to avoid real LLM calls
        self.llm_service_patcher = patch('src.server.LLMService')
        self.mock_llm_service_class = self.llm_service_patcher.start()
        self.mock_llm_service_instance = self.mock_llm_service_class.return_value

        # Patch VCSService to avoid real git operations
        self.vcs_service_patcher = patch('src.server.VCSService')
        self.mock_vcs_service_class = self.vcs_service_patcher.start()
        self.mock_vcs_service_instance = self.mock_vcs_service_class.return_value

        self.app_instance = app

        # Configure app for testing
        self.app_instance.config['TESTING'] = True
        self.app_instance.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing forms
        
        self.app_context = self.app_instance.app_context()
        self.app_context.push()
        
        from flask import g
        g.db_session = self.session
        self.app = self.app_instance.test_client()


    def tearDown(self):
        self.session.close() # Close the session
        Base.metadata.drop_all(self.engine) # Drop all tables
        self.app_context.pop() # Pop the application context
        self.get_session_patcher.stop()
        self.q_patcher.stop()
        self.orchestrator_patcher.stop()
        self.llm_service_patcher.stop()
        self.vcs_service_patcher.stop()

    def test_index_route(self):
        """Test the index route."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_config_route(self):
        """Test the config route."""
        self.mock_llm_service_instance.get_available_models.return_value = ['model1', 'model2']
        response = self.app.get('/config')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'model1', response.data)
        self.assertIn(b'model2', response.data)

    def test_failed_jobs_route(self):
        """Test the failed_jobs route."""
        with patch('src.server.FailedJobRegistry') as mock_registry:
            mock_registry.return_value.get_job_ids.return_value = ['job1', 'job2']
            self.mock_q.fetch_job.side_effect = [
                MagicMock(id='job1', func_name='func1', args=(), kwargs={}, exc_info='error1'),
                MagicMock(id='job2', func_name='func2', args=(), kwargs={}, exc_info='error2')
            ]
            response = self.app.get('/failed_jobs')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'job1', response.data)
            self.assertIn(b'job2', response.data)

    def test_findings_route(self):
        """Test the findings route."""
        repo = Repository(name='test_repo', url='http://test.com')
        scan = Scan(repository=repo)
        finding = Finding(description='test finding', severity='HIGH', scan=scan)
        self.session.add_all([repo, scan, finding])
        self.session.commit()
        response = self.app.get('/findings')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'test finding', response.data)

    def test_reports_route(self):
        """Test the reports route."""
        repo = Repository(id=1, name='test_repo', url='http://test.com')
        scan = Scan(id=1, repository=repo)
        finding = Finding(id=1, description='test finding', severity='HIGH', scan=scan)
        quality_metric = QualityMetric(id=1, scan_id=scan.id, sloc=1000)
        self.session.add_all([repo, scan, finding, quality_metric])
        self.session.commit()
        response = self.app.get('/reports')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'test_repo', response.data)
        self.assertIn(b'test finding', response.data)
        self.assertIn(b'1000', response.data)


    def test_dashboard_route(self):
        """Test the dashboard route."""
        repo = Repository(name='test_repo', url='http://test.com')
        scan = Scan(repository=repo, languages=['Python'])
        finding = Finding(description='test finding', severity='HIGH', scan=scan)
        quality_metric = QualityMetric(scan_id=scan.id, sloc=1000, maintainability_index=80, code_coverage=90)
        self.session.add_all([repo, scan, finding, quality_metric])
        self.session.commit()
        
        # This is a bit complex to mock because of how the data is structured.
        # We will create mock objects that have the .name attribute
        class MockRepoMetric:
            def __init__(self, name, avg_maintainability, code_coverage):
                self.name = name
                self.avg_maintainability = avg_maintainability
                self.code_coverage = code_coverage
        
        self.mock_orchestrator_instance.get_dashboard_metrics.return_value = {
            'total_repos': 1,
            'total_scans': 1,
            'total_findings': 1
        }
        self.mock_orchestrator_instance.get_findings_by_severity.return_value.all.return_value = [('HIGH', 1)]
        self.mock_orchestrator_instance.get_findings_by_repo.return_value = [('test_repo', 1)]
        self.mock_orchestrator_instance.dashboard.get_average_quality_metrics_by_repo.return_value = [
            MockRepoMetric(name='test_repo', avg_maintainability=80, code_coverage=90)
        ]
        self.mock_orchestrator_instance.dashboard.get_languages_by_repo.return_value = {'test_repo': ['Python']}
        self.mock_orchestrator_instance.dashboard.get_findings_by_language_across_repos.return_value = {'Python': 1}
        self.mock_orchestrator_instance.dashboard.get_findings_by_language_per_repo.return_value = {'test_repo': {'Python': 1}}
        
        response = self.app.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'test_repo', response.data)


    def test_save_settings_route(self):
        """Test the save_settings route."""
        response = self.app.get('/config')
        self.assertEqual(response.status_code, 200)
        # Mock the open function to prevent actual file writing
        with patch('builtins.open', MagicMock()) as mock_open:
            data = {
                'scanner_llm_provider': 'gemini',
                'scanner_llama_cpp_model_path': '/path/to/scanner/model',
                'scanner_ollama_url': 'http://localhost:11434',
                'scanner_ollama_model': 'gemma3:latest',
                'scanner_gemini_model': 'gemini-1.5-flash-latest',
                'patcher_llm_provider': 'ollama',
                'patcher_llama_cpp_model_path': '/path/to/patcher/model',
                'patcher_ollama_url': 'http://localhost:11434',
                'patcher_ollama_model': 'gemma3:latest',
                'patcher_gemini_model': 'gemini-1.5-pro-latest',
                'gitleaks_path': 'gitleaks',
                'semgrep_path': 'semgrep',
                'bandit_path': 'bandit',
                'sast_global_exclusions': '.gitignore,*.md',
                'llm_timeout': '120',
                'database_url': 'sqlite:///test.db'
            }
            response = self.app.post('/save_settings', data=data)
            self.assertEqual(response.status_code, 302) # Redirect status code
            self.assertTrue(mock_open.call_count > 0) # Ensure open was called to write config

    @patch('src.server.di.get_orchestrator')
    @patch('src.server.di.get_vcs_service')
    def test_add_repo_route(self, mock_get_vcs_service, mock_get_orchestrator):
        """Test the add_repo route."""
        mock_vcs_service = MagicMock()
        mock_vcs_service.parse_and_validate_repo_url.return_value = ("https://github.com/test/repo.git", "main")
        mock_get_vcs_service.return_value = mock_vcs_service

        mock_orchestrator = MagicMock()
        mock_get_orchestrator.return_value = mock_orchestrator

        response = self.app.post('/add_repo', data={'repo_url': 'https://github.com/test/repo.git'})
        self.assertEqual(response.status_code, 302) # Should redirect
        repo = self.session.query(Repository).filter_by(url='https://github.com/test/repo.git').first()
        self.assertIsNotNone(repo)
        self.assertEqual(repo.name, 'repo')
        self.assertIsNone(repo.primary_branch)
        mock_orchestrator.setup_new_repository.assert_called_once()



    def test_remove_repo_route(self):
        """Test the remove_repo route."""
        repo = Repository(name='test_repo', url='https://github.com/test/repo.git', primary_branch='main')
        self.session.add(repo)
        self.session.commit()
        response = self.app.post(f'/remove_repo/{repo.id}')
        self.assertEqual(response.status_code, 302) # Redirect
        self.assertIsNone(self.session.get(Repository, repo.id))

    def test_repository_route(self):
        """Test the repository route."""
        repo = Repository(name='test_repo', url='https://github.com/test/repo.git', primary_branch='main')
        self.session.add(repo)
        self.session.commit()
        response = self.app.get(f'/repository/{repo.id}')
        self.assertEqual(response.status_code, 200)

    def test_run_scan_route(self):
        """Test the run_scan route."""
        repo = Repository(name='test_repo', url='https://github.com/test/repo.git', primary_branch='main')
        self.session.add(repo)
        self.session.commit()
        response = self.app.post(f'/run_scan/{repo.id}')
        self.assertEqual(response.status_code, 302) # Redirect
        scan = self.session.query(Scan).filter_by(repository_id=repo.id).first()
        self.mock_q.enqueue.assert_called_once_with('src.worker.run_deep_scan_job', repo.url, scan.id, auto_patch=False, include_tests=False, branch=None)

    def test_scan_new_commits_route(self):
        """Test the scan_new_commits route."""
        repo = Repository(name='test_repo', url='https://github.com/test/repo.git', primary_branch='main', last_commit_hash='old_hash', needs_scan=True)
        self.session.add(repo)
        self.session.commit()
        response = self.app.post(f'/scan_new_commits/{repo.id}')
        self.assertEqual(response.status_code, 302) # Redirect
        self.mock_q.enqueue.assert_called_once_with('src.worker.run_analysis_job', repo.url, repo.last_commit_hash, repo.id, auto_patch=False)
        self.assertFalse(repo.needs_scan) # needs_scan should be set to False

    def test_periodic_scan_config_route(self):
        """Test the periodic_scan_config route."""
        repo = Repository(name='test_repo', url='https://github.com/test/repo.git', primary_branch='main')
        self.session.add(repo)
        self.session.commit()
        data = {'periodic_scan_enabled': 'true', 'periodic_scan_interval': '3600'}
        response = self.app.post(f'/repository/{repo.id}/periodic_scan', data=data)
        self.assertEqual(response.status_code, 302) # Redirect
        self.assertTrue(repo.periodic_scan_enabled)
        self.assertEqual(repo.periodic_scan_interval, 3600)

    def test_api_scans_route(self):
        """Test the api_scans route."""
        repo = Repository(name='test_repo', url='https://github.com/test/repo.git', primary_branch='main')
        self.session.add(repo)
        self.session.commit()
        scan = Scan(repository_id=repo.id, scan_type='deep', status='running', status_message='Scanning...', job_id='test_job_id')
        self.session.add(scan)
        self.session.commit()
        
        self.mock_q.fetch_job.return_value = MagicMock(id='test_job_id')

        response = self.app.get('/api/scans')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], scan.id)
        self.assertEqual(data[0]['status'], 'running')
        self.assertEqual(data[0]['status_message'], 'Scanning...')
        self.assertEqual(data[0]['job_id'], 'test_job_id')

if __name__ == '__main__':
    unittest.main()