import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile
import shutil
import json
from git import Repo
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.orchestrator import Orchestrator
from src.database import Repository, Scan, Finding, Base, ScanStatus

class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.db_session = Session()

        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()

        # Patch LLMService and SandboxService to prevent real calls/connections
        with patch('src.orchestrator.LLMService') as self.llm_service_mock, \
             patch('src.orchestrator.SandboxService') as self.sandbox_service_mock:
            self.orchestrator = Orchestrator(self.vcs_service_mock, self.db_session, self.google_web_search_mock)
            # since the llm_service is initialized inside orchestrator, we need to get the instance from there
            self.llm_instance = self.orchestrator.llm_service

    def tearDown(self):
        self.db_session.close()

    def test_validate_vulnerability_with_search_false_positive(self):
        """Test that validate_vulnerability_with_search correctly identifies a false positive."""
        self.google_web_search_mock.return_value = 'some search results'
        # Mocking the vulnerability processor inside orchestrator
        with patch.object(self.orchestrator.vulnerability_processor.llm_service, 'validate_vulnerability') as mock_validate_vulnerability:
            mock_validate_vulnerability.return_value = '{"false_positive": true}'
            vulnerability = {
                'description': 'some vulnerability',
                'code_snippet': 'some code'
            }
            result = self.orchestrator.vulnerability_processor.validate_vulnerability_with_search(vulnerability)
            self.assertFalse(result)

    def test_validate_vulnerability_with_search_not_false_positive(self):
        """Test that validate_vulnerability_with_search correctly identifies a non-false positive."""
        self.google_web_search_mock.return_value = 'some search results'
        with patch.object(self.orchestrator.vulnerability_processor.llm_service, 'validate_vulnerability') as mock_validate_vulnerability:
            mock_validate_vulnerability.return_value = '{"false_positive": false}'
            vulnerability = {
                'description': 'some vulnerability',
                'code_snippet': 'some code'
            }
            result = self.orchestrator.vulnerability_processor.validate_vulnerability_with_search(vulnerability)
            self.assertTrue(result)

class TestOrchestratorLocalScan(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.repo = Repo.init(self.test_dir)
        with open(os.path.join(self.test_dir, 'test.py'), 'w') as f:
            f.write('print("hello world")')
        self.repo.index.add(['test.py'])
        self.repo.index.commit('initial commit')

        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.db_session = Session()

        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()
        self.llm_instance = MagicMock() # Our mock LLMService instance
        
        # Mock SandboxService here as well to prevent docker.from_env() call
        with patch('src.orchestrator.SandboxService'):
            self.orchestrator = Orchestrator(self.vcs_service_mock, self.db_session, self.google_web_search_mock, llm_service=self.llm_instance)

        # We need to mock all the scan runners
        patcher_sast = patch.object(self.orchestrator.scanner, 'run_sast_scan')
        patcher_cve = patch.object(self.orchestrator.scanner, 'run_intelligent_cve_scan')
        patcher_source = patch.object(self.orchestrator.scanner, 'run_source_code_scan')
        patcher_secret = patch.object(self.orchestrator.scanner, 'run_secret_scan')
        patcher_dep = patch.object(self.orchestrator.scanner, 'run_dependency_scan')
        patcher_config = patch.object(self.orchestrator.scanner, 'run_config_scan')
        patcher_quality = patch.object(self.orchestrator.scanner, 'run_quality_scan')

        self.mock_sast = patcher_sast.start()
        self.mock_cve = patcher_cve.start()
        self.mock_source = patcher_source.start()
        self.mock_secret = patcher_secret.start()
        self.mock_dep = patcher_dep.start()
        self.mock_config = patcher_config.start()
        self.mock_quality = patcher_quality.start()

        self.addCleanup(patch.stopall)

    def tearDown(self):
        shutil.rmtree(self.test_dir)
        self.db_session.close()

    def test_run_local_scan(self):
        """Test that run_local_scan correctly orchestrates a local scan."""
        # Since we made primary_branch nullable, we need to make sure this works.
        repo = Repository(name=os.path.basename(self.test_dir), url=self.test_dir)
        self.db_session.add(repo)
        self.db_session.commit()
        
        self.orchestrator.run_local_scan(self.test_dir)

        # Verify a repository and scan were created
        repo = self.db_session.query(Repository).filter_by(url=self.test_dir).first()
        self.assertIsNotNone(repo)
        self.assertEqual(repo.name, os.path.basename(self.test_dir))

        scan = self.db_session.query(Scan).filter_by(repository_id=repo.id).first()
        self.assertIsNotNone(scan)
        self.assertEqual(scan.scan_type, 'deep')

        # Verify that all the individual scan methods were called
        self.mock_sast.assert_called_once()
        self.mock_cve.assert_called_once()
        self.mock_source.assert_called_once()
        self.mock_secret.assert_called_once()
        self.mock_dep.assert_called_once()
        self.mock_config.assert_called_once()
        self.mock_quality.assert_called_once()

class TestFindingModel(unittest.TestCase):
    def test_to_dict(self):
        """Test that the Finding.to_dict method returns the correct dictionary."""
        finding = Finding(
            id=1,
            scan_id=1,
            file_path='test.py',
            line_number=10,
            code_snippet='foo = bar',
            description='test finding',
            severity='High',
            confidence_score=0.9,
            status='new',
            cve_id='CVE-2021-1234'
        )
        expected_dict = {
            'id': 1,
            'scan_id': 1,
            'file_path': 'test.py',
            'line_number': 10,
            'code_snippet': 'foo = bar',
            'description': 'test finding',
            'severity': 'High',
            'confidence_score': 0.9,
            'status': 'new',
            'cve_id': 'CVE-2021-1234',
        }
        self.assertEqual(finding.to_dict(), expected_dict)


class TestRunAnalysisOnCommit(unittest.TestCase):
    def setUp(self):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        self.db_session = sessionmaker(bind=engine)()
        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()
        self.llm_service_mock = MagicMock()
        self.sandbox_service_mock = MagicMock()

        # We patch the VulnerabilityProcessor directly on the orchestrator instance
        with patch('src.orchestrator.VulnerabilityProcessor') as vp_mock:
            self.orchestrator = Orchestrator(
                self.vcs_service_mock,
                self.db_session,
                self.google_web_search_mock,
                llm_service=self.llm_service_mock
            )
            # We need to mock the `process_vulnerability` method on the *instance*
            # of the mocked VulnerabilityProcessor that the orchestrator creates.
            self.vulnerability_processor_instance = self.orchestrator.vulnerability_processor
            self.vulnerability_processor_instance.process_vulnerability = MagicMock()


    def tearDown(self):
        self.db_session.close()

    def test_run_analysis_on_commit_success(self):
        """Test a successful run of analysis on a commit."""
        repo_url = 'https://github.com/example/repo'
        commit_hash = 'abcdef123456'
        repo_id = 1
        
        self.db_session.add(Repository(id=repo_id, url=repo_url, name='repo'))
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'
        self.vcs_service_mock.get_commit_diff.return_value = 'some diff'
        self.llm_service_mock.analyze_diff_with_tools.return_value = json.dumps({
            "vulnerabilities": [{"description": "A vulnerability"}]
        })

        scan = self.orchestrator.run_analysis_on_commit(repo_url, commit_hash, repo_id, wait_for_completion=True)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.vcs_service_mock.clone_repo.assert_called_once_with(repo_url)
        self.vcs_service_mock.get_commit_diff.assert_called_once_with('/tmp/repo', commit_hash)
        self.llm_service_mock.analyze_diff_with_tools.assert_called_once_with('some diff')
        self.vulnerability_processor_instance.process_vulnerability.assert_called_once()
        
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)

    def test_run_analysis_on_commit_no_diff(self):
        """Test a run of analysis on a commit with no diff."""
        repo_url = 'https://github.com/example/repo'
        commit_hash = 'abcdef123456'
        repo_id = 1
        
        self.db_session.add(Repository(id=repo_id, url=repo_url, name='repo'))
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'
        self.vcs_service_mock.get_commit_diff.return_value = ''

        scan = self.orchestrator.run_analysis_on_commit(repo_url, commit_hash, repo_id, wait_for_completion=True)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.vcs_service_mock.clone_repo.assert_called_once_with(repo_url)
        self.vcs_service_mock.get_commit_diff.assert_called_once_with('/tmp/repo', commit_hash)
        self.vulnerability_processor_instance.process_vulnerability.assert_not_called()
        
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)

    def test_run_analysis_on_commit_no_vulnerabilities(self):
        """Test a run of analysis on a commit with no vulnerabilities found."""
        repo_url = 'https://github.com/example/repo'
        commit_hash = 'abcdef123456'
        repo_id = 1
        
        self.db_session.add(Repository(id=repo_id, url=repo_url, name='repo'))
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'
        self.vcs_service_mock.get_commit_diff.return_value = 'some diff'
        self.llm_service_mock.analyze_diff_with_tools.return_value = json.dumps({
            "vulnerabilities": []
        })

        scan = self.orchestrator.run_analysis_on_commit(repo_url, commit_hash, repo_id, wait_for_completion=True)

        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.vcs_service_mock.clone_repo.assert_called_once_with(repo_url)
        self.vcs_service_mock.get_commit_diff.assert_called_once_with('/tmp/repo', commit_hash)
        self.llm_service_mock.analyze_diff_with_tools.assert_called_once_with('some diff')
        self.vulnerability_processor_instance.process_vulnerability.assert_not_called()
        
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)


class TestRunDeepScan(unittest.TestCase):
    def setUp(self):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        self.db_session = sessionmaker(bind=engine)()
        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()
        self.llm_service_mock = MagicMock()
        
        with patch('src.orchestrator.SandboxService'):
            self.orchestrator = Orchestrator(
                self.vcs_service_mock,
                self.db_session,
                self.google_web_search_mock,
                llm_service=self.llm_service_mock
            )

        # Mock all the scan runners on the scanner instance
        self.scanner_instance = self.orchestrator.scanner
        self.scanner_instance.run_sast_scan = MagicMock()
        self.scanner_instance.run_intelligent_cve_scan = MagicMock()
        self.scanner_instance.run_source_code_scan = MagicMock()
        self.scanner_instance.run_secret_scan = MagicMock()
        self.scanner_instance.run_dependency_scan = MagicMock()
        self.scanner_instance.run_config_scan = MagicMock()
        self.scanner_instance.run_quality_scan = MagicMock()
        # Mock language detection
        patcher = patch('src.orchestrator.detect_languages', return_value=['Python'])
        self.mock_detect_languages = patcher.start()
        self.addCleanup(patcher.stop)


    def tearDown(self):
        self.db_session.close()

    def test_run_deep_scan_success(self):
        """Test a successful run of a deep scan."""
        repo_url = 'https://github.com/example/repo'
        repo = Repository(url=repo_url, name='repo', primary_branch='main')
        self.db_session.add(repo)
        self.db_session.commit()
        
        scan = Scan(repository_id=repo.id, scan_type='deep', status='queued')
        self.db_session.add(scan)
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'

        self.orchestrator.run_deep_scan(repo_url, scan.id)

        self.scanner_instance.run_sast_scan.assert_called_once()
        self.scanner_instance.run_intelligent_cve_scan.assert_called_once()
        self.scanner_instance.run_source_code_scan.assert_called_once()
        self.scanner_instance.run_secret_scan.assert_called_once()
        self.scanner_instance.run_dependency_scan.assert_called_once()
        self.scanner_instance.run_config_scan.assert_called_once()
        self.scanner_instance.run_quality_scan.assert_called_once()

        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(db_scan.languages, ['Python'])


class TestRunQualityScanForRepo(unittest.TestCase):
    def setUp(self):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        self.db_session = sessionmaker(bind=engine)()
        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()
        self.llm_service_mock = MagicMock()
        
        with patch('src.orchestrator.SandboxService'):
            self.orchestrator = Orchestrator(
                self.vcs_service_mock,
                self.db_session,
                self.google_web_search_mock,
                llm_service=self.llm_service_mock
            )

        self.scanner_instance = self.orchestrator.scanner
        self.scanner_instance.run_quality_scan = MagicMock()

    def tearDown(self):
        self.db_session.close()

    def test_run_quality_scan_for_repo_success(self):
        """Test a successful run of a quality scan for a repo."""
        repo_url = 'https://github.com/example/repo'
        repo = Repository(url=repo_url, name='repo', primary_branch='main')
        self.db_session.add(repo)
        self.db_session.commit()
        
        scan = Scan(repository_id=repo.id, scan_type='quality', status='queued')
        self.db_session.add(scan)
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'

        self.orchestrator.run_quality_scan_for_repo(scan.id)

        self.scanner_instance.run_quality_scan.assert_called_once_with('/tmp/repo', scan)
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)

    def test_run_quality_scan_for_repo_failure(self):
        """Test a failed run of a quality scan for a repo."""
        repo_url = 'https://github.com/example/repo'
        repo = Repository(url=repo_url, name='repo', primary_branch='main')
        self.db_session.add(repo)
        self.db_session.commit()
        
        scan = Scan(repository_id=repo.id, scan_type='quality', status='queued')
        self.db_session.add(scan)
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'
        self.scanner_instance.run_quality_scan.side_effect = Exception("Quality scan failed")

        self.orchestrator.run_quality_scan_for_repo(scan.id)

        self.scanner_instance.run_quality_scan.assert_called_once_with('/tmp/repo', scan)
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.FAILED)
        self.assertIn("Quality scan failed", db_scan.status_message)


class TestRunTestScan(unittest.TestCase):
    def setUp(self):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        self.db_session = sessionmaker(bind=engine)()
        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()
        self.llm_service_mock = MagicMock()
        
        # We need to mock SandboxService's run_command_in_repo
        with patch('src.orchestrator.SandboxService') as self.sandbox_service_mock_class:
            self.orchestrator = Orchestrator(
                self.vcs_service_mock,
                self.db_session,
                self.google_web_search_mock,
                llm_service=self.llm_service_mock
            )
            # The orchestrator creates its own instance, so we mock the method on that instance
            self.sandbox_service_instance = self.orchestrator.sandbox_service
            self.sandbox_service_instance.run_command_in_repo = MagicMock(return_value="Test output")

    def tearDown(self):
        self.db_session.close()

    def test_run_test_scan_in_container(self):
        """Test running a test scan in a container."""
        repo = Repository(
            url='https://github.com/example/repo',
            name='repo',
            primary_branch='main',
            run_tests_in_container=True,
            test_container='test-image',
            test_command='pytest'
        )
        self.db_session.add(repo)
        self.db_session.commit()
        
        scan = Scan(repository_id=repo.id, languages=['Python'])
        self.db_session.add(scan)
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'
        
        self.orchestrator.run_test_scan(repo.id, scan.id)

        self.sandbox_service_instance.run_command_in_repo.assert_called_once()
        # More specific assertions could be added here about the command run
        
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(db_scan.test_output, 'Test output')

    @patch('subprocess.run')
    def test_run_test_scan_locally(self, mock_subprocess_run):
        """Test running a test scan locally."""
        mock_subprocess_run.return_value = MagicMock(stdout="Local test output", stderr="", text=True)
        repo = Repository(
            url='https://github.com/example/repo',
            name='repo',
            primary_branch='main',
            run_tests_in_container=False, # Explicitly run locally
            test_command='pytest'
        )
        self.db_session.add(repo)
        self.db_session.commit()
        
        scan = Scan(repository_id=repo.id, languages=['Python'])
        self.db_session.add(scan)
        self.db_session.commit()

        self.vcs_service_mock.clone_repo.return_value = '/tmp/repo'
        
        self.orchestrator.run_test_scan(repo.id, scan.id)

        mock_subprocess_run.assert_called_once()
        self.sandbox_service_instance.run_command_in_repo.assert_not_called()
        
        db_scan = self.db_session.query(Scan).get(scan.id)
        self.assertEqual(db_scan.status, ScanStatus.COMPLETED)
        self.assertIn('Local test output', db_scan.test_output)


if __name__ == '__main__':
    unittest.main()