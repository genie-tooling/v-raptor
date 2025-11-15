import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile
import shutil
from git import Repo
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.orchestrator import Orchestrator
from src.database import Repository, Scan, Finding, Base

class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.db_session = Session()

        self.vcs_service_mock = MagicMock()
        self.google_web_search_mock = MagicMock()

        # Patch LLMService to prevent real calls
        with patch('src.orchestrator.LLMService') as self.llm_service_mock:
            self.orchestrator = Orchestrator(self.vcs_service_mock, self.db_session, self.google_web_search_mock)
            # since the llm_service is initialized inside orchestrator, we need to get the instance from there
            self.llm_instance = self.orchestrator.llm_service

    def tearDown(self):
        self.db_session.close()

    def test_validate_vulnerability_with_search_false_positive(self):
        """Test that validate_vulnerability_with_search correctly identifies a false positive."""
        self.google_web_search_mock.return_value = 'some search results'
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

if __name__ == '__main__':
    unittest.main()