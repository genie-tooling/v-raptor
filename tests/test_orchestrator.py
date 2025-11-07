import unittest
from unittest.mock import patch, MagicMock
import os

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.orchestrator import Orchestrator

class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        self.db_session_mock = MagicMock()
        self.vcs_service_mock = MagicMock()
        self.orchestrator = Orchestrator(self.vcs_service_mock, self.db_session_mock)

    @patch('src.orchestrator.di.google_web_search')
    @patch('src.llm.LLMService.validate_vulnerability')
    def test_validate_vulnerability_with_search_false_positive(self, mock_validate_vulnerability, mock_google_web_search):
        """Test that validate_vulnerability_with_search correctly identifies a false positive."""
        mock_google_web_search.return_value = 'some search results'
        mock_validate_vulnerability.return_value = '{"false_positive": true}'
        vulnerability = {
            'description': 'some vulnerability',
            'code_snippet': 'some code'
        }
        result = self.orchestrator.validate_vulnerability_with_search(vulnerability)
        self.assertFalse(result)

    @patch('src.orchestrator.di.google_web_search')
    @patch('src.llm.LLMService.validate_vulnerability')
    def test_validate_vulnerability_with_search_not_false_positive(self, mock_validate_vulnerability, mock_google_web_search):
        """Test that validate_vulnerability_with_search correctly identifies a non-false positive."""
        mock_google_web_search.return_value = 'some search results'
        mock_validate_vulnerability.return_value = '{"false_positive": false}'
        vulnerability = {
            'description': 'some vulnerability',
            'code_snippet': 'some code'
        }
        result = self.orchestrator.validate_vulnerability_with_search(vulnerability)
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()
