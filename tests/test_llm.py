import unittest
from unittest.mock import patch, MagicMock
import os

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.llm import LLMService
from src import config

class TestLLMService(unittest.TestCase):
    def setUp(self):
        with patch.object(config, 'SCANNER_LLM_PROVIDER', 'gemini'), \
             patch.object(config, 'PATCHER_LLM_PROVIDER', 'gemini'):
            self.service = LLMService()
        self.service.scanner_client = MagicMock()
        self.service.patcher_client = MagicMock()

    def test_analyze_diff_with_tools(self):
        """Test that the analyze_diff_with_tools method generates the correct prompt."""
        self.service.analyze_diff_with_tools('test diff')
        self.service.scanner_client.create_chat_completion.assert_called_once()
        prompt = self.service.scanner_client.create_chat_completion.call_args[0][1]
        self.assertIn('test diff', prompt)
        self.assertIn('You are a senior security engineer', prompt)

    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data='test content')
    def test_analyze_file(self, mock_open):
        """Test that the analyze_file method generates the correct prompt."""
        self.service.analyze_file('/fake/path/test.py')
        self.service.scanner_client.create_chat_completion.assert_called_once()
        prompt = self.service.scanner_client.create_chat_completion.call_args[0][1]
        self.assertIn('test content', prompt)
        self.assertIn('You are a senior security engineer', prompt)

    def test_get_root_cause_analysis(self):
        """Test that the get_root_cause_analysis method generates the correct prompt."""
        self.service.get_root_cause_analysis('test code', 'test vulnerability')
        self.service.scanner_client.create_chat_completion.assert_called_once()
        prompt = self.service.scanner_client.create_chat_completion.call_args[0][1]
        self.assertIn('test code', prompt)
        self.assertIn('test vulnerability', prompt)

    def test_generate_test_script(self):
        """Test that the generate_test_script method generates the correct prompt and extracts the code."""
        self.service.scanner_client.create_chat_completion.return_value = '```python\nprint("hello")\n```'
        code = self.service.generate_test_script('test code', 'test vulnerability')
        self.service.scanner_client.create_chat_completion.assert_called_once()
        prompt = self.service.scanner_client.create_chat_completion.call_args[0][1]
        self.assertIn('test code', prompt)
        self.assertIn('test vulnerability', prompt)
        self.assertEqual(code, 'print("hello")')

    def test_interpret_results(self):
        """Test that the interpret_results method generates the correct prompt and parses the output."""
        self.service.scanner_client.create_chat_completion.return_value = '0.9'
        score = self.service.interpret_results('test analysis', 'test script', 'test output')
        self.service.scanner_client.create_chat_completion.assert_called_once()
        prompt = self.service.scanner_client.create_chat_completion.call_args[0][1]
        self.assertIn('test analysis', prompt)
        self.assertIn('test script', prompt)
        self.assertIn('test output', prompt)
        self.assertEqual(score, 0.9)

    def test_generate_patch(self):
        """Test that the generate_patch method generates the correct prompt."""
        self.service.generate_patch('test code', 'test analysis')
        self.service.patcher_client.create_chat_completion.assert_called_once()
        prompt = self.service.patcher_client.create_chat_completion.call_args[0][1]
        self.assertIn('test code', prompt)
        self.assertIn('test analysis', prompt)

    def test_extract_json(self):
        """Test that JSON is extracted correctly from a string."""
        text = '```json\n{"key": "value"}\n```'
        self.assertEqual(self.service.extract_json(text), '{"key": "value"}')

    def test_extract_python_code(self):
        """Test that Python code is extracted correctly from a string."""
        text = '```python\nprint("hello")\n```'
        self.assertEqual(self.service.extract_python_code(text), 'print("hello")')

    def test_validate_vulnerability(self):
        """Test that the validate_vulnerability method generates the correct prompt."""
        self.service.validate_vulnerability('test vulnerability', 'test search results')
        self.service.scanner_client.create_chat_completion.assert_called_once()
        prompt = self.service.scanner_client.create_chat_completion.call_args[0][1]
        self.assertIn('test vulnerability', prompt)
        self.assertIn('test search results', prompt)

    @patch('src.llm_providers.gemini.genai.Client')
    def test_gemini_initialization(self, mock_gemini_client):
        """Test that the LLMService initializes correctly with the gemini provider."""
        with patch.object(config, 'SCANNER_LLM_PROVIDER', 'gemini'), \
             patch.object(config, 'PATCHER_LLM_PROVIDER', 'gemini'):
            service = LLMService()
            self.assertIsNotNone(service.scanner_client)
            self.assertIsNotNone(service.patcher_client)
        self.assertEqual(mock_gemini_client.call_count, 2)

    @patch('src.llm_providers.llama_cpp.Llama')
    def test_llama_cpp_initialization(self, mock_llama):
        """Test that the LLMService initializes correctly with the llama.cpp provider."""
        with patch.object(config, 'SCANNER_LLM_PROVIDER', 'llama.cpp'), \
             patch.object(config, 'SCANNER_LLAMA_CPP_MODEL_PATH', 'test-path'), \
             patch.object(config, 'PATCHER_LLM_PROVIDER', 'llama.cpp'), \
             patch.object(config, 'PATCHER_LLAMA_CPP_MODEL_PATH', 'test-path'), \
             patch('os.path.exists', return_value=True):
            service = LLMService()
            self.assertIsNotNone(service.scanner_client)
            self.assertIsNotNone(service.patcher_client)
        self.assertEqual(mock_llama.call_count, 2)

    @patch('src.llm_providers.ollama.Client')
    def test_ollama_initialization(self, mock_ollama_client):
        """Test that the LLMService initializes correctly with the ollama provider."""
        with patch.object(config, 'SCANNER_LLM_PROVIDER', 'ollama'), \
             patch.object(config, 'PATCHER_LLM_PROVIDER', 'ollama'):
            service = LLMService()
            self.assertIsNotNone(service.scanner_client)
            self.assertIsNotNone(service.patcher_client)
        self.assertEqual(mock_ollama_client.call_count, 2)

if __name__ == '__main__':
    unittest.main()