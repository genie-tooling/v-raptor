import unittest
from unittest.mock import patch, MagicMock
import os

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.llm import LLMService
from src import config

class TestLLMService(unittest.TestCase):

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