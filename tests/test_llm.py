import unittest
from unittest.mock import patch, MagicMock
import os

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.llm import LLMService

class TestLLMService(unittest.TestCase):

    @patch('google.genai.Client')
    def test_gemini_initialization(self, mock_gemini_client):
        """Test that the LLMService initializes correctly with the gemini provider."""
        service = LLMService(llm_provider='gemini')
        self.assertIsNotNone(service.model)
        mock_gemini_client.assert_called_once_with(api_key='test-key')

    @patch('llama_cpp.Llama')
    def test_llama_cpp_initialization(self, mock_llama):
        """Test that the LLMService initializes correctly with the llama.cpp provider."""
        service = LLMService(llm_provider='llama.cpp')
        self.assertIsNotNone(service.model)
        mock_llama.assert_called_once()

    @patch('ollama.Client')
    def test_ollama_initialization(self, mock_ollama_client):
        """Test that the LLMService initializes correctly with the ollama provider."""
        service = LLMService(llm_provider='ollama')
        self.assertIsNotNone(service.model)
        mock_ollama_client.assert_called_once()

if __name__ == '__main__':
    unittest.main()