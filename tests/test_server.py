import unittest
from unittest.mock import patch, MagicMock
import os

# Set a dummy API key for testing
os.environ['GEMINI_API_KEY'] = 'test-key'

from src.server import app

class TestServer(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()

    def test_index_route(self):
        """Test the index route."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_config_route(self):
        """Test the config route."""
        response = self.app.get('/config')
        self.assertEqual(response.status_code, 200)

    @patch('src.server.open')
    def test_save_llm_settings_route(self, mock_open):
        """Test the save_llm_settings route."""
        data = {
            'llm_provider': 'gemini',
            'llama_cpp_model_path': '/path/to/model',
            'ollama_url': 'http://localhost:11434',
            'gemini_model': 'gemini-1.5-pro-latest'
        }
        response = self.app.post('/save_llm_settings', data=data)
        self.assertEqual(response.status_code, 302) # Redirect status code

if __name__ == '__main__':
    unittest.main()
