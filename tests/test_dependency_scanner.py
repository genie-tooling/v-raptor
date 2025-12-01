import unittest
from unittest.mock import patch, MagicMock
from src.dependency_scanner import scan_dependencies
import subprocess
import json

class TestDependencyScanner(unittest.TestCase):

    @patch('subprocess.run')
    def test_scan_dependencies_osv_not_found(self, mock_subprocess_run):
        """Test that the scanner handles when osv-scanner is not found."""
        mock_subprocess_run.side_effect = FileNotFoundError
        result = scan_dependencies('/fake/path')
        self.assertEqual(result, [])

    @patch('subprocess.run')
    def test_scan_dependencies_called_process_error(self, mock_subprocess_run):
        """Test that the scanner handles a CalledProcessError from osv-scanner."""
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, 'cmd', stderr='some error')
        result = scan_dependencies('/fake/path')
        self.assertEqual(result, [])

    @patch('subprocess.run')
    def test_scan_dependencies_with_vulnerabilities(self, mock_subprocess_run):
        """Test that the scanner correctly parses vulnerabilities from osv-scanner output."""
        mock_output = {
            "results": [
                {
                    "package": {
                        "name": "test-package",
                        "version": "1.0.0"
                    },
                    "vulns": [
                        {
                            "id": "CVE-2023-12345",
                            "summary": "A test vulnerability",
                            "details": "Details about the test vulnerability"
                        }
                    ]
                }
            ]
        }
        mock_subprocess_run.return_value = MagicMock(stdout=json.dumps(mock_output), stderr="")
        result = scan_dependencies('/fake/path')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'CVE-2023-12345')
        self.assertEqual(result[0]['package'], 'test-package')
        self.assertEqual(result[0]['version'], '1.0.0')
        self.assertEqual(result[0]['summary'], 'A test vulnerability')
        self.assertEqual(result[0]['details'], 'Details about the test vulnerability')

    @patch('subprocess.run')
    def test_scan_dependencies_no_vulnerabilities(self, mock_subprocess_run):
        """Test that the scanner returns an empty list when no vulnerabilities are found."""
        mock_output = {"results": []}
        mock_subprocess_run.return_value = MagicMock(stdout=json.dumps(mock_output), stderr="")
        result = scan_dependencies('/fake/path')
        self.assertEqual(result, [])

    @patch('subprocess.run')
    def test_scan_dependencies_invalid_json(self, mock_subprocess_run):
        """Test that the scanner handles invalid JSON output from osv-scanner."""
        mock_subprocess_run.return_value = MagicMock(stdout='not json', stderr="")
        result = scan_dependencies('/fake/path')
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main()
