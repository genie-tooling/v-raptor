import unittest
from unittest.mock import patch, MagicMock
import os
import json
import subprocess
from src.scanner import Scanner
from src.database import Scan, Repository

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.db_session = MagicMock()
        self.llm_service = MagicMock()
        self.vulnerability_processor = MagicMock()
        self.sandbox_service = MagicMock()
        self.scanner = Scanner(
            self.db_session,
            self.llm_service,
            self.vulnerability_processor,
            self.sandbox_service
        )
        self.scan = Scan(id=1, repository=Repository(id=1))

    @patch('src.scanner.subprocess.run')
    @patch('src.scanner.os.path.exists')
    def test_run_sast_tool_file_output(self, mock_exists, mock_run):
        """Test the _run_sast_tool method with file output."""
        mock_exists.return_value = True
        mock_parser = MagicMock(return_value=[{'description': 'test vulnerability'}])
        
        self.scanner._run_sast_tool(
            command=['test-command'],
            repo_path='/fake/path',
            scan=self.scan,
            parser=mock_parser,
            report_path='/fake/path/report.json',
            tool_name='test-tool'
        )

        mock_run.assert_called_once_with(
            ['test-command'], check=True, capture_output=True, text=True, cwd=None
        )
        mock_parser.assert_called_once_with('/fake/path/report.json', 'test-tool')
        self.vulnerability_processor.process_vulnerability.assert_called_once_with(
            {'description': 'test vulnerability'},
            '/fake/path',
            self.scan.repository.url,
            self.scan
        )

    @patch('src.scanner.subprocess.run')
    def test_run_sast_tool_stdout_output(self, mock_run):
        """Test the _run_sast_tool method with stdout output."""
        mock_run.return_value = MagicMock(stdout='{"results": []}')
        mock_parser = MagicMock(return_value=[{'description': 'test vulnerability'}])

        self.scanner._run_sast_tool(
            command=['test-command'],
            repo_path='/fake/path',
            scan=self.scan,
            parser=mock_parser,
            report_path=None,
            tool_name='test-tool',
            output_to_stdout=True
        )

        mock_run.assert_called_once_with(
            ['test-command'], check=True, capture_output=True, text=True, cwd=None
        )
        mock_parser.assert_called_once_with('{"results": []}', 'test-tool')
        self.vulnerability_processor.process_vulnerability.assert_called_once_with(
            {'description': 'test vulnerability'},
            '/fake/path',
            self.scan.repository.url,
            self.scan
        )

    def test_parse_semgrep_report(self):
        """Test the _parse_semgrep_report method."""
        report = {
            "results": [
                {
                    "check_id": "test-rule",
                    "path": "/fake/path/test.py",
                    "start": {"line": 10},
                    "extra": {
                        "lines": "test code",
                        "message": "test message",
                        "severity": "HIGH"
                    }
                }
            ]
        }
        with patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps(report))):
            vulnerabilities = self.scanner._parse_semgrep_report('/fake/path/report.json', 'semgrep')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['description'], 'semgrep: test message (https://semgrep.dev/r/test-rule)')

    def test_parse_bandit_report(self):
        """Test the _parse_bandit_report method."""
        report = {
            "results": [
                {
                    "test_id": "B001",
                    "filename": "/fake/path/test.py",
                    "line_number": 10,
                    "code": "test code",
                    "issue_text": "test issue",
                    "issue_severity": "HIGH"
                }
            ]
        }
        with patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps(report))):
            vulnerabilities = self.scanner._parse_bandit_report('/fake/path/report.json', 'bandit')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['description'], 'bandit: test issue (https://bandit.readthedocs.io/en/latest/plugins/B001.html)')

    def test_parse_brakeman_report(self):
        """Test the _parse_brakeman_report method."""
        report = {
            "warnings": [
                {
                    "file": "/fake/path/test.rb",
                    "line": 10,
                    "code": "test code",
                    "warning_type": "test warning",
                    "message": "test message",
                    "confidence": "HIGH"
                }
            ]
        }
        with patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps(report))):
            vulnerabilities = self.scanner._parse_brakeman_report('/fake/path/report.json', 'brakeman')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['description'], 'brakeman: test warning - test message')

    def test_parse_njsscan_report(self):
        """Test the _parse_njsscan_report method."""
        report = {
            "/fake/path/test.js": {
                "findings": [
                    {
                        "line": 10,
                        "lines": "test code",
                        "title": "test title",
                        "metadata": {
                            "severity": "HIGH"
                        }
                    }
                ]
            }
        }
        vulnerabilities = self.scanner._parse_njsscan_report(json.dumps(report), 'njsscan')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['description'], 'njsscan: test title')

    def test_parse_gosec_report(self):
        """Test the _parse_gosec_report method."""
        report = {
            "Issues": [
                {
                    "file": "/fake/path/test.go",
                    "line": "10",
                    "code": "test code",
                    "details": "test details",
                    "severity": "HIGH"
                }
            ]
        }
        with patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps(report))):
            vulnerabilities = self.scanner._parse_gosec_report('/fake/path/report.json', 'gosec')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['description'], 'gosec: test details')

    @patch('xml.etree.ElementTree.parse')
    def test_parse_cppcheck_report(self, mock_xml_parse):
        """Test the _parse_cppcheck_report method."""
        xml_content = """
        <results version="2">
            <errors>
                <error id="arrayIndexOutOfBounds" severity="error" msg="Array &apos;a[10]&apos; accessed at index 10, which is out of bounds.">
                    <location file="test.cpp" line="5"/>
                </error>
            </errors>
        </results>
        """
        mock_root = unittest.mock.MagicMock()
        mock_root.iter.return_value = [unittest.mock.MagicMock(
            find=unittest.mock.MagicMock(return_value=unittest.mock.MagicMock(
                get=lambda x: {'file': 'test.cpp', 'line': '5'}[x]
            )),
            get=lambda x: {'msg': "Array 'a[10]' accessed at index 10, which is out of bounds.", 'severity': 'error'}[x]
        )]
        mock_tree = unittest.mock.MagicMock()
        mock_tree.getroot.return_value = mock_root
        mock_xml_parse.return_value = mock_tree

        vulnerabilities = self.scanner._parse_cppcheck_report('/fake/path/report.xml', 'cppcheck')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['description'], "cppcheck: Array 'a[10]' accessed at index 10, which is out of bounds.")






if __name__ == '__main__':
    unittest.main()