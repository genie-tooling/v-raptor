import unittest
from unittest.mock import MagicMock
import os
import tempfile
import shutil

from src.quality_scanners.ruby import RubyQualityScanner
from src.quality_scanners.python import PythonQualityScanner

class TestRubyQualityScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ruby_file_path = os.path.join(self.test_dir, 'test.rb')
        with open(self.ruby_file_path, 'w') as f:
            f.write("""
class Greeter
  def initialize(name)
    @name = name.capitalize
  end

  def salute
    puts "Hello #{@name}!"
  end
end
""")
        self.scanner = RubyQualityScanner(self.test_dir, MagicMock(), MagicMock())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_get_quality_metrics_for_ruby_file(self):
        """Test that get_quality_metrics returns a dictionary with the correct keys for a Ruby file."""
        metrics = self.scanner.get_quality_metrics(self.ruby_file_path)

        self.assertIsInstance(metrics, dict)
        self.assertIn('cyclomatic_complexity', metrics)
        self.assertIn('maintainability_index', metrics)
        self.assertIn('sloc', metrics)
        self.assertIn('code_churn', metrics)
        self.assertIsInstance(metrics['cyclomatic_complexity'], int)
        self.assertIsInstance(metrics['maintainability_index'], (int, float))
        self.assertIsInstance(metrics['sloc'], int)
        self.assertIsInstance(metrics['code_churn'], int)

class TestPythonQualityScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.python_file_path = os.path.join(self.test_dir, 'test.py')
        with open(self.python_file_path, 'w') as f:
            f.write("""
def greet(name):
    return f"Hello, {name}!"
""")
        # Mock the repo_path for _get_code_churn
        self.scanner = PythonQualityScanner(self.test_dir, MagicMock(), MagicMock())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_get_quality_metrics_for_python_file(self):
        """Test that get_quality_metrics returns a dictionary with the correct keys for a Python file."""
        # Create a git repo in the temp directory so that churn can be calculated
        from git import Repo
        repo = Repo.init(self.test_dir)
        repo.index.add([self.python_file_path])
        repo.index.commit("initial commit")
        
        metrics = self.scanner.get_quality_metrics(self.python_file_path)

        self.assertIsInstance(metrics, dict)
        self.assertIn('cyclomatic_complexity', metrics)
        self.assertIn('maintainability_index', metrics)
        self.assertIn('sloc', metrics)
        self.assertIn('code_churn', metrics)
        self.assertIsInstance(metrics['cyclomatic_complexity'], int)
        self.assertIsInstance(metrics['maintainability_index'], (int, float))
        self.assertIsInstance(metrics['sloc'], int)
        self.assertIsInstance(metrics['code_churn'], int)

if __name__ == '__main__':
    unittest.main()
