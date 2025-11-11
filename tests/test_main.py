import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile
import shutil
from git import Repo
import json
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import main
from src.database import Base, Finding, Repository, Scan

class TestMain(unittest.TestCase):

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

        self.get_session_patcher = patch('main.get_session')
        self.mock_get_session = self.get_session_patcher.start()
        self.mock_get_session.return_value.return_value = self.db_session
        
        self.orchestrator_patcher = patch('main.Orchestrator')
        self.mock_orchestrator_class = self.orchestrator_patcher.start()
        self.mock_orchestrator_instance = self.mock_orchestrator_class.return_value


    def tearDown(self):
        shutil.rmtree(self.test_dir)
        self.db_session.close()
        self.get_session_patcher.stop()
        self.orchestrator_patcher.stop()

    def test_scan_local_argument(self):
        """Test that the --scan-local argument is correctly handled."""
        test_args = ['main.py', '--scan-local', self.test_dir]
        with patch.object(sys, 'argv', test_args):
            main()
        
        self.mock_orchestrator_instance.run_local_scan.assert_called_once_with(self.test_dir)

    @patch('sys.stdout', new_callable=__import__('io').StringIO)
    def test_output_json_argument(self, mock_stdout):
        """Test that the --output-json argument produces JSON output."""
        
        repo = Repository(name=os.path.basename(self.test_dir), url=self.test_dir)
        self.db_session.add(repo)
        self.db_session.commit()
        
        scan = Scan(repository_id=repo.id, scan_type='deep')
        self.db_session.add(scan)
        self.db_session.commit()

        finding = Finding(scan_id=scan.id, description="test finding")
        self.db_session.add(finding)
        self.db_session.commit()

        test_args = ['main.py', '--scan-local', self.test_dir, '--output-json']
        with patch.object(sys, 'argv', test_args):
            main()

        self.mock_orchestrator_instance.run_local_scan.assert_called_once_with(self.test_dir)
        
        output = mock_stdout.getvalue()
        try:
            # The output might contain other print statements, so we find the JSON part
            json_output_start = output.find('[')
            if json_output_start == -1:
                self.fail(f"Could not find JSON start in output: {output}")
            json_output = output[json_output_start:]
            data = json.loads(json_output)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]['description'], 'test finding')
        except (json.JSONDecodeError, IndexError):
            self.fail(f"Could not parse JSON from output: {output}")


if __name__ == '__main__':
    unittest.main()
