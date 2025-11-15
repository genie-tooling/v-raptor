import unittest
from unittest.mock import patch, MagicMock
from src.server import app
from src.database import get_session, ChatMessage, Finding, QualityInterpretation, Base, Scan, Repository, QualityMetric
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
import tempfile
import shutil
from flask import g

class TestChat(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.db_session = Session()
        self.test_dir = tempfile.mkdtemp()

        self.get_session_patcher = patch('src.server.get_session')
        self.mock_get_session = self.get_session_patcher.start()
        self.mock_get_session.return_value = lambda: self.db_session

    def tearDown(self):
        self.db_session.close()
        Base.metadata.drop_all(self.engine)
        shutil.rmtree(self.test_dir)
        self.get_session_patcher.stop()

    def test_reset_chat_finding(self):
        """Test that the /reset_chat route correctly deletes chat messages for a finding."""
        # Create a dummy finding and chat messages
        repo = Repository(id=1, name='test_repo', url=self.test_dir)
        scan = Scan(id=1, repository_id=1)
        finding = Finding(id=1, scan_id=1)
        self.db_session.add_all([repo, scan, finding])
        self.db_session.commit()
        chat_message1 = ChatMessage(finding_id=1, message="test message 1", sender="user")
        chat_message2 = ChatMessage(finding_id=1, message="test message 2", sender="assistant")
        self.db_session.add_all([chat_message1, chat_message2])
        self.db_session.commit()

        # Verify that the chat messages were created
        messages = self.db_session.query(ChatMessage).filter_by(finding_id=1).all()
        self.assertEqual(len(messages), 2)

        # Call the reset_chat route
        response = self.app.post('/reset_chat/finding/1')

        # Verify that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'success', 'message': 'Chat history has been reset.'})

        # Verify that the chat messages were deleted
        messages = self.db_session.query(ChatMessage).filter_by(finding_id=1).all()
        self.assertEqual(len(messages), 0)

    def test_reset_chat_quality(self):
        """Test that the /reset_chat route correctly deletes chat messages for a quality interpretation."""
        # Create a dummy quality interpretation and chat messages
        repo = Repository(id=1, name='test_repo', url=self.test_dir)
        scan = Scan(id=1, repository_id=1)
        quality_metric = QualityMetric(id=1, scan_id=1)
        quality_interpretation = QualityInterpretation(id=1, quality_metric_id=1)
        self.db_session.add_all([repo, scan, quality_metric, quality_interpretation])
        self.db_session.commit()
        chat_message1 = ChatMessage(quality_interpretation_id=1, message="test message 1", sender="user")
        chat_message2 = ChatMessage(quality_interpretation_id=1, message="test message 2", sender="assistant")
        self.db_session.add_all([chat_message1, chat_message2])
        self.db_session.commit()

        # Verify that the chat messages were created
        messages = self.db_session.query(ChatMessage).filter_by(quality_interpretation_id=1).all()
        self.assertEqual(len(messages), 2)

        # Call the reset_chat route
        response = self.app.post('/reset_chat/quality/1')

        # Verify that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'success', 'message': 'Chat history has been reset.'})

        # Verify that the chat messages were deleted
        messages = self.db_session.query(ChatMessage).filter_by(quality_interpretation_id=1).all()
        self.assertEqual(len(messages), 0)

    @patch('src.chat_service.LLMService')
    @patch('src.chat_service.VCSService')
    def test_chat_with_finding_with_context(self, mock_vcs_service, mock_llm_service):
        """Test that the file content is correctly included in the prompt when chatting about a finding."""
        # Create a dummy finding
        repo = Repository(id=1, name='test_repo', url=self.test_dir)
        scan = Scan(id=1, repository_id=1)
        finding = Finding(id=1, scan_id=1, file_path='test.py', code_snippet='print("hello")')
        self.db_session.add_all([repo, scan, finding])
        self.db_session.commit()

        # Create a fake file
        file_path = os.path.join(self.test_dir, 'test.py')
        with open(file_path, 'w') as f:
            f.write('print("hello world")')

        # Mock the vcs_service to return the test directory
        mock_vcs_instance = mock_vcs_service.return_value
        mock_vcs_instance.clone_repo.return_value = self.test_dir

        # Mock the llm_service to capture the prompt
        mock_llm_instance = mock_llm_service.return_value
        mock_llm_instance._create_chat_completion.return_value = "test response"

        from src.chat_service import ChatService
        chat_service = ChatService(self.db_session, mock_llm_instance, mock_vcs_instance)
        chat_service.chat_with_finding(1, "test message")

        # Verify that the prompt contains the file content
        prompt = mock_llm_instance._create_chat_completion.call_args[0][2]
        self.assertIn('print("hello world")', prompt)

    @patch('src.chat_service.LLMService')
    @patch('src.chat_service.VCSService')
    def test_chat_with_quality_interpretation_with_context(self, mock_vcs_service, mock_llm_service):
        """Test that the file content is correctly included in the prompt when chatting about a quality interpretation."""
        # Create a dummy quality interpretation
        repo = Repository(id=1, name='test_repo', url=self.test_dir)
        scan = Scan(id=1, repository_id=1)
        quality_metric = QualityMetric(id=1, scan_id=1, file_path='test.py')
        quality_interpretation = QualityInterpretation(id=1, quality_metric_id=1)
        self.db_session.add_all([repo, scan, quality_metric, quality_interpretation])
        self.db_session.commit()

        # Create a fake file
        file_path = os.path.join(self.test_dir, 'test.py')
        with open(file_path, 'w') as f:
            f.write('print("hello world")')

        # Mock the vcs_service to return the test directory
        mock_vcs_instance = mock_vcs_service.return_value
        mock_vcs_instance.clone_repo.return_value = self.test_dir

        # Mock the llm_service to capture the prompt
        mock_llm_instance = mock_llm_service.return_value
        mock_llm_instance._create_chat_completion.return_value = "test response"

        from src.chat_service import ChatService
        chat_service = ChatService(self.db_session, mock_llm_instance, mock_vcs_instance)
        chat_service.chat_with_quality_interpretation(1, "test message")

        # Verify that the prompt contains the file content
        prompt = mock_llm_instance._create_chat_completion.call_args[0][2]
        self.assertIn('print("hello world")', prompt)

if __name__ == '__main__':
    unittest.main()
