import unittest
from unittest.mock import patch, MagicMock
from src.vcs import VCSService

class TestVCSService(unittest.TestCase):

    def test_init(self):
        """Test that the Git provider and token are initialized correctly."""
        service = VCSService('github', 'test-token')
        self.assertEqual(service.git_provider, 'github')
        self.assertEqual(service.token, 'test-token')

    @patch('subprocess.check_output')
    def test_parse_and_validate_repo_url(self, mock_check_output):
        """Test various Git URLs to ensure they are parsed and validated correctly."""
        mock_check_output.return_value = b''
        service = VCSService('github', 'test-token')

        # Test case 1: Standard URL
        url = 'https://github.com/user/repo'
        base_url, branch = service.parse_and_validate_repo_url(url)
        self.assertEqual(base_url, 'https://github.com/user/repo.git')
        self.assertIsNone(branch)

        # Test case 2: URL with .git
        url = 'https://github.com/user/repo.git'
        base_url, branch = service.parse_and_validate_repo_url(url)
        self.assertEqual(base_url, 'https://github.com/user/repo.git')
        self.assertIsNone(branch)

        # Test case 3: URL with branch
        url = 'https://github.com/user/repo/tree/my-branch'
        base_url, branch = service.parse_and_validate_repo_url(url)
        self.assertEqual(base_url, 'https://github.com/user/repo.git')
        self.assertEqual(branch, 'my-branch')

        # Test case 4: Invalid URL
        url = 'https://invalid.com/user/repo'
        base_url, branch = service.parse_and_validate_repo_url(url)
        self.assertIsNone(base_url)
        self.assertIsNone(branch)

    @patch('subprocess.check_output')
    def test_get_branches(self, mock_check_output):
        """Test that the branches are fetched correctly."""
        mock_check_output.return_value = 'some_hash\trefs/heads/main\nanother_hash\trefs/heads/dev'
        service = VCSService('github', 'test-token')
        branches = service.get_branches('https://github.com/user/repo.git')
        self.assertEqual(branches, ['main', 'dev'])

    @patch('subprocess.check_output')
    def test_get_primary_branch(self, mock_check_output):
        """Test that the primary branch is fetched correctly."""
        mock_check_output.return_value = 'ref: refs/heads/main\tHEAD'
        service = VCSService('github', 'test-token')
        primary_branch = service.get_primary_branch('https://github.com/user/repo.git')
        self.assertEqual(primary_branch, 'main')

    @patch('subprocess.check_output')
    def test_get_latest_commit_hash(self, mock_check_output):
        """Test that the latest commit hash is fetched correctly."""
        mock_check_output.return_value = 'some_hash\trefs/heads/main'
        service = VCSService('github', 'test-token')
        commit_hash = service.get_latest_commit_hash('https://github.com/user/repo.git', 'main')
        self.assertEqual(commit_hash, 'some_hash')

    def test_is_valid_git_url(self):
        """Test various URLs to ensure they are validated correctly."""
        service = VCSService('github', 'test-token')
        self.assertEqual(service.is_valid_git_url('https://github.com/user/repo.git'), 'https://github.com/user/repo.git')
        self.assertEqual(service.is_valid_git_url('https://github.com/user/repo'), 'https://github.com/user/repo.git')
        self.assertIsNone(service.is_valid_git_url('https://invalid.com/user/repo'))

    @patch('src.vcs.Repo')
    def test_clone_repo(self, mock_repo):
        """Test that a repository is cloned correctly."""
        service = VCSService('github', 'test-token')
        with patch('tempfile.mkdtemp') as mock_mkdtemp:
            mock_mkdtemp.return_value = '/fake/path'
            path = service.clone_repo('https://github.com/user/repo.git')
            self.assertEqual(path, '/fake/path')
            mock_repo.clone_from.assert_called_once_with('https://github.com/user/repo.git', '/fake/path')

    @patch('src.vcs.Repo')
    def test_get_commit_diff(self, mock_repo):
        """Test that a commit diff is retrieved correctly."""
        mock_git_repo = MagicMock()
        mock_repo.return_value = mock_git_repo
        mock_commit = MagicMock()
        mock_commit.parents = [MagicMock()]
        mock_git_repo.commit.return_value = mock_commit
        service = VCSService('github', 'test-token')
        service.get_commit_diff('/fake/path', 'some_hash')
        mock_git_repo.git.diff.assert_called_once()


if __name__ == '__main__':
    unittest.main()
