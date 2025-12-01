import unittest
from unittest.mock import patch, MagicMock
from src.sandbox import SandboxService
import docker

class TestSandboxService(unittest.TestCase):

    @patch('docker.from_env')
    def test_init_docker_available(self, mock_from_env):
        """Test that the Docker client is initialized correctly when Docker is available."""
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        service = SandboxService()
        self.assertEqual(service.client, mock_client)

    @patch('docker.from_env')
    def test_init_docker_not_available(self, mock_from_env):
        """Test that an error is raised if Docker is not available."""
        mock_from_env.side_effect = docker.errors.DockerException
        with self.assertRaises(RuntimeError):
            SandboxService()

    @patch('docker.from_env')
    def test_ensure_image_not_found(self, mock_from_env):
        """Test that the image is pulled if it's not found locally."""
        mock_client = MagicMock()
        mock_client.images.get.side_effect = docker.errors.ImageNotFound(message="not found")
        mock_from_env.return_value = mock_client
        service = SandboxService()
        service._ensure_image('test-image')
        mock_client.images.pull.assert_called_once_with('test-image')

    @patch('docker.from_env')
    def test_probe_image(self, mock_from_env):
        """Test that the correct shell is returned."""
        mock_client = MagicMock()
        # Simulate that /bin/bash fails and /bin/sh succeeds
        mock_client.containers.run.side_effect = [Exception, MagicMock()]
        mock_from_env.return_value = mock_client
        service = SandboxService()
        shell = service.probe_image('test-image')
        self.assertEqual(shell, '/bin/sh')

    @patch('docker.from_env')
    def test_create_sandbox(self, mock_from_env):
        """Test that a sandbox is created successfully."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = 'test-id'
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client
        service = SandboxService()
        container_id = service.create_sandbox()
        self.assertEqual(container_id, 'test-id')

    @patch('src.sandbox.tarfile')
    @patch('src.sandbox.io.BytesIO')
    @patch('docker.from_env')
    def test_execute_python_script(self, mock_from_env, mock_bytesio, mock_tarfile):
        """Test that a Python script is executed correctly."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.exec_run.return_value = (0, b'output')
        mock_client.containers.get.return_value = mock_container
        mock_from_env.return_value = mock_client

        # Mock tarfile creation
        mock_tar = MagicMock()
        mock_tarfile.TarFile.return_value.__enter__.return_value = mock_tar

        service = SandboxService()
        output = service.execute_python_script('test-id', 'print("hello")')

        self.assertEqual(output, 'output')
        mock_container.put_archive.assert_called_once()
        mock_container.exec_run.assert_called_with('python3 /app/test_script.py')

    @patch('docker.from_env')
    def test_destroy_sandbox(self, mock_from_env):
        """Test that the sandbox is destroyed correctly."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_client.containers.get.return_value = mock_container
        mock_from_env.return_value = mock_client
        service = SandboxService()
        service.destroy_sandbox('test-id')
        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once()

    @patch('src.sandbox.tarfile')
    @patch('src.sandbox.io.BytesIO')
    @patch('docker.from_env')
    def test_run_command_in_repo(self, mock_from_env, mock_bytesio, mock_tarfile):
        """Test that a command is run in the repository correctly."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.exec_run.return_value = (0, b'output')
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client
        
        # Mock tarfile creation
        mock_tar = MagicMock()
        mock_tarfile.open.return_value.__enter__.return_value = mock_tar
        
        service = SandboxService()
        output = service.run_command_in_repo('/fake/repo', 'pytest')

        self.assertEqual(output, 'output')
        mock_client.containers.run.assert_called_once()
        mock_tar.add.assert_called_once_with('/fake/repo', arcname='.')
        mock_container.put_archive.assert_called_once()
        mock_container.exec_run.assert_called_once_with(
            cmd=['/bin/sh', '-c', 'pytest'],
            workdir='/app'
        )
        mock_container.kill.assert_called_once()
        mock_container.remove.assert_called_once()


if __name__ == '__main__':
    unittest.main()
