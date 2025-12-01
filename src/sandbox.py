import docker
import io
import tarfile
import logging
import os
from . import config

class SandboxService:
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.image_name = "v-raptor-sandbox:latest"
            if config.DOCKER_REGISTRY and not self.image_name.startswith(config.DOCKER_REGISTRY):
                self.image_name = f"{config.DOCKER_REGISTRY}/{self.image_name}"
        except docker.errors.DockerException as e:
            raise RuntimeError(f"Docker is not running or misconfigured: {e}")

    def _ensure_image(self, image_name):
        """Ensures the image exists locally, pulling it if necessary."""
        try:
            self.client.images.get(image_name)
        except docker.errors.ImageNotFound:
            logging.info(f"Image {image_name} not found locally. Pulling...")
            try:
                self.client.images.pull(image_name)
                logging.info(f"Image {image_name} pulled successfully.")
            except Exception as e:
                logging.error(f"Failed to pull image {image_name}: {e}")
                raise

    def probe_image(self, image_name):
        """
        Probes a container image to find a working shell entrypoint.
        Returns the shell path (e.g. '/bin/bash' or '/bin/sh') or None.
        """
        self._ensure_image(image_name)
        
        shells = ['/bin/bash', '/bin/sh']
        
        for shell in shells:
            try:
                logging.info(f"Probing {image_name} for {shell}...")
                self.client.containers.run(
                    image_name,
                    entrypoint=shell,
                    command=['-c', 'true'],
                    user='0',
                    remove=True
                )
                logging.info(f"Probe successful: {shell} works in {image_name}")
                return shell
            except Exception as e:
                logging.debug(f"Probe failed for {shell} in {image_name}: {e}")
                continue
        
        return None

    def create_sandbox(self):
        """Creates a new sandbox from the pre-built image."""
        try:
            logging.info(f"Creating sandbox from image: {self.image_name}...")
            container = self.client.containers.run(
                self.image_name, 
                command='tail -f /dev/null', 
                detach=True
            )
            logging.info(f"Sandbox created with ID: {container.id[:12]}")
            return container.id
        except Exception as e:
            logging.error(f"Error creating sandbox: {e}")
            return None

    def execute_in_sandbox(self, container_id, command):
        """Executes a generic command in the sandbox."""
        try:
            container = self.client.containers.get(container_id)
            exit_code, output = container.exec_run(command)
            return output.decode('utf-8')
        except Exception as e:
            logging.error(f"Error executing command in sandbox: {e}")
            return None

    def put_archive(self, container_id, path, data):
        """Puts a tar archive to a path in the container."""
        try:
            container = self.client.containers.get(container_id)
            container.put_archive(path, data)
        except Exception as e:
            logging.error(f"Error putting archive in sandbox: {e}")

    def execute_python_script(self, container_id, script_code):
        """Executes a Python script in the sandbox by copying it."""
        try:
            container = self.client.containers.get(container_id)
            pw_tarstream = io.BytesIO()
            pw_tar = tarfile.TarFile(fileobj=pw_tarstream, mode='w')
            file_data = script_code.encode('utf8')
            tarinfo = tarfile.TarInfo(name='test_script.py')
            tarinfo.size = len(file_data)
            pw_tar.addfile(tarinfo, io.BytesIO(file_data))
            pw_tar.close()
            pw_tarstream.seek(0)
            container.put_archive('/app/', pw_tarstream)
            return self.execute_in_sandbox(container_id, f'python3 /app/test_script.py')
        except Exception as e:
            logging.error(f"Error executing Python script: {e}")
            return None

    def destroy_sandbox(self, container_id):
        """Stops and removes the sandbox container."""
        if not container_id:
            return
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            pass # Container already gone
        except Exception as e:
            logging.warning(f"Error destroying sandbox {container_id[:12]}: {e}")

    def run_command_in_repo(self, repo_path, command, image_name=None, entrypoint='/bin/sh'):
        """
        Runs a command in a sandbox. 
        Uses 'docker cp' (via put_archive) instead of bind mounts to ensure files 
        are visible regardless of whether the worker is in a container or on host.
        """
        container = None
        try:
            image_to_use = image_name if image_name else self.image_name
            self._ensure_image(image_to_use)
            
            logging.info(f"Creating container for {image_to_use} using entrypoint {entrypoint}...")
            
            # 1. Start the container in detached mode, kept alive by tail
            # We use user='0' (root) to avoid permission issues during copy/execution
            container = self.client.containers.run(
                image_to_use,
                entrypoint=entrypoint,
                command=['-c', 'tail -f /dev/null'],
                detach=True,
                user='0',
                working_dir='/app'
            )

            # 2. Create a tar archive of the repo
            logging.info(f"Archiving repo at {repo_path}...")
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar.add(repo_path, arcname='.')
            tar_stream.seek(0)
            
            # 3. Copy repo into /app
            logging.info(f"Copying repo to container {container.id[:12]}...")
            container.put_archive('/app', tar_stream)
            
            # 4. Execute the command
            logging.info(f"Executing command: {command}")
            # Note: We use the same entrypoint shell for execution
            # exec_run does not take an entrypoint arg, it uses the default or shell.
            # To ensure consistent shell behavior, we wrap in the specific shell if needed,
            # but typically `['/bin/sh', '-c', command]` is safe if the shell exists.
            
            # If entrypoint was passed as /bin/bash, use it for exec too
            shell_cmd = [entrypoint, '-c', command]
            
            exit_code, output = container.exec_run(
                cmd=shell_cmd, 
                workdir='/app'
            )
            
            logs = output.decode('utf-8', errors='replace')
            
            if exit_code != 0:
                logging.error(f"Command failed with exit code {exit_code}")
                logs += f"\n[Process exited with code {exit_code}]"
                
                # If files were missing, list directory for debugging
                debug_exit, debug_ls = container.exec_run(['ls', '-la', '/app'])
                logs += f"\n[Debug: /app contents]\n{debug_ls.decode('utf-8', errors='replace')}"
            else:
                # Try to copy coverage.xml back to host if it exists
                try:
                    bits, stat = container.get_archive('/app/coverage.xml')
                    with open(os.path.join(repo_path, 'coverage.xml'), 'wb') as f:
                        for chunk in bits:
                            f.write(chunk)
                    logging.info("Retrieved coverage.xml from container.")
                except docker.errors.NotFound:
                    logging.warning("coverage.xml not found in container after success.")
                except Exception as e:
                    logging.error(f"Error retrieving coverage.xml: {e}")

            return logs

        except Exception as e:
            logging.error(f"Error running command in repo: {e}")
            return f"Error: {e}"
        finally:
            if container:
                try:
                    container.kill()
                    container.remove()
                except:
                    pass