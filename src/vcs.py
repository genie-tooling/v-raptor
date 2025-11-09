import os
import tempfile
from git import Repo, GitCommandError
from github import Github, GithubException
from io import BytesIO
import re
import subprocess

class VCSService:
    def __init__(self, git_provider, token):
        self.git_provider = git_provider
        self.token = token
        if not self.token and self.git_provider == 'github':
            self.token = os.getenv('GITHUB_TOKEN')
        if not self.token:
            print("Warning: GITHUB_TOKEN environment variable is not set. Creating pull requests will fail.")

    def parse_and_validate_repo_url(self, url: str):
        """
        Parses a potentially complex Git URL to extract the base repository URL
        and an optional branch name.
        Returns a tuple: (base_repo_url, branch_name) or (None, None) if invalid.
        """
        patterns = [
            re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/tree/([\w./-]+)"),
            re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)\.git"),
            re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)")
        ]

        for pattern in patterns:
            match = pattern.match(url)
            if match:
                groups = match.groups()
                user, repo = groups[0], groups[1]
                base_url = f"https://github.com/{user}/{repo}.git"
                branch = groups[2] if len(groups) > 2 else None

                try:
                    subprocess.check_output(
                        ['git', 'ls-remote', '--exit-code', base_url],
                        stderr=subprocess.PIPE
                    )
                    return base_url, branch
                except subprocess.CalledProcessError:
                    return None, None
        return None, None

    def get_branches(self, repo_url: str) -> list:
        """
        Lists all branches for a given remote repository URL without cloning it.
        Returns a list of branch names.
        """
        if not repo_url:
            return []
        try:
            result = subprocess.check_output(
                ['git', 'ls-remote', '--heads', repo_url],
                stderr=subprocess.PIPE,
                text=True
            )
            branches = [line.split('refs/heads/')[-1] for line in result.strip().split('\n') if line]
            return branches
        except subprocess.CalledProcessError as e:
            print(f"Error fetching branches for {repo_url}: {e.stderr}")
            return []
        except Exception as e:
            print(f"An unexpected error occurred while fetching branches: {e}")
            return []

    def get_primary_branch(self, repo_url: str) -> str:
        """
        Gets the primary branch name for a given remote repository URL without cloning it.
        Returns the primary branch name as a string, or None if it cannot be determined.
        """
        if not repo_url:
            return None
        try:
            result = subprocess.check_output(
                ['git', 'ls-remote', '--symref', repo_url, 'HEAD'],
                stderr=subprocess.PIPE,
                text=True
            )
            # The output looks like:
            # ref: refs/heads/main	HEAD
            # <hash>	HEAD
            # We are interested in the first line.
            match = re.search(r'ref: refs/heads/(\S+)\s+HEAD', result)
            if match:
                return match.group(1)
            return None
        except subprocess.CalledProcessError as e:
            print(f"Error fetching primary branch for {repo_url}: {e.stderr}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred while fetching primary branch: {e}")
            return None

    def is_valid_git_url(self, repo_url):
        """Checks if a given URL is a valid git repository URL."""
        if os.path.isdir(repo_url) and os.path.isdir(os.path.join(repo_url, '.git')):
            return repo_url
        if repo_url.endswith('.git'):
            return repo_url
        github_match = re.match(r"https://github.com/([\w-]+)/([\w-]+)", repo_url)
        if github_match:
            return f"{repo_url}.git"
        bitbucket_match = re.match(r"https://bitbucket.org/([\w-]+)/([\w-]+)", repo_url)
        if bitbucket_match:
            return f"{repo_url}.git"
        return None

    def clone_repo(self, repo_url, branch=None):
        """Clones a git repository to a temporary directory."""
        local_path = tempfile.mkdtemp(prefix="v-raptor-")
        print(f"Cloning {repo_url} to {local_path}")
        if branch:
            print(f"Checking out specific branch: {branch}")
            Repo.clone_from(repo_url, local_path, branch=branch)
        else:
            Repo.clone_from(repo_url, local_path)
        return local_path

    def get_commit_diff(self, repo_path, commit_hash):
        """Gets the diff of a commit against its parent."""
        try:
            repo = Repo(repo_path)
            commit = repo.commit(commit_hash)
            if not commit.parents:
                return repo.git.show(commit_hash)
            return repo.git.diff(commit.parents[0].hexsha, commit.hexsha)
        except GitCommandError as e:
            print(f"Error getting commit diff: {e}")
            return ""

    def create_pull_request(self, repo_path, repo_url, branch_name, title, body, patch_diff):
        """Applies a patch, creates a branch, pushes it, and opens a PR."""
        try:
            repo = Repo(repo_path)
            main_branch = repo.active_branch
            print(f"Creating new branch: {branch_name}")
            if branch_name in repo.heads:
                repo.delete_head(branch_name, '-D')
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()

            print("Applying patch...")
            patch_stream = BytesIO(patch_diff.encode('utf-8'))
            repo.git.apply(istream=patch_stream)

            print("Committing changes...")
            repo.git.add(A=True)
            repo.index.commit(title)

            print(f"Pushing branch '{branch_name}' to origin...")
            origin = repo.remote(name='origin')
            origin.push(f"{branch_name}:{branch_name}", force=True)

            if self.git_provider == 'github' and self.token:
                self._create_github_pr(repo_url, main_branch.name, branch_name, title, body)
            else:
                print("Skipping PR creation. No supported git provider or token.")
                
            main_branch.checkout()
        except (GitCommandError, Exception) as e:
            print(f"An error occurred during pull request creation: {e}")
            if 'repo' in locals() and 'main_branch' in locals():
                main_branch.checkout()

    def _create_github_pr(self, repo_url, base_branch, head_branch, title, body):
        """Creates a pull request on GitHub."""
        if not self.token:
            print("Cannot create GitHub PR: token not provided.")
            return

        try:
            g = Github(self.token)
            repo_name = '/'.join(repo_url.split('.git')[0].split('/')[-2:])
            gh_repo = g.get_repo(repo_name)
            
            existing_prs = gh_repo.get_pulls(state='open', head=f"{gh_repo.owner.login}:{head_branch}")
            if existing_prs.totalCount > 0:
                print(f"A pull request from branch '{head_branch}' already exists. Skipping creation.")
                return

            print(f"Creating pull request on GitHub repo: {repo_name}")
            pr = gh_repo.create_pull(
                title=title,
                body=body,
                head=head_branch,
                base=base_branch
            )
            print(f"Successfully created pull request: {pr.html_url}")
        except GithubException as e:
            print(f"Failed to create GitHub pull request: {e.status} {e.data}")
        except Exception as e:
            print(f"An unexpected error occurred with the GitHub API: {e}")