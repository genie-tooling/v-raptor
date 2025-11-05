import os
import tempfile
from git import Repo, GitCommandError
from github import Github, GithubException
from io import BytesIO
import re

class VCSService:
    def __init__(self, git_provider, token):
        self.git_provider = git_provider
        self.token = token
        if not self.token and self.git_provider == 'github':
            self.token = os.getenv('GITHUB_TOKEN')
        if not self.token:
            print("Warning: GITHUB_TOKEN environment variable is not set. Creating pull requests will fail.")

    def is_valid_git_url(self, repo_url):
        """Checks if a given URL is a valid git repository URL."""
        # Check for local git repository
        if os.path.isdir(repo_url) and os.path.isdir(os.path.join(repo_url, '.git')):
            return repo_url

        # Check for remote git repository
        if repo_url.endswith('.git'):
            return repo_url

        # Check for GitHub and Bitbucket URLs and add .git if missing
        github_match = re.match(r"https://github.com/([\w-]+)/([\w-]+)", repo_url)
        if github_match:
            return f"{repo_url}.git"

        bitbucket_match = re.match(r"https://bitbucket.org/([\w-]+)/([\w-]+)", repo_url)
        if bitbucket_match:
            return f"{repo_url}.git"

        return None

    def clone_repo(self, repo_url):
        """Clones a git repository to a temporary directory."""
        local_path = tempfile.mkdtemp(prefix="v-raptor-")
        print(f"Cloning {repo_url} to {local_path}")
        Repo.clone_from(repo_url, local_path)
        return local_path

    def get_commit_diff(self, repo_path, commit_hash):
        """Gets the diff of a commit against its parent."""
        try:
            repo = Repo(repo_path)
            commit = repo.commit(commit_hash)
            if not commit.parents:
                # This is the initial commit, diff against an empty tree
                return repo.git.show(commit_hash)
            
            # Get diff against the first parent of the commit
            return repo.git.diff(commit.parents.hexsha, commit.hexsha)
        except GitCommandError as e:
            print(f"Error getting commit diff: {e}")
            return ""

    def create_pull_request(self, repo_path, repo_url, branch_name, title, body, patch_diff):
        """Applies a patch, creates a branch, pushes it, and opens a PR."""
        try:
            repo = Repo(repo_path)
            
            # Store the current branch to return to it later
            main_branch = repo.active_branch
            
            print(f"Creating new branch: {branch_name}")
            # Delete branch if it exists locally from a previous run
            if branch_name in repo.heads:
                repo.delete_head(branch_name, '-D')
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()

            print("Applying patch...")
            # Use BytesIO to pass the patch diff as a stream to git apply
            patch_stream = BytesIO(patch_diff.encode('utf-8'))
            repo.git.apply(istream=patch_stream)

            print("Committing changes...")
            repo.git.add(A=True)
            repo.index.commit(title)

            print(f"Pushing branch '{branch_name}' to origin...")
            origin = repo.remote(name='origin')
            # Use force-with-lease in a real scenario, but force is fine for this tool
            origin.push(f"{branch_name}:{branch_name}", force=True)

            if self.git_provider == 'github' and self.token:
                self._create_github_pr(repo_url, main_branch.name, branch_name, title, body)
            else:
                print("Skipping PR creation. No supported git provider or token.")
                
            # Clean up by returning to the original branch
            main_branch.checkout()
        except (GitCommandError, Exception) as e:
            print(f"An error occurred during pull request creation: {e}")
            # Try to clean up and go back to main branch
            if 'repo' in locals() and 'main_branch' in locals():
                main_branch.checkout()

    def _create_github_pr(self, repo_url, base_branch, head_branch, title, body):
        """Creates a pull request on GitHub."""
        if not self.token:
            print("Cannot create GitHub PR: token not provided.")
            return

        try:
            g = Github(self.token)
            # Extract 'user/repo' from 'https://github.com/user/repo.git'
            repo_name = '/'.join(repo_url.split('.git').split('/')[-2:])

            gh_repo = g.get_repo(repo_name)
            
            # Check if a PR already exists
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