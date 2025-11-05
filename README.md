# V-Raptor

V-Raptor (Vulnerability-Remediation and Patching Tool Orchestrated by Reasoning) is an advanced AI agent for automated code analysis, bug detection, and remediation.

## Features

- **Automated Code Analysis:** V-Raptor can analyze code for a variety of issues, including security vulnerabilities, bugs, and code quality problems.
- **Bug Detection:** V-Raptor can detect bugs in code and provide detailed information about the bug, including the file, line number, and a description of the bug.
- **Automated Remediation:** V-Raptor can automatically generate patches for detected vulnerabilities and bugs.
- **Deep Scans:** V-Raptor can perform deep scans of repositories to find hidden vulnerabilities and secrets.
- **Dependency Scanning:** V-Raptor can scan the dependencies of a project for known vulnerabilities.
- **Configuration Scanning:** V-Raptor can scan configuration files for security misconfigurations.
- **Stale Secret Detection:** V-Raptor can detect stale secrets that are no longer in use.
- **HTML Reporting:** V-Raptor can generate an HTML report of its findings.

## Getting Started

### Prerequisites

- Python 3.10 or later
- Docker
- Go

### Installation

1. Clone the repository:

```
git clone https://github.com/your-username/v-raptor.git
```

2. Install the dependencies:

```
./run.sh init-db
```

### Usage

V-Raptor can be run in several modes:

#### Deep Scan Mode

This mode performs a comprehensive, one-time scan of an entire repository. It's useful for establishing a security baseline or running periodic in-depth analyses. The deep scan includes:
- Secret detection
- Dependency vulnerability scanning
- Security misconfiguration scanning in common config files

To run a deep scan:
```bash
./run.sh deep-scan --repo-url <repository-url>
```

## Server Mode

V-Raptor can be run as a server to provide continuous analysis of your code. In this mode, V-Raptor can be used as a pre-commit or pre-push hook to analyze your code before it is committed or pushed to a repository.

To run V-Raptor in server mode, you need to start the webhook server and a worker. The server will listen for requests from your Git hooks, and the worker will process the analysis jobs.

**To start the server:**
```bash
./run.sh start-server
```

**To start a worker:**
```bash
./run.sh start-worker
```

### Git Hook Examples

You can use V-Raptor as a pre-commit or pre-push hook to analyze your code before it is committed or pushed to a repository. Here are some examples of how you can do this.

#### Pre-Commit Hook

This hook will scan the staged files for issues before you commit them.

Create a file named `.git/hooks/pre-commit` in your repository and add the following code:

```bash
#!/bin/bash

# Get the list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

# If there are no staged files, exit
if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Send the staged files to the V-Raptor server for analysis
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"files\": \"$STAGED_FILES\"}" http://localhost:8000/scan)

# If the server returns a non-zero exit code, abort the commit
if [ "$RESPONSE" != "0" ]; then
  echo "V-Raptor found issues in your code. Please fix them before committing."
  exit 1
fi

exit 0
```

Make the hook executable:

```bash
chmod +x .git/hooks/pre-commit
```

#### Pre-Push Hook

This hook will scan the changes you are about to push for issues.

Create a file named `.git/hooks/pre-push` in your repository and add the following code:

```bash
#!/bin/bash

# Get the remote repository URL
REMOTE_URL=$(git config --get remote.origin.url)

# Get the current branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Send the push event to the V-Raptor server for analysis
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"ref\": \"refs/heads/$BRANCH\", \"repository\": {\"clone_url\": \"$REMOTE_URL\"}}" http://localhost:8000/webhook)

# If the server returns a non-zero exit code, abort the push
if [ "$RESPONSE" != "0" ]; then
  echo "V-Raptor found issues in your code. Please fix them before pushing."
  exit 1
fi

exit 0
```

Make the hook executable:

```bash
chmod +x .git/hooks/pre-push
```

### Webhook Mode (Continuous Analysis)

For continuous analysis, V-Raptor can listen for webhook events from your Git provider (e.g., GitHub, GitLab). When a `push` event occurs, V-Raptor will automatically analyze the commit diff for potential vulnerabilities.

This mode requires two components to be running:

1.  **Webhook Server:** This is a lightweight server that listens for incoming webhooks.
2.  **RQ Worker:** This is a background worker that processes the analysis jobs.

**To start the webhook server:**
```bash
./run.sh start-server
```
The server will run on `http://localhost:8000`. You will need to configure your Git repository's webhooks to point to this address.

**To start the RQ worker:**
```bash
./run.sh start-worker
```
The worker will listen for jobs on the Redis queue and execute them.

### Web UI

V-Raptor includes a simple web UI to browse scan results and interact with the system. To start the web server, run:

```bash
./run.sh start-web
```

The web UI will be available at `http://localhost:5000`. From the UI, you can:

- Add and remove repositories.
- Run and re-run scans.
- View scan results and findings.
- Re-check finding results.
- Re-write remediation patches.
- Manually edit and update patches.
