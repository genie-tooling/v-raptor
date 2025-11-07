# Advanced Usage

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
