# Advanced Usage

This guide covers advanced V-Raptor features, including running local scans from the command line, using it in Git pre-commit hooks, and running it as a server for continuous analysis.

## CLI Scanning

V-Raptor's command-line interface (CLI) is a powerful tool for developers who want to integrate security scanning into their local development workflow. It allows you to scan your code without needing to run a web server.

### Local Repository Scanning

You can scan a local Git repository directly from the command line. This is useful for running scans on your local machine without pushing your code to a remote repository. It's also the foundation for integrating V-Raptor into your Git hooks.

To scan a local repository, use the `--scan-local` flag and provide the path to your repository:

```bash
./run.sh --scan-local /path/to/your/repo
```

You can also run it from within the repository's directory:

```bash
./run.sh --scan-local .
```

This command will perform a deep scan on your local repository, which includes:
- SAST scanning with Semgrep and Bandit
- Intelligent CVE scanning
- Source code analysis with an LLM
- Secret scanning with Gitleaks
- Dependency scanning
- Configuration scanning
- Code quality analysis

### JSON Output

For programmatic use, such as in scripts or CI/CD pipelines, you can get the scan results in JSON format using the `--output-json` flag.

```bash
./run.sh --scan-local . --output-json
```

This will output a JSON array of all the findings from the scan.

**Example JSON Output:**

```json
[
    {
        "id": 1,
        "scan_id": 1,
        "file_path": "src/server.py",
        "line_number": 42,
        "code_snippet": "app.run(debug=True)",
        "description": "Running a Flask app in debug mode is insecure.",
        "severity": "High",
        "confidence_score": 0.9,
        "status": "new",
        "cve_id": null
    }
]
```

You can use tools like `jq` to process this output. For example, to count the number of high-severity findings:

```bash
./run.sh --scan-local . --output-json | jq '[.[] | select(.severity == "High")] | length'
```

## Git Pre-commit Hook

You can use V-Raptor as a pre-commit hook to analyze your code before it's committed. This helps catch vulnerabilities early in the development process.

The following script will run a local scan on your repository and fail the commit if any findings are detected.

**1. Create the pre-commit hook file:**

Create a file named `.git/hooks/pre-commit` in your repository.

**2. Add the script to the file:**

```bash
#!/bin/bash

# Path to your v-raptor project
VRAPTOR_PATH="/path/to/your/v-raptor"

echo "Running V-Raptor pre-commit hook..."

# Run the scan and capture the JSON output
# Make sure your v-raptor environment is set up correctly (e.g., virtualenv)
output=$($VRAPTOR_PATH/run.sh --scan-local . --output-json)

# Check if the output is empty or not a valid JSON
if [ -z "$output" ] || ! echo "$output" | jq . > /dev/null 2>&1; then
  echo "V-Raptor scan did not produce valid JSON output. Allowing commit."
  exit 0
fi

# Count the number of findings
finding_count=$(echo "$output" | jq 'length')

if [ "$finding_count" -gt 0 ]; then
  echo "V-Raptor found $finding_count issues in your code. Please fix them before committing."
  echo "$output" | jq .
  exit 1
else
  echo "No issues found by V-Raptor."
fi

exit 0
```

**Important:** Replace `/path/to/your/v-raptor` with the actual absolute path to your V-Raptor installation.

**3. Make the hook executable:**

```bash
chmod +x .git/hooks/pre-commit
```

Now, every time you run `git commit`, this hook will execute, scan your code, and prevent the commit if any issues are found.

## Server Mode (Continuous Analysis)

For continuous analysis, V-Raptor can listen for webhook events from your Git provider (e.g., GitHub, GitLab). When a `push` event occurs, V-Raptor will automatically analyze the commit diff for potential vulnerabilities.

This mode requires two components to be running:

1.  **Web Server:** This is a Flask-based web application that provides the web UI and the webhook endpoint.
2.  **RQ Worker:** This is a background worker that processes the analysis jobs.

**To start the web server:**
```bash
./run.sh --start-web
```
The server will run on `http://localhost:5000`. You will need to configure your Git repository's webhooks to point to this address (e.g., `http://your-server-ip:5000/webhook`).

**To start the RQ worker:**
```bash
./run.sh --start-worker
```
The worker will listen for jobs on the Redis queue and execute them.

You can also use Docker Compose to run all the services together:

```bash

docker-compose up --build

```



## CI/CD Integration



You can trigger scans from your CI/CD pipeline (e.g., Jenkins, GitLab CI, GitHub Actions) by calling the `/ci/scan` API endpoint.



This endpoint accepts a POST request with a JSON payload containing the `repo_url` and an optional `commit_hash`.



- If `commit_hash` is provided, V-Raptor will scan that specific commit.

- If `commit_hash` is not provided, V-Raptor will automatically scan the latest commit of the repository's primary branch.



**Example `curl` command:**



To scan the latest commit:

```bash

curl -X POST -H "Content-Type: application/json" \

  -d '{"repo_url": "https://github.com/your-username/your-repo.git"}' \

  http://localhost:5000/ci/scan

```



To scan a specific commit:

```bash

curl -X POST -H "Content-Type: application/json" \

  -d '{"repo_url": "https://github.com/your-username/your-repo.git", "commit_hash": "your-commit-hash"}' \

  http://localhost:5000/ci/scan

```



**Success Response:**

```json

{

  "status": "success",

  "message": "Scan initiated for https://github.com/your-username/your-repo.git at commit your-commit-hash."

}

```



**Failure Response:**

```json

{

  "status": "failure",

  "message": "Could not get latest commit hash for https://github.com/your-username/your-repo.git."

}

```
