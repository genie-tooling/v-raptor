# V-Raptor

V-Raptor is an AI agent for automated code analysis, bug detection, and remediation.

## Features

- **Automated Code Analysis:** Analyzes code for security vulnerabilities, bugs, and code quality problems.
- **Automated Remediation:** Generates patches for detected vulnerabilities and bugs.
- **Manual and Deep Scans:** Perform deep scans of repositories to find hidden vulnerabilities and secrets, or trigger scans manually from the web UI.
- **Dependency and Configuration Scanning:** Scans dependencies for known vulnerabilities and configuration files for security misconfigurations.
- **Webhook Support:** Continuously analyze code by listening for webhook events from your Git provider.
- **Web UI:** A simple web UI to browse scan results, manage repositories, and configure the application.

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
./run.sh
```

Also initialize the DB:
```
./run.sh --init-db
```

## Usage

V-Raptor can be used in several ways:

### Web UI

The easiest way to use V-Raptor is through the web UI.

1. Start the web server:

```
./run.sh start-web
```

2. Open your browser and go to `http://localhost:5000`.

From the web UI, you can:
- Add and remove repositories.
- Run and re-run scans.
- View scan results and findings.
- Configure the application.

### Command Line

You can also run scans from the command line.

To run a deep scan of a repository:

```
./run.sh --scan-url <repository-url>
```

To scan a specific commit:

```
./run.sh --scan-url <repository-url> --scan-commit <commit-hash>
```

## Configuration

All configuration is done through the web UI. Go to the "Configuration" page to set up your API keys and other settings.

## Advanced Usage

For more advanced usage, including server mode, git hooks, and webhooks, see the [Advanced Usage](docs/advanced_usage.md) documentation.
