import re

SECRETS_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "HIGH"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r"aws", re.IGNORECASE),
        "severity": "HIGH"
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "severity": "HIGH"
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        "severity": "HIGH"
    },
    {
        "name": "RSA Private Key",
        "pattern": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "severity": "CRITICAL"
    }
]

def scan_for_secrets(file_path, file_content):
    """
    Scans a file for secrets.

    Args:
        file_path (str): The path to the file.
        file_content (str): The content of the file.

    Returns:
        list: A list of findings.
    """
    findings = []
    for line_number, line in enumerate(file_content.splitlines(), 1):
        for secret in SECRETS_PATTERNS:
            if secret["pattern"].search(line):
                findings.append({
                    "file_path": file_path,
                    "line": line_number,
                    "type": "secret",
                    "name": secret["name"],
                    "severity": secret["severity"],
                    "description": f"Potential {secret['name']} found.",
                })
    return findings