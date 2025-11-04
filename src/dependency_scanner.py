import subprocess
import json
import os

def scan_dependencies(path):
    """Scans a given path for dependencies and checks for vulnerabilities using OSV-Scanner."""
    print(f"--- Scanning dependencies in {path} ---")
    # Use --format=json to get structured output
    # The scanner can scan directories and will find relevant lockfiles
    command = ["osv-scanner", "--format=json", path]
    
    try:
        # We run this in the sandbox for security, but for now, let's run it directly
        # In a real implementation, this would be a call to the SandboxService
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        raw_output = result.stdout
    except FileNotFoundError:
        print("Error: 'osv-scanner' command not found. Make sure it is installed and in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        # OSV-Scanner exits with a non-zero code if vulnerabilities are found.
        # We need to parse the output even in that case.
        raw_output = e.stdout
        if not raw_output:
            print(f"Error running OSV-Scanner: {e}")
            print(f"Stderr: {e.stderr}")
            return []

    try:
        # The JSON output is a stream of JSON objects, one per line.
        # We need to handle this by splitting lines and parsing each one.
        # For simplicity, let's assume the primary results are in a structured format.
        # A more robust implementation would parse the JSON stream correctly.
        data = json.loads(raw_output)
        vulnerabilities = []
        if 'results' in data:
            for result_group in data['results']:
                if 'vulns' in result_group:
                    for vuln in result_group['vulns']:
                        vulnerabilities.append({
                            "id": vuln.get('id'),
                            "package": result_group.get('package', {}).get('name'),
                            "version": result_group.get('package', {}).get('version'),
                            "summary": vuln.get('summary', 'No summary available.'),
                            "details": vuln.get('details', 'No details available.')
                        })
        return vulnerabilities
    except json.JSONDecodeError:
        print(f"Could not parse OSV-Scanner JSON output. Raw output:\n{raw_output}")
        return []

if __name__ == '__main__':
    # Example usage: Clone a repo and scan it
    # This requires git to be installed.
    repo_url = "https://github.com/pallets/flask"
    temp_dir = "temp_flask_repo"
    if not os.path.exists(temp_dir):
        subprocess.run(["git", "clone", repo_url, temp_dir])
    
    vulns = scan_dependencies(temp_dir)
    if vulns:
        print(f"\nFound {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - ID: {v['id']}")
            print(f"    Package: {v['package']}")
            print(f"    Summary: {v['summary']}")
    else:
        print("\nNo vulnerabilities found.")
