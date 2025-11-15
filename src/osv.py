import requests

OSV_API_URL = "https://api.osv.dev/v1/query"

def make_osv_request(query: dict) -> dict:
    """Makes a request to the OSV API."""
    response = requests.post(OSV_API_URL, json=query, timeout=60)
    response.raise_for_status()
    return response.json()

def get_vulns_for_package(package_name: str, version: str = None) -> dict:
    """Gets vulnerabilities for a given package and version."""
    query = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI" # Assuming PyPI for now, this will need to be improved
        }
    }
    if version:
        query["version"] = version
    
    return make_osv_request(query)

def get_vulns_for_commit(commit_hash: str) -> dict:
    """Gets vulnerabilities for a given commit hash."""
    query = {
        "commit": commit_hash
    }
    return make_osv_request(query)
