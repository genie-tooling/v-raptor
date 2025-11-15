import json
import logging
from .database import Scan, Finding, ScanStatus
from .llm import LLMService
from .osv import get_vulns_for_package


class CveLinker:
    def __init__(self, db_session, llm_service: LLMService):
        self.db_session = db_session
        self.llm_service = llm_service

    def link_cves_to_findings(self, repo_id, scan_id):
        """Runs a CVE scan on a repository."""
        scan = self.db_session.query(Scan).get(scan_id)
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            findings = self.db_session.query(Finding).join(Scan).filter(Scan.repository_id == repo_id, Finding.cve_id == None).all()
            for finding in findings:
                self.search_cve_for_finding(finding)
            scan.status = ScanStatus.COMPLETED
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            self.db_session.commit()
            logging.info(f"Error during CVE scan of repo {repo_id}: {e}")

    def search_cve_for_finding(self, finding):
        """Searches for a CVE for a given finding."""
        prompt = f"""Based on the following vulnerability description, what is the package name?

Description:
{finding.description}

Respond with a JSON object containing the package name.

Example response:
```json
{{
  "package_name": "requests"
}}
```

If no package name is found, respond with an empty JSON object: {{}}.
"""
        response = self.llm_service._create_chat_completion(self.llm_service.scanner_client, self.llm_service._get_model_name('scanner'), prompt, is_json=True)
        
        try:
            data = json.loads(response)
            package_name = data.get('package_name')

            if package_name:
                vulns = get_vulns_for_package(package_name)
                if vulns and 'vulns' in vulns and len(vulns['vulns']) == 1:
                    cve_id = vulns['vulns'][0]['id']
                    finding.cve_id = cve_id
                    self.db_session.commit()
                    logging.info(f"Found CVE: {cve_id} for finding #{finding.id}")
        except json.JSONDecodeError:
            logging.info("Error: Could not decode LLM response as JSON.")
