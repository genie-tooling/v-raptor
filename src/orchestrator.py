import os
import json
import re
import subprocess
import tarfile
import tempfile
from datetime import datetime, timedelta
from sqlalchemy.sql import func
from .database import Repository, Scan, Finding, Patch, ChatMessage, Evidence, QualityMetric
from .vcs import VCSService
from .sandbox import SandboxService
from .llm import LLMService
from .config import LLM_PROVIDER
from .dependency_scanner import scan_dependencies
from .config_scanner import find_config_files, scan_configuration
from .secret_scanner import scan_for_secrets
from .quality_scanner import get_cyclomatic_complexity, get_code_churn

from . import di

class Orchestrator:
    def __init__(self, vcs_service, db_session, google_web_search):
        self.vcs_service = vcs_service
        self.llm_service = LLMService(llm_provider=LLM_PROVIDER)
        self.sandbox_service = SandboxService()
        self.db_session = db_session
        self.google_web_search = google_web_search

    def run_analysis_on_commit(self, repo_url, commit_hash, repo_id, wait_for_completion=False):
        """Runs the analysis on a commit."""
        scan = Scan(repository_id=repo_id, triggering_commit_hash=commit_hash, status='running')
        self.db_session.add(scan)
        self.db_session.commit()

        if wait_for_completion:
            self._run_analysis_on_commit_sync(repo_url, commit_hash, scan)
            return scan
        else:
            # Here you would enqueue the task for a background worker
            # For simplicity, we will run it synchronously for now
            self._run_analysis_on_commit_sync(repo_url, commit_hash, scan)
            return scan

    def _run_analysis_on_commit_sync(self, repo_url, commit_hash, scan):
        local_path = self.vcs_service.clone_repo(repo_url)
        diff = self.vcs_service.get_commit_diff(local_path, commit_hash)

        if not diff:
            print("Could not get diff or diff is empty.")
            scan.status = 'completed'
            self.db_session.commit()
            return

        print(f"--- Analyzing Diff for commit {commit_hash[:7]} ---")
        response_text = self.llm_service.analyze_diff_with_tools(diff)

        try:
            data = json.loads(response_text)
            vulnerabilities = data.get("vulnerabilities", [])
        except json.JSONDecodeError:
            print("Error: Could not decode LLM response as JSON.")
            vulnerabilities = []

        if not vulnerabilities:
            print("No vulnerabilities identified by initial scan.")
            scan.status = 'completed'
            self.db_session.commit()
            return

        for vulnerability in vulnerabilities:
            self.process_vulnerability(vulnerability, local_path, repo_url, scan)

        scan.status = 'completed'
        self.db_session.commit()

    def validate_vulnerability_with_search(self, vulnerability):
        """Validates a vulnerability by searching for it on the web."""
        if not self.google_web_search:
            print("--- Web search validation skipped: search function not provided. ---")
            return True
        print(f"\n--- Validating Vulnerability: {vulnerability['description']} ---")
        search_query = f"{vulnerability['description']} {vulnerability['code_snippet']}"
        search_results = self.google_web_search(query=search_query)

        if not search_results:
            return True # If search fails, proceed with the vulnerability

        response_text = self.llm_service.validate_vulnerability(vulnerability['description'], search_results)
        try:
            data = json.loads(response_text)
            if data.get("false_positive"):
                print("Vulnerability identified as a false positive.")
                return False
        except json.JSONDecodeError:
            print("Error: Could not decode LLM response as JSON.")
        
        return True

    def process_vulnerability(self, vulnerability, local_path, repo_url, scan):
        if not self.validate_vulnerability_with_search(vulnerability):
            return

        print(f"\n+++ Potential Vulnerability Found: {vulnerability['description']} +++")
        print(f"File: {vulnerability['file_path']}, Line: {vulnerability['line_number']}")

        finding = Finding(
            scan_id=scan.id,
            file_path=vulnerability['file_path'],
            line_number=vulnerability['line_number'],
            code_snippet=vulnerability['code_snippet'],
            description=vulnerability['description'],
        )
        self.db_session.add(finding)
        self.db_session.commit()

        analysis = self.llm_service.get_root_cause_analysis(
            vulnerability['code_snippet'], vulnerability['description']
        )
        print("\n--- Root Cause Analysis ---")
        print(analysis)

        evidence_analysis = Evidence(finding_id=finding.id, type='root_cause_analysis', content=analysis)
        self.db_session.add(evidence_analysis)
        self.db_session.commit()

        test_script = self.llm_service.generate_test_script(
            vulnerability['code_snippet'], vulnerability['description']
        )
        print("\n--- Generated Test Script ---")
        print(test_script)

        evidence_test_script = Evidence(finding_id=finding.id, type='test_script', content=test_script)
        self.db_session.add(evidence_test_script)
        self.db_session.commit()

        container_id = self.sandbox_service.create_sandbox()
        if not container_id:
            return

        try:
            output = self.sandbox_service.execute_python_script(container_id, test_script)
            print("\n--- Test Script Output ---")
            print(output)

            evidence_test_output = Evidence(finding_id=finding.id, type='test_output', content=output)
            self.db_session.add(evidence_test_output)
            self.db_session.commit()

            confidence_score = self.llm_service.interpret_results(analysis, test_script, output)
            print(f"\nConfidence Score: {confidence_score}")
            finding.confidence_score = confidence_score
            self.db_session.commit()


            if confidence_score > 0.7:
                print("\nHigh confidence score. Generating patch...")
                patch_diff = self.llm_service.generate_patch(vulnerability['code_snippet'], analysis)
                print("\n--- Generated Patch ---")
                print(patch_diff)

                if patch_diff:
                    patch = Patch(finding_id=finding.id, generated_patch_diff=patch_diff)
                    self.db_session.add(patch)
                    self.db_session.commit()

                    self.vcs_service.create_pull_request(
                        repo_path=local_path,
                        repo_url=repo_url,
                        branch_name=f'v-raptor-fix/{os.path.basename(vulnerability["file_path"]).replace(".","_")}-{vulnerability["line_number"]}',
                        title=f'Fix: {vulnerability["description"]}',
                        body=f"""### V-Raptor Analysis\n
**Vulnerability:** {vulnerability['description']}\n
**File:** `{vulnerability['file_path']}`\n
**Line:** {vulnerability['line_number']}\n
**Root Cause Analysis:**\n{analysis}\n
This patch was automatically generated by V-Raptor based on a confidence score of {confidence_score:.2f}.""",
                        patch_diff=patch_diff
                    )
                else:
                    print("Patch generation failed or returned empty.")
            else:
                print("Confidence score is too low, skipping patch generation.")
        finally:
            self.sandbox_service.destroy_sandbox(container_id)

    def rewrite_remediation(self, finding_id):
        """Re-writes a remediation for a finding."""
        finding = self.db_session.query(Finding).get(finding_id)
        if not finding:
            return

        analysis_evidence = self.db_session.query(Evidence).filter_by(finding_id=finding.id, type='root_cause_analysis').first()
        analysis = analysis_evidence.content if analysis_evidence else ''

        patch_diff = self.llm_service.generate_patch(finding.code_snippet, analysis)
        print("\n--- Generated Patch ---")
        print(patch_diff)

        if patch_diff:
            patch = self.db_session.query(Patch).filter_by(finding_id=finding.id).first()
            if not patch:
                patch = Patch(finding_id=finding.id)
                self.db_session.add(patch)
            patch.generated_patch_diff = patch_diff
            self.db_session.commit()

    def recheck_finding(self, finding_id):
        """Re-checks a finding by re-running the test script."""
        finding = self.db_session.query(Finding).get(finding_id)
        if not finding:
            return

        test_script_evidence = self.db_session.query(Evidence).filter_by(finding_id=finding.id, type='test_script').first()
        if not test_script_evidence:
            return

        container_id = self.sandbox_service.create_sandbox()
        if not container_id:
            return

        try:
            output = self.sandbox_service.execute_python_script(container_id, test_script_evidence.content)
            print("\n--- Test Script Output ---")
            print(output)

            evidence_test_output = self.db_session.query(Evidence).filter_by(finding_id=finding.id, type='test_output').first()
            if not evidence_test_output:
                evidence_test_output = Evidence(finding_id=finding.id, type='test_output')
                self.db_session.add(evidence_test_output)
            evidence_test_output.content = output
            self.db_session.commit()

            analysis_evidence = self.db_session.query(Evidence).filter_by(finding_id=finding.id, type='root_cause_analysis').first()
            analysis = analysis_evidence.content if analysis_evidence else ''

            confidence_score = self.llm_service.interpret_results(analysis, test_script_evidence.content, output)
            print(f"\nConfidence Score: {confidence_score}")
            finding.confidence_score = confidence_score
            self.db_session.commit()
        finally:
            self.sandbox_service.destroy_sandbox(container_id)

    def run_source_code_scan(self, repo_path, repo_id):
        """Runs a source code scan on a repository."""
        print("\n--- Running Source Code Scan ---")
        scan = Scan(repository_id=repo_id, scan_type='source', status='running')
        self.db_session.add(scan)
        self.db_session.commit()

        for root, _, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Simple check to avoid scanning binary files
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        f.read(1024) # Try to read the first 1KB
                except (UnicodeDecodeError, IsADirectoryError):
                    continue

                print(f"Scanning {file_path}")
                response_text = self.llm_service.analyze_file(file_path)
                try:
                    data = json.loads(response_text)
                    vulnerabilities = data.get("vulnerabilities", [])
                except json.JSONDecodeError:
                    print(f"Error: Could not decode LLM response for {file_path} as JSON.")
                    vulnerabilities = []

                for vulnerability in vulnerabilities:
                    self.process_vulnerability(vulnerability, repo_path, scan.repository.url, scan)

        scan.status = 'completed'
        self.db_session.commit()

    def run_deep_scan(self, repo_url):
        """Runs a deep scan on a repository."""
        repository = self.db_session.query(Repository).filter_by(url=repo_url).first()
        if not repository:
            repository = Repository(name=repo_url.split('/')[-1], url=repo_url)
            self.db_session.add(repository)
            self.db_session.commit()

        local_path = self.vcs_service.clone_repo(repo_url, branch=repository.primary_branch)
        self.run_source_code_scan(local_path, repository.id)
        self.run_secret_scan(local_path, repository.id)
        self.run_dependency_scan(local_path, repository.id)
        self.run_config_scan(local_path, repository.id)
        self.run_quality_scan(local_path, repository.id)

    def run_secret_scan(self, repo_path, repo_id):
        """Runs a secret scan on a repository."""
        print("\n--- Running Secret Scan ---")
        scan = Scan(repository_id=repo_id, scan_type='secret', status='running')
        self.db_session.add(scan)
        self.db_session.commit()

        for root, _, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except (UnicodeDecodeError, IsADirectoryError):
                    continue

                findings = scan_for_secrets(file_path, content)
                for finding in findings:
                    new_finding = Finding(
                        scan_id=scan.id,
                        file_path=finding['file_path'],
                        line_number=finding['line'],
                        description=finding['description'],
                        severity=finding['severity'],
                        code_snippet=content.splitlines()[finding['line']-1]
                    )
                    self.db_session.add(new_finding)
        
        scan.status = 'completed'
        self.db_session.commit()

    def run_quality_scan(self, repo_path, repo_id):
        """Runs a quality scan on a repository."""
        print("\n--- Running Quality Scan ---")
        scan = Scan(repository_id=repo_id, scan_type='quality', status='running')
        self.db_session.add(scan)
        self.db_session.commit()

        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    complexity = get_cyclomatic_complexity(file_path)
                    churn = get_code_churn(file_path)

                    quality_metric = QualityMetric(
                        scan_id=scan.id,
                        file_path=file_path,
                        cyclomatic_complexity=complexity,
                        code_churn=churn
                    )
                    self.db_session.add(quality_metric)
        
        scan.status = 'completed'
        self.db_session.commit()

    def search_for_cve(self, package_name, version):
        """Searches for a CVE for a given package and version."""
        print(f"\n--- Searching for CVE for {package_name} {version} ---")
        search_query = f"{package_name} {version} vulnerability"
        search_results = self.google_web_search(query=search_query)

        if not search_results:
            return None

        # Simple regex to find CVE IDs
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', search_results)
        if cve_match:
            return cve_match.group(0)
        
        return None

    def run_dependency_scan(self, repo_path, repo_id):
        """Runs a dependency scan on a repository."""
        print("\n--- Running Dependency Scan ---")
        scan = Scan(repository_id=repo_id, scan_type='dependency', status='running')
        self.db_session.add(scan)
        self.db_session.commit()

        vulnerabilities = scan_dependencies(repo_path)
        if vulnerabilities:
            print(f"Found {len(vulnerabilities)} vulnerabilities in dependencies:")
            for vuln in vulnerabilities:
                cve_id = self.search_for_cve(vuln['package'], vuln['version'])
                finding = Finding(
                    scan_id=scan.id,
                    description=vuln['summary'],
                    severity=vuln.get('severity', 'UNKNOWN'),
                    cve_id=cve_id,
                    # Other fields like file_path and line_number might not be applicable for dependency scans
                )
                self.db_session.add(finding)
                print(f"  - ID: {vuln['id']}")
                print(f"    Package: {vuln['package']}")
                print(f"    Summary: {vuln['summary']}")
                if cve_id:
                    print(f"    CVE: {cve_id}")
            
            # Automatically remediate vulnerabilities
            print("\n--- Automatically Remediating Dependencies ---")
            try:
                subprocess.run(["osv-scanner", "fix", repo_path], check=True)
                print("Dependencies remediated successfully.")

                # Create a pull request with the changes
                self.vcs_service.create_pull_request(
                    repo_path=repo_path,
                    repo_url=scan.repository.url,
                    branch_name='v-raptor-remediate-dependencies',
                    title='Fix: Remediate dependency vulnerabilities',
                    body='This pull request was automatically generated by V-Raptor to remediate dependency vulnerabilities.',
                    patch_diff=self.vcs_service.get_commit_diff(repo_path, 'HEAD')
                )

            except subprocess.CalledProcessError as e:
                print(f"Error running OSV-Scanner fix: {e}")
                print(f"Stderr: {e.stderr}")

        else:
            print("No dependency vulnerabilities found.")
        
        scan.status = 'completed'
        self.db_session.commit()

    def run_config_scan(self, repo_path, repo_id):
        """Runs a configuration scan on a repository."""
        print("\n--- Running Configuration Scan ---")
        scan = Scan(repository_id=repo_id, scan_type='configuration', status='running')
        self.db_session.add(scan)
        self.db_session.commit()

        config_files = find_config_files(repo_path)
        if not config_files:
            print("No configuration files found.")
            scan.status = 'completed'
            self.db_session.commit()
            return

        total_misconfigs = 0
        for file_path in config_files:
            misconfigs = scan_configuration(file_path, self.llm_service)
            if misconfigs:
                total_misconfigs += len(misconfigs)
                print(f"Found {len(misconfigs)} misconfigurations in {file_path}:")
                for misconfig in misconfigs:
                    finding = Finding(
                        scan_id=scan.id,
                        file_path=file_path,
                        line_number=misconfig.get('line_number'),
                        description=misconfig.get('description'),
                    )
                    self.db_session.add(finding)
                    print(f"  - Line: {misconfig.get('line_number')}, Description: {misconfig.get('description')}")
        
        if total_misconfigs == 0:
            print("No configuration misconfigurations found.")

        scan.status = 'completed'
        self.db_session.commit()

    def get_dashboard_metrics(self):
        """Gets metrics for the dashboard."""
        total_repos = self.db_session.query(Repository).count()
        total_scans = self.db_session.query(Scan).count()
        total_findings = self.db_session.query(Finding).count()

        return {
            'total_repos': total_repos,
            'total_scans': total_scans,
            'total_findings': total_findings
        }

    def chat_with_finding(self, finding_id, message):
        """Chats with a finding."""
        finding = self.db_session.query(Finding).get(finding_id)
        if not finding:
            return "Finding not found."

        # Store user message
        user_message = ChatMessage(finding_id=finding_id, message=message, sender='user')
        self.db_session.add(user_message)
        self.db_session.commit()

        history = self.db_session.query(ChatMessage).filter_by(finding_id=finding_id).order_by(ChatMessage.created_at).all()

        prompt = f"""You are a senior security engineer. You are chatting with a developer about the following vulnerability:

Description: {finding.description}
File: {finding.file_path}
Line: {finding.line_number}
Code Snippet:
```
{finding.code_snippet}
```

Here is the chat history:
"""
        for msg in history:
            prompt += f"{msg.sender}: {msg.message}\n"

        prompt += "\nProvide a concise and helpful response to the last message from the user. Do not ask any questions."

        response = self.llm_service._create_chat_completion(prompt, is_json=False)

        # Store assistant message
        assistant_message = ChatMessage(finding_id=finding_id, message=response, sender='assistant')
        self.db_session.add(assistant_message)
        self.db_session.commit()

        return response