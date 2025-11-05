import os
import json
import tarfile
import tempfile
from datetime import datetime, timedelta
from sqlalchemy.sql import func
from .database import Secret, Repository, Scan, Finding, Patch
from .vcs import VCSService
from .sandbox import SandboxService
from .llm import LLMService
from .config import LLM_PROVIDER
from .database import Scan, Finding, Evidence

from .dependency_scanner import scan_dependencies
from .config_scanner import find_config_files, scan_configuration

class Orchestrator:
    def __init__(self, vcs_service, db_session):
        self.vcs_service = vcs_service
        self.llm_service = LLMService(llm_provider=LLM_PROVIDER)
        self.sandbox_service = SandboxService()
        self.db_session = db_session

    def run_analysis_on_commit(self, repo_url, commit_hash, repo_id):
        """Runs the analysis on a commit."""
        scan = Scan(repository_id=repo_id, triggering_commit_hash=commit_hash, status='running')
        self.db_session.add(scan)
        self.db_session.commit()

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

    def process_vulnerability(self, vulnerability, local_path, repo_url, scan):
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
                        body=f"### V-Raptor Analysis\n\n**Vulnerability:** {vulnerability['description']}\n\n**File:** `{vulnerability['file_path']}`\n\n**Line:** {vulnerability['line_number']}\n\n**Root Cause Analysis:**\n{analysis}\n\nThis patch was automatically generated by V-Raptor based on a confidence score of {confidence_score:.2f}.",
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

    def run_deep_scan(self, repo_url):
        """Runs a deep scan on a repository."""
        repository = self.db_session.query(Repository).filter_by(url=repo_url).first()
        if not repository:
            repository = Repository(name=repo_url.split('/')[-1], url=repo_url)
            self.db_session.add(repository)
            self.db_session.commit()

        local_path = self.vcs_service.clone_repo(repo_url)
        self.detect_secrets(local_path)
        self.run_dependency_scan(local_path, repository.id)
        self.run_config_scan(local_path, repository.id)
        self.check_stale_secrets()

    def run_gitleaks(self, repo_path):
        """Runs gitleaks on a repository inside the sandbox."""
        container_id = self.sandbox_service.create_sandbox()
        if not container_id: return ""
        
        temp_tar_file = None
        try:
            # Create a tarball of the repo
            temp_tar_file = tempfile.NamedTemporaryFile(delete=False, suffix='.tar').name
            with tarfile.open(temp_tar_file, "w") as tar:
                tar.add(repo_path, arcname=os.path.basename(repo_path))
            
            # Copy tarball to container
            with open(temp_tar_file, 'rb') as f:
                self.sandbox_service.put_archive(container_id, '/app', f.read())

            # Run gitleaks
            scan_path = f"/app/{os.path.basename(repo_path)}"
            report_path = "/app/gitleaks-report.json"
            command = f"gitleaks detect --source {scan_path} --report-format json --report-path {report_path} --no-git"
            self.sandbox_service.execute_in_sandbox(container_id, command)

            # Read the report from the container
            output = self.sandbox_service.execute_in_sandbox(container_id, f"cat {report_path}")
            return output
        finally:
            self.sandbox_service.destroy_sandbox(container_id)
            if temp_tar_file and os.path.exists(temp_tar_file):
                os.remove(temp_tar_file)

    def check_stale_secrets(self, days_threshold=30):
        """Checks for secrets that have not been seen in a while."""
        print("\n--- Checking for Stale Secrets ---")
        stale_threshold = datetime.utcnow() - timedelta(days=days_threshold)
        stale_secrets = self.db_session.query(Secret).filter(Secret.last_seen < stale_threshold).all()

        if stale_secrets:
            print(f"Found {len(stale_secrets)} stale secrets (not seen in {days_threshold} days):")
            for secret in stale_secrets:
                print(f"  - Description: {secret.description}")
                print(f"    File: {secret.file_path}")
                print(f"    Last Seen: {secret.last_seen}")
        else:
            print("No stale secrets found.")

    def detect_secrets(self, repo_path):
        """Detects hardcoded secrets in a repository using gitleaks."""
        print("\n--- Detecting Hardcoded Secrets ---")
        output = self.run_gitleaks(repo_path)
        if output:
            try:
                # gitleaks output is a JSON array, but it might be returned as a single string
                leaks = json.loads(output)
                if leaks:
                    print(f"Found {len(leaks)} potential secrets.")
                    for leak in leaks:
                        # Check if the secret already exists in the database
                        existing_secret = self.db_session.query(Secret).filter_by(
                            file_path=leak.get('File'),
                            line_number=leak.get('StartLine'),
                            commit_hash=leak.get('Commit')
                        ).first()

                        if existing_secret:
                            existing_secret.last_seen = func.now()
                        else:
                            new_secret = Secret(
                                file_path=leak.get('File'),
                                line_number=leak.get('StartLine'),
                                commit_hash=leak.get('Commit'),
                                description=leak.get('Description')
                            )
                            self.db_session.add(new_secret)
                        self.db_session.commit()
                else:
                    print("No secrets found by gitleaks.")
            except json.JSONDecodeError:
                print(f"Could not parse gitleaks output. Raw output: {output}")

    def check_stale_secrets(self, days_threshold=30):
        """Checks for secrets that have not been seen in a while."""
        print("\n--- Checking for Stale Secrets ---")
        stale_threshold = datetime.utcnow() - timedelta(days=days_threshold)
        stale_secrets = self.db_session.query(Secret).filter(Secret.last_seen < stale_threshold).all()

        if stale_secrets:
            print(f"Found {len(stale_secrets)} stale secrets (not seen in {days_threshold} days):")
            for secret in stale_secrets:
                print(f"  - Description: {secret.description}")
                print(f"    File: {secret.file_path}")
                print(f"    Last Seen: {secret.last_seen}")
        else:
            print("No stale secrets found.")

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
                finding = Finding(
                    scan_id=scan.id,
                    description=vuln['summary'],
                    severity=vuln['severity'],
                    # Other fields like file_path and line_number might not be applicable for dependency scans
                )
                self.db_session.add(finding)
                print(f"  - ID: {vuln['id']}")
                print(f"    Package: {vuln['package']}")
                print(f"    Summary: {vuln['summary']}")
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