import os
import json
import logging
from .database import Repository, Scan, ScanStatus
from .sandbox import SandboxService
from .llm import LLMService
from .vulnerability_processor import VulnerabilityProcessor
from .scanner import Scanner
from .cve_linker import CveLinker
from .dashboard import Dashboard
from .chat_service import ChatService


class Orchestrator:
    VERSION = "1.1"
    def __init__(self, vcs_service, db_session, google_web_search, llm_service=None):
        logging.info(f"--- Orchestrator class reloaded (version: {self.VERSION}) ---")
        self.vcs_service = vcs_service
        if llm_service:
            self.llm_service = llm_service
        else:
            try:
                # Add logging around the potentially failing part
                logging.info("Orchestrator: Initializing LLMService...")
                self.llm_service = LLMService()
                logging.info("Orchestrator: LLMService initialized successfully.")
            except Exception as e:
                logging.error(f"Orchestrator: Failed to initialize LLMService: {e}", exc_info=True)
                # Re-raise the exception so the calling function knows something went wrong
                raise e
            
        self.sandbox_service = SandboxService()
        self.db_session = db_session
        self.google_web_search = google_web_search
        self.vulnerability_processor = VulnerabilityProcessor(db_session, self.llm_service, self.sandbox_service, self.vcs_service, self.google_web_search)
        self.scanner = Scanner(db_session, self.llm_service, self.vulnerability_processor)
        self.cve_linker = CveLinker(db_session, self.llm_service)
        self.dashboard = Dashboard(db_session)
        self.chat_service = ChatService(db_session, self.llm_service, self.vcs_service)

    def _calculate_total_progress(self, local_path, include_tests=False):
        """Calculates the total progress for a deep scan."""
        total_progress = 0
        total_progress += len(self.scanner.get_sast_files(local_path, include_tests))
        total_progress += len(self.scanner.get_source_code_files(local_path, include_tests))
        total_progress += len(self.scanner.get_secret_files(local_path))
        total_progress += len(self.scanner.get_config_files(local_path))
        total_progress += len(self.scanner.get_quality_files(local_path))
        total_progress += 1 # for intelligent CVE scan
        total_progress += 1 # for dependency scan
        return total_progress

    def run_analysis_on_commit(self, repo_url, commit_hash, repo_id, auto_patch=False, wait_for_completion=False):
        """Runs the analysis on a commit."""
        scan = Scan(repository_id=repo_id, triggering_commit_hash=commit_hash, status='queued', auto_patch_enabled=auto_patch)
        self.db_session.add(scan)
        self.db_session.commit()

        if wait_for_completion:
            self._run_analysis_on_commit_sync(repo_url, commit_hash, scan, auto_patch=auto_patch)
            return scan
        else:
            # In a real-world scenario, this would be handled by a background worker
            self._run_analysis_on_commit_sync(repo_url, commit_hash, scan, auto_patch=auto_patch)
            return scan

    def _run_analysis_on_commit_sync(self, repo_url, commit_hash, scan, auto_patch=False):
        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            local_path = self.vcs_service.clone_repo(repo_url)
            diff = self.vcs_service.get_commit_diff(local_path, commit_hash)

            if not diff:
                logging.info("Could not get diff or diff is empty.")
                scan.status = ScanStatus.COMPLETED
                self.db_session.commit()
                return

            logging.info(f"--- Analyzing Diff for commit {commit_hash[:7]} ---")
            response_text = self.llm_service.analyze_diff_with_tools(diff)

            try:
                data = json.loads(response_text)
                vulnerabilities = data.get("vulnerabilities", [])
            except json.JSONDecodeError:
                logging.info("Error: Could not decode LLM response as JSON.")
                vulnerabilities = []

            if not vulnerabilities:
                logging.info("No vulnerabilities identified by initial scan.")
                ScanStatus.COMPLETED
                self.db_session.commit()
                return

            for vulnerability in vulnerabilities:
                self.vulnerability_processor.process_vulnerability(vulnerability, local_path, repo_url, scan, auto_patch=auto_patch)

            scan.status = ScanStatus.COMPLETED
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.status_message = f"Error during analysis: {e}"
            self.db_session.commit()
            logging.info(f"Error during analysis of commit {commit_hash}: {e}")

    def run_deep_scan(self, repo_url, scan_id, auto_patch=False, include_tests=False, branch=None):
        """Runs a deep scan on a repository."""
        scan = self.db_session.query(Scan).get(scan_id)
        if not scan:
            logging.error(f"Scan with id {scan_id} not found.")
            return

        repository = scan.repository
        
        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            scan.status_message = "Cloning repository..."
            self.db_session.commit()
            local_path = self.vcs_service.clone_repo(repo_url, branch=branch or repository.primary_branch)
            
            # TODO: Add a database migration to add the progress and total_progress columns to the scan table
            scan.total_progress = self._calculate_total_progress(local_path, include_tests)
            self.db_session.commit()

            logging.info("Starting SAST scan...")
            self.scanner.run_sast_scan(local_path, scan, include_tests=include_tests)
            logging.info("SAST scan finished.")

            logging.info("Starting intelligent CVE scan...")
            self.scanner.run_intelligent_cve_scan(local_path, scan)
            logging.info("Intelligent CVE scan finished.")

            logging.info("Starting source code scan...")
            self.scanner.run_source_code_scan(scan, local_path, auto_patch=auto_patch, include_tests=include_tests)
            logging.info("Source code scan finished.")

            logging.info("Starting secret scan...")
            self.scanner.run_secret_scan(local_path, scan)
            logging.info("Secret scan finished.")

            logging.info("Starting dependency scan...")
            self.scanner.run_dependency_scan(local_path, scan)
            logging.info("Dependency scan finished.")

            logging.info("Starting config scan...")
            self.scanner.run_config_scan(local_path, scan)
            logging.info("Config scan finished.")

            logging.info("Starting quality scan...")
            self.scanner.run_quality_scan(local_path, scan)
            logging.info("Quality scan finished.")

            scan.status = ScanStatus.COMPLETED
            scan.status_message = "Completed"
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.status_message = f"Error during deep scan: {e}"
            self.db_session.commit()
            logging.error(f"Error during deep scan of {repo_url}: {e}", exc_info=True)

    def run_local_scan(self, repo_path, auto_patch=False):
        """Runs a deep scan on a local repository."""
        repo_name = os.path.basename(os.path.abspath(repo_path))
        repository = self.db_session.query(Repository).filter_by(url=repo_path).first()
        if not repository:
            # For local repos, we can't easily determine the primary branch without more git commands.
            # We'll leave it as None for now.
            repository = Repository(name=repo_name, url=repo_path, primary_branch=None)
            self.db_session.add(repository)
            self.db_session.commit()

        scan = Scan(repository_id=repository.id, scan_type='deep', status='queued', auto_patch_enabled=auto_patch)
        self.db_session.add(scan)
        self.db_session.commit()

        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            scan.status_message = "Starting local scan..."
            self.db_session.commit()
            # For a local scan, the repo_path is the local_path. No need to clone.
            self.scanner.run_sast_scan(repo_path, scan)
            self.scanner.run_intelligent_cve_scan(repo_path, scan)
            self.scanner.run_source_code_scan(repo_path, scan, auto_patch=auto_patch)
            self.scanner.run_secret_scan(repo_path, scan)
            self.scanner.run_dependency_scan(repo_path, scan)
            self.scanner.run_config_scan(repo_path, scan)
            self.scanner.run_quality_scan(repo_path, scan)
            scan.status = ScanStatus.COMPLETED
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.status_message = f"Error during local scan: {e}"
            self.db_session.commit()
            logging.info(f"Error during local scan of {repo_path}: {e}")

    def run_quality_scan_for_repo(self, scan_id):
        """Runs a quality scan on a repository for a given scan_id."""
        scan = self.db_session.query(Scan).get(scan_id)
        if not scan:
            logging.error(f"Quality scan failed: Scan with id {scan_id} not found.")
            return

        repository = scan.repository
        if not repository:
            scan.status = ScanStatus.FAILED
            scan.status_message = "Repository not found for this scan."
            self.db_session.commit()
            return

        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            local_path = self.vcs_service.clone_repo(repository.url, branch=repository.primary_branch)
            self.scanner.run_quality_scan(local_path, scan)
            scan.status = ScanStatus.COMPLETED
            # The scanner now sets the final status message
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.status_message = f"Error during quality scan: {str(e)}"
            self.db_session.commit()
            logging.error(f"Error during quality scan of repo {repository.id}: {e}", exc_info=True)

    def rewrite_remediation(self, finding_id):
        """Re-writes a remediation for a finding."""
        return self.vulnerability_processor.rewrite_remediation(finding_id)

    def recheck_finding(self, finding_id):
        """Re-checks a finding by re-running the test script."""
        return self.vulnerability_processor.recheck_finding(finding_id)

    def link_cves_to_findings(self, repo_id, scan_id):
        """Runs a CVE scan on a repository."""
        return self.cve_linker.link_cves_to_findings(repo_id, scan_id)

    def get_findings_by_severity(self):
        """Gets the number of findings for each severity."""
        return self.dashboard.get_findings_by_severity()

    def get_findings_by_repo(self):
        """Gets the number of findings for each repository."""
        return self.dashboard.get_findings_by_repo()

    def get_dashboard_metrics(self):
        """Gets metrics for the dashboard."""
        return self.dashboard.get_dashboard_metrics()

    def chat_with_finding(self, finding_id, message):
        """Chats with a finding."""
        return self.chat_service.chat_with_finding(finding_id, message)

    def chat_with_quality_interpretation(self, interpretation_id, message):
        """Chats with a quality interpretation."""
        return self.chat_service.chat_with_quality_interpretation(interpretation_id, message)