import os
import json
import logging
import subprocess
from sqlalchemy import func

from .database import Repository, Scan, Finding, Patch, ChatMessage, Evidence, QualityMetric, ScanStatus
from .sandbox import SandboxService
from .llm import LLMService
from .dependency_scanner import scan_dependencies
from .config_scanner import find_config_files, scan_configuration
from .secret_scanner import scan_for_secrets
from .quality_scanner import get_quality_metrics
from . import config


class Orchestrator:
    def __init__(self, vcs_service, db_session, google_web_search):
        self.vcs_service = vcs_service
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
                self.process_vulnerability(vulnerability, local_path, repo_url, scan, auto_patch=auto_patch)

            scan.status = ScanStatus.COMPLETED
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            self.db_session.commit()
            logging.info(f"Error during analysis of commit {commit_hash}: {e}")

    def validate_vulnerability_with_search(self, vulnerability):
        """Validates a vulnerability by searching for it on the web."""
        if not self.google_web_search:
            logging.info("--- Web search validation skipped: search function not provided. ---")
            return True
        logging.info(f"\n--- Validating Vulnerability: {vulnerability['description']} ---")
        search_query = f"{vulnerability['description']} {vulnerability['code_snippet']}"
        search_results = self.google_web_search(query=search_query)

        if not search_results:
            return True # If search fails, proceed with the vulnerability

        response_text = self.llm_service.validate_vulnerability(vulnerability['description'], search_results)
        try:
            data = json.loads(response_text)
            if data.get("false_positive"):
                logging.info("Vulnerability identified as a false positive.")
                return False
        except json.JSONDecodeError:
            logging.info("Error: Could not decode LLM response as JSON.")
        
        return True

    def process_vulnerability(self, vulnerability, local_path, repo_url, scan, auto_patch=False):
        if not self.validate_vulnerability_with_search(vulnerability):
            return

        logging.info(f"\n+++ Potential Vulnerability Found: {vulnerability['description']} +++")
        logging.info(f"File: {vulnerability['file_path']}, Line: {vulnerability['line_number']}")

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
        logging.info("\n--- Root Cause Analysis ---")
        logging.info(analysis)

        evidence_analysis = Evidence(finding_id=finding.id, type='root_cause_analysis', content=analysis)
        self.db_session.add(evidence_analysis)
        self.db_session.commit()

        test_script = self.llm_service.generate_test_script(
            vulnerability['code_snippet'], vulnerability['description']
        )
        logging.info("\n--- Generated Test Script ---")
        logging.info(test_script)

        evidence_test_script = Evidence(finding_id=finding.id, type='test_script', content=test_script)
        self.db_session.add(evidence_test_script)
        self.db_session.commit()

        container_id = self.sandbox_service.create_sandbox()
        if not container_id:
            return

        try:
            output = self.sandbox_service.execute_python_script(container_id, test_script)
            logging.info("\n--- Test Script Output ---")
            logging.info(output)

            evidence_test_output = Evidence(finding_id=finding.id, type='test_output', content=output)
            self.db_session.add(evidence_test_output)
            self.db_session.commit()

            confidence_score = self.llm_service.interpret_results(analysis, test_script, output)
            logging.info(f"\nConfidence Score: {confidence_score}")
            finding.confidence_score = confidence_score
            self.db_session.commit()


            if auto_patch and confidence_score > 0.7:
                logging.info("\nHigh confidence score. Generating patch...")
                patch_diff = self.llm_service.generate_patch(vulnerability['code_snippet'], analysis)
                logging.info("\n--- Generated Patch ---")
                logging.info(patch_diff)

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
                    logging.info("Patch generation failed or returned empty.")
            else:
                logging.info("Confidence score is too low or auto_patch is disabled, skipping patch generation.")
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
        logging.info("\n--- Generated Patch ---")
        logging.info(patch_diff)

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
            logging.info("\n--- Test Script Output ---")
            logging.info(output)

            evidence_test_output = self.db_session.query(Evidence).filter_by(finding_id=finding.id, type='test_output').first()
            if not evidence_test_output:
                evidence_test_output = Evidence(finding_id=finding.id, type='test_output')
                self.db_session.add(evidence_test_output)
            evidence_test_output.content = output
            self.db_session.commit()

            analysis_evidence = self.db_session.query(Evidence).filter_by(finding_id=finding.id, type='root_cause_analysis').first()
            analysis = analysis_evidence.content if analysis_evidence else ''

            confidence_score = self.llm_service.interpret_results(analysis, test_script_evidence.content, output)
            logging.info(f"\nConfidence Score: {confidence_score}")
            finding.confidence_score = confidence_score
            self.db_session.commit()
        finally:
            self.sandbox_service.destroy_sandbox(container_id)

    def run_sast_scan(self, repo_path, scan):
        """Runs a SAST scan on a repository using semgrep and bandit."""
        logging.info("\n--- Running SAST Scan ---")
        scan.scan_type = 'sast'
        self.db_session.commit()

        # Run semgrep
        try:
            report_path = os.path.join(repo_path, 'semgrep-report.json')
            command = [
                config.SEMGREP_PATH,
                'scan',
                '--json',
                '--output',
                report_path,
                repo_path
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report = json.load(f)
                for result in report['results']:
                    new_finding = Finding(
                        scan_id=scan.id,
                        file_path=result['path'],
                        line_number=result['start']['line'],
                        code_snippet=result['extra']['lines'],
                        description=f"Semgrep: {result['extra']['message']}",
                        severity=result['extra']['severity'],
                    )
                    self.db_session.add(new_finding)
                self.db_session.commit()
        except subprocess.CalledProcessError as e:
            logging.error(f"Semgrep scan failed: {e.stderr}")
        except Exception as e:
            logging.error(f"An error occurred during Semgrep scan: {e}")

        # Run bandit
        try:
            report_path = os.path.join(repo_path, 'bandit-report.json')
            command = [
                config.BANDIT_PATH,
                '-r',
                repo_path,
                '-f',
                'json',
                '-o',
                report_path
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode not in [0, 1]:
                logging.error(f"Bandit scan failed with exit code {result.returncode}")
                logging.error(f"Bandit stdout: {result.stdout}")
                logging.error(f"Bandit stderr: {result.stderr}")
                return

            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report = json.load(f)
                for res in report['results']:
                    new_finding = Finding(
                        scan_id=scan.id,
                        file_path=res['filename'],
                        line_number=res['line_number'],
                        code_snippet=res['code'],
                        description=f"Bandit: {res['issue_text']}",
                        severity=res['issue_severity'],
                    )
                    self.db_session.add(new_finding)
                self.db_session.commit()
        except Exception as e:
            logging.error(f"An error occurred during Bandit scan: {e}")

    def run_intelligent_cve_scan(self, repo_path, scan):
        """Runs an intelligent CVE scan on a repository."""
        logging.info("\n--- Running Intelligent CVE Scan ---")
        scan.scan_type = 'intelligent_cve'
        self.db_session.commit()

        # 1. Get the list of files
        files = []
        for root, _, filenames in os.walk(repo_path):
            for filename in filenames:
                # Limit to 1000 files to avoid making the prompt too long
                if len(files) > 1000:
                    break
                files.append(os.path.join(root, filename))

        # 2. Use LLM to identify technologies
        technologies = self.llm_service.identify_technologies(files)
        logging.info(f"Identified technologies: {technologies}")

        # 3. Search for CVEs for each technology
        for tech in technologies:
            cves = self.search_cves_for_technology(tech)
            
            # 4. Validate CVEs
            for cve in cves:
                is_relevant = self.llm_service.validate_cve(cve, files)
                if is_relevant:
                    # 5. Create findings
                    self.create_cve_finding(scan, cve)

    def search_cves_for_technology(self, technology):
        """Searches for CVEs for a given technology."""
        logging.info(f"Searching for CVEs for {technology}")
        search_query = f"{technology} CVE"
        search_results = self.google_web_search(query=search_query)
        
        return self.llm_service.extract_cves_from_search(technology, search_results)

    def create_cve_finding(self, scan, cve):
        """Creates a finding for a CVE."""
        logging.info(f"Creating finding for CVE {cve['id']}")
        new_finding = Finding(
            scan_id=scan.id,
            description=cve['description'],
            cve_id=cve['id'],
            severity='HIGH', # Or some other default
        )
        self.db_session.add(new_finding)
        self.db_session.commit()

    def run_deep_scan(self, repo_url, auto_patch=False):
        """Runs a deep scan on a repository."""
        repository = self.db_session.query(Repository).filter_by(url=repo_url).first()
        if not repository:
            primary_branch = self.vcs_service.get_primary_branch(repo_url)
            repository = Repository(name=repo_url.split('/')[-1], url=repo_url, primary_branch=primary_branch)
            self.db_session.add(repository)
            self.db_session.commit()

        scan = Scan(repository_id=repository.id, scan_type='deep', status='queued', auto_patch_enabled=auto_patch)
        self.db_session.add(scan)
        self.db_session.commit()

        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            local_path = self.vcs_service.clone_repo(repo_url, branch=repository.primary_branch)
            self.run_sast_scan(local_path, scan)
            self.run_intelligent_cve_scan(local_path, scan)
            self.run_source_code_scan(local_path, scan, auto_patch=auto_patch)
            self.run_secret_scan(local_path, scan)
            self.run_dependency_scan(local_path, scan)
            self.run_config_scan(local_path, scan)
            self.run_quality_scan(local_path, scan)
            scan.status = ScanStatus.COMPLETED
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            self.db_session.commit()
            logging.info(f"Error during deep scan of {repo_url}: {e}")

    def run_source_code_scan(self, repo_path, scan, auto_patch=False):
        """Runs a source code scan on a repository."""
        logging.info("\n--- Running Source Code Scan ---")
        scan.scan_type = 'source' # Set scan type to source
        self.db_session.commit()

        for root, _, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Simple check to avoid scanning binary files
                try:
                    # Skip files larger than 1MB
                    if os.path.getsize(file_path) > 1024 * 1024:
                        logging.info(f"Skipping large file: {file_path}")
                        continue
                    with open(file_path, 'r', encoding='utf-8') as f:
                        f.read(1024) # Try to read the first 1KB
                except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
                    continue

                logging.info(f"Scanning {file_path}")
                response_text = self.llm_service.analyze_file(file_path)
                try:
                    data = json.loads(response_text)
                    vulnerabilities = data.get("vulnerabilities", [])
                except json.JSONDecodeError:
                    logging.info(f"Error: Could not decode LLM response for {file_path} as JSON.")
                    vulnerabilities = []

                for vulnerability in vulnerabilities:
                    self.process_vulnerability(vulnerability, repo_path, scan.repository.url, scan, auto_patch=auto_patch)

    def run_secret_scan(self, repo_path, scan):
        """Runs a secret scan on a repository using gitleaks."""
        logging.info("\n--- Running Secret Scan with Gitleaks ---")
        scan.scan_type = 'secret'
        self.db_session.commit()

        report_path = os.path.join(repo_path, 'gitleaks-report.json')
        command = [
            config.GITLEAKS_PATH,
            'detect',
            '--source',
            repo_path,
            '--report-path',
            report_path,
            '--report-format',
            'json'
        ]

        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    findings = json.load(f)
                
                for finding in findings:
                    new_finding = Finding(
                        scan_id=scan.id,
                        file_path=finding['File'],
                        line_number=finding['StartLine'],
                        code_snippet=finding['Secret'],
                        description=f"Gitleaks: {finding['Description']}",
                        severity=finding.get('Severity', 'HIGH'),
                    )
                    self.db_session.add(new_finding)
                self.db_session.commit()

        except subprocess.CalledProcessError as e:
            logging.error(f"Gitleaks scan failed: {e.stderr}")
        except Exception as e:
            logging.error(f"An error occurred during secret scan: {e}")
        
    def run_quality_scan_for_repo(self, repo_id):
        """Runs a quality scan on a repository."""
        repository = self.db_session.query(Repository).get(repo_id)
        if not repository:
            return

        scan = Scan(repository_id=repo_id, scan_type='quality', status='queued')
        self.db_session.add(scan)
        self.db_session.commit()

        scan.status = ScanStatus.RUNNING
        self.db_session.commit()
        try:
            local_path = self.vcs_service.clone_repo(repository.url, branch=repository.primary_branch)
            self.run_quality_scan(local_path, scan)
            scan.status = ScanStatus.COMPLETED
            self.db_session.commit()
        except Exception as e:
            scan.status = ScanStatus.FAILED
            self.db_session.commit()
            logging.info(f"Error during quality scan of repo {repo_id}: {e}")

    def run_quality_scan(self, repo_path, scan):
        """Runs a quality scan on a repository."""
        logging.info("\n--- Running Quality Scan ---")
        logging.info(f"Scanning for .py files in {repo_path}")

        found_files = False
        for root, _, files in os.walk(repo_path):
            logging.info(f"Scanning directory: {root}")
            for file in files:
                logging.info(f"Found file: {file}")
                if file.endswith('.py'):
                    found_files = True
                    logging.info(f"Found python file: {file}")
                    absolute_file_path = os.path.join(root, file)
                    
                    metrics = get_quality_metrics(absolute_file_path, repo_path)
                    if metrics:
                        quality_metric = QualityMetric(
                            scan_id=scan.id,
                            file_path=absolute_file_path,
                            cyclomatic_complexity=metrics['cyclomatic_complexity'],
                            sloc=metrics['sloc'],
                            lloc=metrics['lloc'],
                            comments=metrics['comments'],
                            halstead_volume=metrics['halstead_volume'],
                            code_churn=metrics['code_churn']
                        )
                        self.db_session.add(quality_metric)
                        self.db_session.commit()
                        logging.info(f"Added and committed quality metric for file: {absolute_file_path}")
                        logging.info(f"Metric: {quality_metric}")
        
        if not found_files:
            logging.info("No .py files found in the repository.")

    def run_dependency_scan(self, repo_path, scan):
        """Runs a dependency scan on a repository."""
        logging.info("\n--- Running Dependency Scan ---")
        scan.scan_type = 'dependency' # Set scan type to dependency
        self.db_session.commit()

        vulnerabilities = scan_dependencies(repo_path)
        if vulnerabilities:
            logging.info(f"Found {len(vulnerabilities)} vulnerabilities in dependencies:")
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
                logging.info(f"  - ID: {vuln['id']}")
                logging.info(f"    Package: {vuln['package']}")
                logging.info(f"    Summary: {vuln['summary']}")
                if cve_id:
                    logging.info(f"    CVE: {cve_id}")
            
            # Automatically remediate vulnerabilities
            logging.info("\n--- Automatically Remediating Dependencies ---")
            try:
                subprocess.run(["osv-scanner", "fix", repo_path], check=True)
                logging.info("Dependencies remediated successfully.")

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
                logging.info(f"Error running OSV-Scanner fix: {e}")
                logging.info(f"Stderr: {e.stderr}")

        else:
            logging.info("No dependency vulnerabilities found.")

    def run_config_scan(self, repo_path, scan):
        """Runs a configuration scan on a repository."""
        logging.info("\n--- Running Configuration Scan ---")
        scan.scan_type = 'configuration' # Set scan type to configuration
        self.db_session.commit()

        config_files = find_config_files(repo_path)
        if not config_files:
            logging.info("No configuration files found.")
            return

        total_misconfigs = 0
        for file_path in config_files:
            misconfigs = scan_configuration(file_path, self.llm_service)
            if misconfigs:
                total_misconfigs += len(misconfigs)
                logging.info(f"Found {len(misconfigs)} misconfigurations in {file_path}:")
                for misconfig in misconfigs:
                    finding = Finding(
                        scan_id=scan.id,
                        file_path=file_path,
                        line_number=misconfig.get('line_number'),
                        description=misconfig.get('description'),
                    )
                    self.db_session.add(finding)
                    logging.info(f"  - Line: {misconfig.get('line_number')}, Description: {misconfig.get('description')}")
        
        if total_misconfigs == 0:
            logging.info("No configuration misconfigurations found.")

    def link_cves_to_findings(self, repo_id):
        """Runs a CVE scan on a repository."""
        scan = Scan(repository_id=repo_id, scan_type='cve', status='queued')
        self.db_session.add(scan)
        self.db_session.commit()

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
        search_query = f"{finding.description} CVE"
        search_results = self.google_web_search(query=search_query)
        
        prompt = f"Based on the following search results, what is the most likely CVE for the vulnerability '{finding.description}'?\n\nSearch results:\n{search_results}\n\nRespond with only the CVE ID (e.g., CVE-2021-44228). If no CVE is found, respond with 'N/A'."
        cve_id = self.llm_service._create_chat_completion(self.llm_service.scanner_client, self.llm_service._get_model_name('scanner'), prompt, is_json=False)

        if 'cve-' in cve_id.lower():
            finding.cve_id = cve_id.strip()
            self.db_session.commit()
            logging.info(f"Found CVE: {cve_id} for finding #{finding.id}")

    def get_findings_by_severity(self):
        """Gets the number of findings for each severity."""
        return self.db_session.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()

    def get_findings_by_repo(self):
        """Gets the number of findings for each repository."""
        return self.db_session.query(Repository.name, func.count(Finding.id)).select_from(Repository).join(Scan).join(Finding).group_by(Repository.name).all()

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