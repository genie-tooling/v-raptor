import os
import json
import logging
import subprocess

from .database import QualityMetric, Finding
from .llm import LLMService
from .osv import get_vulns_for_package
from .dependency_scanner import scan_dependencies
from .config_scanner import find_config_files, scan_configuration
from .quality_scanner import get_quality_metrics
from . import config
from .vulnerability_processor import VulnerabilityProcessor


class Scanner:
    def __init__(self, db_session, llm_service: LLMService, vulnerability_processor: VulnerabilityProcessor):
        self.db_session = db_session
        self.llm_service = llm_service
        self.vulnerability_processor = vulnerability_processor

    def run_sast_scan(self, repo_path, scan, include_tests=False):
        """Runs a SAST scan on a repository using semgrep and bandit."""
        logging.info("\n--- Running SAST Scan ---")
        scan.status_message = "Running SAST scan..."
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
            if not include_tests:
                command.extend(['--exclude', 'tests', '--exclude', 'test'])
            subprocess.run(command, check=True, capture_output=True, text=True)
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report = json.load(f)
                for result in report['results']:
                    rule_id = result['check_id']
                    link = f"https://semgrep.dev/r/{rule_id}"
                    vulnerability = {
                        'file_path': result['path'],
                        'line_number': result['start']['line'],
                        'code_snippet': result['extra']['lines'],
                        'description': f"Semgrep: {result['extra']['message']} ({link})",
                        'severity': result['extra']['severity'],
                    }
                    self.vulnerability_processor.process_vulnerability(vulnerability, repo_path, scan.repository.url, scan)
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
            if not include_tests:
                command.extend(['-x', 'tests', '-x', 'test'])
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
                    test_id = res['test_id']
                    link = f"https://bandit.readthedocs.io/en/latest/plugins/{test_id}.html"
                    vulnerability = {
                        'file_path': res['filename'],
                        'line_number': res['line_number'],
                        'code_snippet': res['code'],
                        'description': f"Bandit: {res['issue_text']} ({link})",
                        'severity': res['issue_severity'],
                    }
                    self.vulnerability_processor.process_vulnerability(vulnerability, repo_path, scan.repository.url, scan)
        except Exception as e:
            logging.error(f"An error occurred during Bandit scan: {e}")

    def run_intelligent_cve_scan(self, repo_path, scan):
        """Runs an intelligent CVE scan on a repository."""
        logging.info("\n--- Running Intelligent CVE Scan (aliased to Dependency Scan) ---")
        scan.status_message = "Running intelligent CVE scan..."
        self.db_session.commit()
        return self.run_dependency_scan(repo_path, scan)

    def run_source_code_scan(self, scan, repo_path, auto_patch=False, include_tests=False):
        logging.info("Starting source code scan...")
        scan.status_message = "Scanning source code..."
        self.db_session.commit()
        
        ignorable_files = ['.gitignore', 'semgrep-report.json', 'bandit-report.json']
        ignorable_extensions = ['.db', '.sqlite3', '.log', '.pyc', '.egg-info', '.DS_Store', '.md', '.txt', '.rst', '.yml']
        ignorable_dirs = ['__pycache__', '.git', '.venv', '.venv2', 'node_modules', 'build', 'dist']
        if not include_tests:
            ignorable_dirs.extend(['tests', 'test'])

        for root, dirs, files in os.walk(repo_path):
            # Remove ignorable directories from the list of directories to traverse
            dirs[:] = [d for d in dirs if d not in ignorable_dirs]

            for file in files:
                file_path = os.path.join(root, file)

                if os.path.basename(file_path) in ignorable_files:
                    continue
                
                if any(file_path.endswith(ext) for ext in ignorable_extensions):
                    continue

                scan.status_message = f"Scanning {file_path}..."
                self.db_session.commit()
                
                try:
                    # Get existing findings for this file
                    existing_findings = self.db_session.query(Finding).filter_by(scan_id=scan.id, file_path=os.path.relpath(file_path, repo_path)).all()
                    
                    response = self.llm_service.analyze_file(file_path, existing_findings)
                    vulnerabilities = json.loads(response).get('vulnerabilities', [])
                    for vuln in vulnerabilities:
                        confidence = vuln.get('confidence', 0.0)
                        if confidence >= 0.7:
                            vulnerability = {
                                'file_path': vuln['file_path'],
                                'line_number': vuln['line_number'],
                                'code_snippet': vuln['code_snippet'],
                                'description': vuln['description'],
                                'confidence_score': confidence,
                                'severity': vuln.get('severity', 'UNKNOWN'),
                            }
                            self.vulnerability_processor.process_vulnerability(vulnerability, repo_path, scan.repository.url, scan, auto_patch=auto_patch)
                except Exception as e:
                    logging.error(f"Error analyzing file {file_path}: {e}", exc_info=True)
        self.db_session.commit()
        logging.info("Source code scan finished.")

    def run_secret_scan(self, repo_path, scan):
        """Runs a secret scan on a repository using gitleaks."""
        logging.info("\n--- Running Secret Scan with Gitleaks ---")
        scan.status_message = "Running secret scan..."
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
                    vulnerability = {
                        'file_path': finding['File'],
                        'line_number': finding['StartLine'],
                        'code_snippet': finding['Secret'],
                        'description': f"Gitleaks: {finding['Description']}",
                        'severity': finding.get('Severity', 'HIGH'),
                    }
                    self.vulnerability_processor.process_vulnerability(vulnerability, repo_path, scan.repository.url, scan)

        except subprocess.CalledProcessError as e:
            logging.error(f"Gitleaks scan failed: {e.stderr}")
        except Exception as e:
            logging.error(f"An error occurred during secret scan: {e}")

    def run_quality_scan(self, repo_path, scan):
        """Runs a quality scan on a repository."""
        logging.info("\n--- Running Quality Scan ---")
        scan.status_message = "Running quality scan..."
        self.db_session.commit()
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
                            file_path=os.path.relpath(absolute_file_path, repo_path),
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
        scan.status_message = "Running dependency scan..."
        self.db_session.commit()

        dependencies = scan_dependencies(repo_path)
        if dependencies:
            logging.info(f"Found {len(dependencies)} dependencies.")
            for dep in dependencies:
                vulns = get_vulns_for_package(dep['package'], dep['version'])
                if vulns and 'vulns' in vulns:
                    for vuln in vulns['vulns']:
                        vulnerability = {
                            'description': vuln['summary'],
                            'severity': vuln.get('severity', 'UNKNOWN'),
                            'cve_id': vuln['id'],
                        }
                        self.vulnerability_processor.process_dependency_vulnerability(vulnerability, scan)
            self.db_session.commit()
        else:
            logging.info("No dependency vulnerabilities found.")

    def run_config_scan(self, repo_path, scan):
        """Runs a configuration scan on a repository."""
        logging.info("\n--- Running Configuration Scan ---")
        scan.status_message = "Running configuration scan..."
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
                    vulnerability = {
                        'file_path': file_path,
                        'line_number': misconfig.get('line_number'),
                        'description': misconfig.get('description'),
                    }
                    self.vulnerability_processor.process_config_vulnerability(vulnerability, scan)
        
        if total_misconfigs == 0:
            logging.info("No configuration misconfigurations found.")
