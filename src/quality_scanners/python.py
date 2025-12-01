# src/quality_scanners/python.py

import logging
import subprocess
import json
import xml.etree.ElementTree as ET
import re
import os
from radon.visitors import ComplexityVisitor
from radon.metrics import h_visit, mi_visit
from radon.raw import analyze

from .base import BaseQualityScanner
from .. import config

class PythonQualityScanner(BaseQualityScanner):
    """
    Python-specific quality scanner.
    """
    def get_language(self):
        return "Python"

    def get_project_wide_metrics(self):
        logging.info("--- Running Python project-wide quality scans... ---")
        
        coverage, tests_passed = self.run_coverage()

        duplicated_lines = self.run_duplication_scan()
        linter_issues = self.run_linter()
        coupling, cohesion = self.run_architecture_scan()
        logging.info("--- Python project-wide scans complete. ---")
        return {
            'code_coverage': coverage,
            'tests_passing': 1 if tests_passed else 0,
            'duplicated_lines': duplicated_lines,
            'linter_issues': linter_issues,
            'coupling': coupling,
            'cohesion': cohesion,
        }

    def get_quality_metrics(self, file_path):
        metrics = {
            'cyclomatic_complexity': 0,
            'sloc': 0,
            'lloc': 0,
            'comments': 0,
            'halstead_volume': 0,
            'code_churn': 0,
            'maintainability_index': 0,
            'bug_risk_score': 0
        }
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Cyclomatic Complexity
            visitor = ComplexityVisitor.from_code(content)
            total_complexity = sum(func.complexity for func in visitor.functions)

            # Raw metrics
            raw_metrics = analyze(content)
            
            # Halstead metrics
            halstead_results = h_visit(content)
            total_halstead_volume = halstead_results.total.volume if halstead_results and halstead_results.total else 0

            # Code Churn
            relative_file_path = os.path.relpath(file_path, self.repo_path)
            churn = self._get_code_churn(relative_file_path)

            # Maintainability Index
            mi_score = mi_visit(content, multi=True)

            # Bug Risk Score
            bug_risk_score = total_complexity * churn

            metrics.update({
                'cyclomatic_complexity': total_complexity,
                'sloc': raw_metrics.sloc,
                'lloc': raw_metrics.lloc,
                'comments': raw_metrics.comments,
                'halstead_volume': total_halstead_volume,
                'code_churn': churn,
                'maintainability_index': mi_score,
                'bug_risk_score': bug_risk_score
            })
        except Exception as e:
            logging.error(f"Could not run Python quality scan for {file_path}: {e}")

        return metrics

    def run_coverage(self):
        try:
            should_run_in_container = config.RUN_TESTS_IN_CONTAINER_DEFAULT
            if self.repo_config.run_tests_in_container is not None:
                should_run_in_container = self.repo_config.run_tests_in_container

            user_command = self.repo_config.test_command
            if not user_command:
                user_command = 'pytest'

            if user_command.strip() == 'pytest':
                user_command = 'pytest --cov=. --cov-report=xml'
            
            logs = ""

            if should_run_in_container:
                if self.repo_config.use_venv and self.repo_config.python_version:
                    setup_steps = [
                        "if ! command -v uv >/dev/null; then pip install uv; fi",
                        "if command -v apt-get >/dev/null && (! command -v gcc >/dev/null || ! command -v cmake >/dev/null); then apt-get update && apt-get install -y --no-install-recommends build-essential cmake; fi",
                        f"uv venv -p {self.repo_config.python_version} .test_venv",
                        ". .test_venv/bin/activate",
                        "uv pip install pytest pytest-cov",
                        "if [ -f requirements.txt ]; then uv pip install -r requirements.txt; fi",
                        "if [ -f pyproject.toml ] || [ -f setup.py ]; then uv pip install .; fi"
                    ]
                    setup_cmd = " && ".join(setup_steps)
                    command = f"{setup_cmd} && {user_command}"
                    
                elif not self.repo_config.use_venv:
                     setup_steps = [
                         "if command -v apt-get >/dev/null && (! command -v gcc >/dev/null || ! command -v cmake >/dev/null); then apt-get update && apt-get install -y --no-install-recommends build-essential cmake; fi",
                         "if [ -f pyproject.toml ] || [ -f setup.py ]; then pip install .; fi"
                     ]
                     setup_cmd = " && ".join(setup_steps)
                     command = f"{setup_cmd} && {user_command}"
                else:
                    command = user_command 

                selected_image = self.repo_config.test_container
                entrypoint = '/bin/sh'
                
                if hasattr(config, 'TEST_CONTAINER_IMAGES'):
                    for container_conf in config.TEST_CONTAINER_IMAGES:
                        if isinstance(container_conf, dict):
                            if container_conf.get('image') == selected_image:
                                entrypoint = container_conf.get('entrypoint', '/bin/sh')
                                break
                        elif isinstance(container_conf, str) and container_conf == selected_image:
                            entrypoint = '/bin/sh'

                logging.info(f"Running Python coverage scan in {selected_image} (Entry: {entrypoint}) with command: {command}")
                logs = self.sandbox_service.run_command_in_repo(
                    self.repo_path, 
                    command,
                    image_name=selected_image,
                    entrypoint=entrypoint
                )
            
            else:
                logging.info(f"Running Python coverage scan locally: {user_command}")
                try:
                    shell_exec = '/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
                    result = subprocess.run(
                        user_command, 
                        shell=True, 
                        cwd=self.repo_path,
                        executable=shell_exec,
                        capture_output=True, 
                        text=True
                    )
                    logs = result.stdout + "\n" + result.stderr
                    if result.returncode != 0:
                        logging.warning(f"Local coverage command failed with code {result.returncode}")
                except Exception as e:
                    logging.error(f"Local subprocess failed: {e}")
                    logs = str(e)

            tests_passed = "failed" not in logs.lower() and "error" not in logs.lower()
            
            coverage_xml_path = os.path.join(self.repo_path, 'coverage.xml')
            if os.path.exists(coverage_xml_path):
                try:
                    tree = ET.parse(coverage_xml_path)
                    root = tree.getroot()
                    line_rate = float(root.get('line-rate', 0.0)) * 100
                    logging.info(f"Python coverage found: {line_rate}%")
                    return line_rate, tests_passed
                except Exception as e:
                    logging.error(f"Failed to parse coverage.xml: {e}")
            else:
                logging.warning(f"coverage.xml not found at {coverage_xml_path}. Logs:\n{logs[-1000:]}")

        except Exception as e:
            logging.error(f"An unexpected error occurred during Python coverage scan: {e}")
        
        return 0.0, False

    def run_duplication_scan(self):
        try:
            pmd_executable = '/opt/pmd/bin/run.sh'
            result = subprocess.run(
                [
                    pmd_executable, 'cpd',
                    '--minimum-tokens', '70',
                    '--dir', self.repo_path,
                    '--format', 'text',
                    '--language', 'python',
                    '--failOnViolation', 'false'
                ],
                capture_output=True, text=True, check=True
            )
            
            total_duplicated_lines = 0
            for match in re.finditer(r"Found a (\d+) line duplication", result.stdout):
                total_duplicated_lines += int(match.group(1))
                
            return total_duplicated_lines
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"Could not run Python duplication scan: {e}")
            if hasattr(e, 'stderr'):
                logging.error(f"PMD stderr: {e.stderr}")
        return 0

    def run_linter(self):
        try:
            result = subprocess.run(
                ['pylint', '--recursive=y', '.', '-f', 'json'],
                cwd=self.repo_path,
                capture_output=True, text=True
            )
            if result.stdout:
                try:
                    report = json.loads(result.stdout)
                    return len(report)
                except json.JSONDecodeError:
                    logging.error(f"Pylint did not produce valid JSON. Output: {result.stdout}")
                    return 0
        except Exception as e:
            logging.error(f"Could not run Pylint scan: {e}")
        return 0

    def run_architecture_scan(self):
        try:
            find_result = subprocess.run(
                ['find', '.', '-name', '*.py'],
                cwd=self.repo_path,
                capture_output=True, text=True, check=True
            )
            python_files = find_result.stdout.strip().split('\n')
            
            if not python_files or not python_files[0]:
                logging.info("No python files found for architecture scan.")
                return 0.0, 0.0

            command = ['cohesion', '-x', '-f'] + python_files
            result = subprocess.run(
                command,
                cwd=self.repo_path,
                capture_output=True, text=True,
                check=True
            )
            data = json.loads(result.stdout)
            
            total_cohesion = 0
            total_coupling = 0
            module_count = len(data)
            
            if module_count == 0:
                return 0.0, 0.0

            for metrics in data.values():
                total_cohesion += metrics.get('lcom4', 0)
                total_coupling += metrics.get('ic', 0)
                
            avg_cohesion = total_cohesion / module_count
            avg_coupling = total_coupling / module_count
            
            return avg_coupling, avg_cohesion
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
            logging.error(f"Could not run or parse Python architecture scan: {e}")
            if hasattr(e, 'stdout'):
                logging.error(f"Cohesion stdout: {e.stdout}")
            if hasattr(e, 'stderr'):
                logging.error(f"Cohesion stderr: {e.stderr}")
        return 0.0, 0.0

    def _get_code_churn(self, file_path):
        try:
            output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path], cwd=self.repo_path)
            commits = output.decode('utf-8').strip().split('\n')
            return len(commits)
        except Exception as e:
            logging.error(f"Could not calculate code churn for {file_path}: {e}")
            return 0
