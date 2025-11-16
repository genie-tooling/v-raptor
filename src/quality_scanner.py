from radon.visitors import ComplexityVisitor
from radon.metrics import h_visit, mi_visit
from radon.raw import analyze
import logging
import subprocess
import os
import json
import xml.etree.ElementTree as ET
import re

def run_coverage(repo_path):
    """Runs pytest with coverage and returns the coverage percentage and test outcome."""
    try:
        # The project's dependencies are installed by the main Dockerfile build.
        # Here, we ensure the project's own source is on the PYTHONPATH.
        env = os.environ.copy()
        env['PYTHONPATH'] = repo_path

        test_result = subprocess.run(
            ['pytest', '--cov=.', '--cov-report=xml'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            env=env
        )
        
        tests_passed = test_result.returncode == 0
        if not tests_passed:
            logging.warning(f"Pytest run failed or tests failed. Stderr: {test_result.stderr}")

        coverage_xml_path = os.path.join(repo_path, 'coverage.xml')
        if os.path.exists(coverage_xml_path):
            tree = ET.parse(coverage_xml_path)
            root = tree.getroot()
            line_rate = float(root.get('line-rate', 0.0)) * 100
            return line_rate, tests_passed
    except Exception as e:
        logging.error(f"An unexpected error occurred during coverage scan: {e}")
    return 0.0, False

def run_duplication_scan(repo_path):
    """Runs PMD's Copy/Paste Detector (CPD) and returns the total number of duplicated lines."""
    try:
        pmd_executable = '/opt/pmd/bin/run.sh'
        result = subprocess.run(
            [
                pmd_executable, 'cpd',
                '--minimum-tokens', '70',
                '--dir', repo_path,
                '--format', 'text',
                '--language', 'python',
                '--failOnViolation', 'false'
            ],
            capture_output=True, text=True, check=True
        )
        
        # Parse the output to sum duplicated lines
        total_duplicated_lines = 0
        # Regex to find "Found a X line duplication"
        for match in re.finditer(r"Found a (\d+) line duplication", result.stdout):
            total_duplicated_lines += int(match.group(1))
            
        return total_duplicated_lines
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Could not run duplication scan: {e}")
        if 'result' in locals():
            logging.error(f"PMD stderr: {e.stderr}")
    return 0

def run_linter(repo_path):
    """Runs pylint on the repository and returns the number of issues."""
    try:
        result = subprocess.run(
            ['pylint', '--recursive=y', '.', '-f', 'json'],
            cwd=repo_path,
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
        logging.error(f"Could not run linter scan: {e}")
    return 0

def run_architecture_scan(repo_path):
    """Runs cohesion to get coupling and cohesion metrics."""
    try:
        # cohesion requires a list of files, not a directory.
        find_result = subprocess.run(
            ['find', '.', '-name', '*.py'],
            cwd=repo_path,
            capture_output=True, text=True, check=True
        )
        python_files = find_result.stdout.strip().split('\n')
        
        if not python_files or not python_files[0]:
            logging.info("No python files found for architecture scan.")
            return 0.0, 0.0

        # The tool outputs JSON by default when no format is specified.
        command = ['cohesion', '-x', '-f'] + python_files
        result = subprocess.run(
            command,
            cwd=repo_path,
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
        logging.error(f"Could not run or parse architecture scan: {e}")
        if 'result' in locals():
            logging.error(f"Cohesion stdout: {result.stdout}")
            logging.error(f"Cohesion stderr: {result.stderr}")
    return 0.0, 0.0

def get_project_wide_metrics(repo_path):
    """Runs all project-wide scans and returns a dictionary of the results."""
    logging.info("--- Running project-wide quality scans... ---")
    coverage, tests_passed = run_coverage(repo_path)
    duplicated_lines = run_duplication_scan(repo_path)
    linter_issues = run_linter(repo_path)
    coupling, cohesion = run_architecture_scan(repo_path)
    logging.info("--- Project-wide scans complete. ---")
    return {
        'code_coverage': coverage,
        'tests_passing': 1 if tests_passed else 0,
        'duplicated_lines': duplicated_lines,
        'linter_issues': linter_issues,
        'coupling': coupling,
        'cohesion': cohesion,
    }

def get_quality_metrics(file_path, repo_path):
    """Calculates all per-file quality metrics."""
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
    relative_file_path = os.path.relpath(file_path, repo_path)
    churn = get_code_churn(relative_file_path, repo_path)

    # Maintainability Index
    mi_score = mi_visit(content, multi=True)

    # Bug Risk Score
    bug_risk_score = total_complexity * churn

    return {
        'cyclomatic_complexity': total_complexity,
        'sloc': raw_metrics.sloc,
        'lloc': raw_metrics.lloc,
        'comments': raw_metrics.comments,
        'halstead_volume': total_halstead_volume,
        'code_churn': churn,
        'maintainability_index': mi_score,
        'bug_risk_score': bug_risk_score
    }

def get_code_churn(file_path, repo_path):
    """Calculates the code churn of a file."""
    try:
        output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path], cwd=repo_path)
        commits = output.decode('utf-8').strip().split('\n')
        return len(commits)
    except Exception as e:
        logging.error(f"Could not calculate code churn for {file_path}: {e}")
        return 0