# src/quality_scanner.py

import logging
import os
import subprocess
from .quality_scanners.python import PythonQualityScanner
from .quality_scanners.ruby import RubyQualityScanner
from .quality_scanners.javascript import JavaScriptQualityScanner
from .quality_scanners.go import GoQualityScanner
from .quality_scanners.rust import RustQualityScanner
from .quality_scanners.cpp import CppQualityScanner

def get_scanner_for_language(language, repo_path, sandbox_service, repo_config):
    """
    Factory function to get the appropriate quality scanner for a given language.
    """
    scanners = {
        "Python": PythonQualityScanner,
        "Ruby": RubyQualityScanner,
        "JavaScript": JavaScriptQualityScanner,
        "Go": GoQualityScanner,
        "Rust": RustQualityScanner,
        "C++": CppQualityScanner,
    }
    scanner_class = scanners.get(language)
    if scanner_class:
        return scanner_class(repo_path, sandbox_service, repo_config)
    return None

def get_project_wide_metrics(repo_path, languages, sandbox_service=None, repo_config=None):
    """
    Runs all project-wide scans for the detected languages and returns a dictionary of the results.
    """
    logging.info("--- Running project-wide quality scans for languages: %s ---", languages)
    
    all_metrics = {
        'code_coverage': 0.0,
        'tests_passing': 0,
        'duplicated_lines': 0,
        'linter_issues': 0,
        'coupling': 0.0,
        'cohesion': 0.0,
    }

    scanners_run = 0
    for lang in languages:
        scanner = get_scanner_for_language(lang, repo_path, sandbox_service, repo_config)
        if scanner:
            metrics = scanner.get_project_wide_metrics()
            for key, value in metrics.items():
                if key in all_metrics:
                    all_metrics[key] += value # Sum up metrics from different scanners
            scanners_run += 1

    # Average metrics that should be averaged (like coverage)
    if scanners_run > 0:
        if 'code_coverage' in all_metrics:
            all_metrics['code_coverage'] /= scanners_run
        if 'coupling' in all_metrics:
            all_metrics['coupling'] /= scanners_run
        if 'cohesion' in all_metrics:
            all_metrics['cohesion'] /= scanners_run
            
    logging.info("--- All project-wide scans complete. ---")
    return all_metrics

def get_quality_metrics(file_path, repo_path, language):
    """
    Calculates all per-file quality metrics for a given language.
    """
    scanner = get_scanner_for_language(language, repo_path, None, None) # sandbox and repo_config not needed for per-file
    if scanner:
        return scanner.get_quality_metrics(file_path)

    # Fallback for basic metrics if no specific scanner is found
    return {
        'code_churn': get_code_churn(os.path.relpath(file_path, repo_path), repo_path)
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
