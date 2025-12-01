# src/quality_scanners/base.py

import logging

class BaseQualityScanner:
    """
    Base class for language-specific quality scanners.
    """
    def __init__(self, repo_path, sandbox_service, repo_config):
        self.repo_path = repo_path
        self.sandbox_service = sandbox_service
        self.repo_config = repo_config

    def get_project_wide_metrics(self):
        """
        Runs all project-wide scans and returns a dictionary of the results.
        """
        logging.warning(f"Project-wide metrics not implemented for {self.get_language()}")
        return {}

    def get_quality_metrics(self, file_path):
        """
        Calculates all per-file quality metrics.
        """
        logging.warning(f"Per-file quality metrics not implemented for {self.get_language()}")
        return {}

    def get_language(self):
        """
        Returns the language supported by this scanner.
        """
        raise NotImplementedError

    def run_linter(self):
        """
        Runs a linter and returns the number of issues.
        """
        logging.warning(f"Linter not implemented for {self.get_language()}")
        return 0

    def run_coverage(self):
        """
        Runs tests and returns coverage percentage and test pass status.
        """
        logging.warning(f"Coverage not implemented for {self.get_language()}")
        return 0.0, False

    def run_duplication_scan(self):
        """
        Runs a duplication scan and returns the number of duplicated lines.
        """
        logging.warning(f"Duplication scan not implemented for {self.get_language()}")
        return 0
