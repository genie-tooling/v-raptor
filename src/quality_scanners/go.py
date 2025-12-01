# src/quality_scanners/go.py

import logging
from .base import BaseQualityScanner

import logging
import subprocess
import os
import re

from .base import BaseQualityScanner
from .. import config

class GoQualityScanner(BaseQualityScanner):
    def get_language(self):
        return "Go"

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
            command = [config.GOCYCLO_PATH, file_path]
            result = subprocess.run(command, capture_output=True, text=True, cwd=self.repo_path)
            
            if result.returncode != 0:
                logging.error(f"gocyclo failed for {file_path}: {result.stderr}")
                return metrics

            total_complexity = 0
            for line in result.stdout.strip().split('\\n'):
                match = re.match(r'^(\\d+)', line)
                if match:
                    total_complexity += int(match.group(1))

            churn = self._get_code_churn(os.path.relpath(file_path, self.repo_path))
            
            metrics.update({
                'cyclomatic_complexity': total_complexity,
                'code_churn': churn,
                'bug_risk_score': total_complexity * churn,
            })
            
        except (FileNotFoundError, ValueError) as e:
            logging.error(f"Could not run or parse gocyclo scan for {file_path}: {e}")
            
        return metrics

    def _get_code_churn(self, file_path):
        try:
            output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path], cwd=self.repo_path)
            commits = output.decode('utf-8').strip().split('\\n')
            return len(commits)
        except Exception as e:
            logging.error(f"Could not calculate code churn for {file_path}: {e}")
            return 0

