# src/quality_scanners/rust.py

import logging
from .base import BaseQualityScanner

import logging
import subprocess
import json
import os

from .base import BaseQualityScanner
from .. import config

class RustQualityScanner(BaseQualityScanner):
    def get_language(self):
        return "Rust"

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
            command = [config.RUST_QUALITY_TOOL_PATH, '-p', file_path, '-o', 'json']
            result = subprocess.run(command, capture_output=True, text=True, cwd=self.repo_path)

            if result.returncode != 0:
                logging.error(f"rust-code-analysis-cli failed for {file_path}: {result.stderr}")
                return metrics
            
            # The tool outputs JSON for each file, one per line
            # For a single file, we take the first line
            first_line = result.stdout.strip().split('\\n')[0]
            report = json.loads(first_line)
            
            space_metrics = report.get('spaces', [{}])[0].get('metrics', {})
            file_metrics = report.get('metrics', {})
            
            churn = self._get_code_churn(os.path.relpath(file_path, self.repo_path))
            
            complexity = file_metrics.get('cyclomatic', {}).get('sum', 0)
            
            metrics.update({
                'maintainability_index': file_metrics.get('mi', {}).get('mi_original', 0),
                'cyclomatic_complexity': complexity,
                'sloc': space_metrics.get('loc', 0),
                'lloc': space_metrics.get('lloc', 0),
                'comments': space_metrics.get('comments', 0),
                'code_churn': churn,
                'bug_risk_score': complexity * churn,
            })

        except (json.JSONDecodeError, FileNotFoundError, IndexError) as e:
            logging.error(f"Could not run or parse rust-code-analysis-cli scan for {file_path}: {e}")
            
        return metrics

    def _get_code_churn(self, file_path):
        try:
            output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path], cwd=self.repo_path)
            commits = output.decode('utf-8').strip().split('\\n')
            return len(commits)
        except Exception as e:
            logging.error(f"Could not calculate code churn for {file_path}: {e}")
            return 0

