# src/quality_scanners/ruby.py

import logging
import subprocess
import json
import os

from .base import BaseQualityScanner
from .. import config

class RubyQualityScanner(BaseQualityScanner):
    """
    Ruby-specific quality scanner.
    """
    def get_language(self):
        return "Ruby"

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
            command = [config.RUBYCRITIC_PATH, file_path, '--format', 'json']
            result = subprocess.run(command, capture_output=True, text=True, cwd=self.repo_path)
            
            if result.returncode != 0 and "No smell" not in result.stderr:
                logging.error(f"RubyCritic failed for {file_path}: {result.stderr}")
                return metrics

            if not result.stdout:
                logging.warning(f"RubyCritic produced no output for {file_path}")
                return metrics

            report = json.loads(result.stdout)
            
            if not report.get('analysed_modules'):
                logging.warning(f"RubyCritic produced an empty report for {file_path}")
                return metrics

            module_report = report['analysed_modules'][0]
            
            churn = self._get_code_churn(os.path.relpath(file_path, self.repo_path))
            
            complexity = 0
            for method in module_report.get('methods', []):
                complexity += method.get('complexity', 0)

            rating_map = {'A': 100, 'B': 80, 'C': 60, 'D': 40, 'E': 20, 'F': 0}
            rating = module_report.get('rating', 'F')
            maintainability_score = rating_map.get(rating.upper(), 0)

            metrics.update({
                'cyclomatic_complexity': complexity,
                'sloc': module_report.get('lines_of_code', 0),
                'code_churn': churn,
                'maintainability_index': maintainability_score,
                'bug_risk_score': complexity * churn 
            })

        except (json.JSONDecodeError, FileNotFoundError, IndexError) as e:
            logging.error(f"Could not run or parse RubyCritic scan for {file_path}: {e}")
        
        return metrics

    def _get_code_churn(self, file_path):
        try:
            output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path], cwd=self.repo_path)
            commits = output.decode('utf-8').strip().split('\n')
            return len(commits)
        except Exception as e:
            logging.error(f"Could not calculate code churn for {file_path}: {e}")
            return 0
