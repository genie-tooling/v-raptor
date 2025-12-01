# src/quality_scanners/javascript.py

import logging
from .base import BaseQualityScanner

import logging
import subprocess
import json
import os
import tempfile
import shutil

from .base import BaseQualityScanner
from .. import config

class JavaScriptQualityScanner(BaseQualityScanner):
    def get_language(self):
        return "JavaScript"

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
        
        report_dir = tempfile.mkdtemp()
        try:
            command = [
                config.NODE_QUALITY_TOOL_PATH,
                '-r', file_path,
                '-d', report_dir,
                '-j' # Output JSON report
            ]
            subprocess.run(command, capture_output=True, text=True, cwd=self.repo_path)
            
            report_path = os.path.join(report_dir, 'report.json')
            if not os.path.exists(report_path):
                logging.error(f"Plato did not generate a report for {file_path}")
                return metrics
                
            with open(report_path, 'r') as f:
                report = json.load(f)
            
            summary = report.get('summary', {})
            if not summary.get('reports'):
                return metrics
            
            file_report = summary['reports'][0]
            
            churn = self._get_code_churn(os.path.relpath(file_path, self.repo_path))
            
            metrics.update({
                'maintainability_index': file_report['complexity'].get('maintainability', 0),
                'cyclomatic_complexity': file_report['complexity'].get('cyclomatic', 0),
                'sloc': file_report['complexity'].get('sloc', 0),
                'code_churn': churn,
                'bug_risk_score': file_report['complexity'].get('cyclomatic', 0) * churn,
            })
            
        except (json.JSONDecodeError, FileNotFoundError, IndexError) as e:
            logging.error(f"Could not run or parse Plato scan for {file_path}: {e}")
        finally:
            shutil.rmtree(report_dir)
            
        return metrics

    def _get_code_churn(self, file_path):
        try:
            output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path], cwd=self.repo_path)
            commits = output.decode('utf-8').strip().split('\n')
            return len(commits)
        except Exception as e:
            logging.error(f"Could not calculate code churn for {file_path}: {e}")
            return 0

