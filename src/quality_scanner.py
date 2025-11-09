from radon.visitors import ComplexityVisitor
from radon.metrics import h_visit
from radon.raw import analyze
import logging
import subprocess
import os

def get_quality_metrics(file_path, repo_path):
    """Calculates all quality metrics for a file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Cyclomatic Complexity
    visitor = ComplexityVisitor.from_code(content)
    total_complexity = 0
    for func in visitor.functions:
        total_complexity += func.complexity

    # Raw metrics
    raw_metrics = analyze(content)
    sloc = raw_metrics.sloc
    lloc = raw_metrics.lloc
    comments = raw_metrics.comments

    # Halstead metrics
    halstead_results = h_visit(content)
    total_halstead_volume = 0
    if halstead_results and halstead_results.total:
        total_halstead_volume = halstead_results.total.volume

    # Code Churn
    relative_file_path = os.path.relpath(file_path, repo_path)
    churn = get_code_churn(relative_file_path, repo_path)

    return {
        'cyclomatic_complexity': total_complexity,
        'sloc': sloc,
        'lloc': lloc,
        'comments': comments,
        'halstead_volume': total_halstead_volume,
        'code_churn': churn
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
