from radon.visitors import ComplexityVisitor
from radon.metrics import h_visit
from radon.raw import analyze
import subprocess

def get_cyclomatic_complexity(file_path):
    """Calculates the cyclomatic complexity of a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        visitor = ComplexityVisitor.from_code(content)
        total_complexity = 0
        for func in visitor.functions:
            total_complexity += func.complexity
        return total_complexity
    except Exception as e:
        print(f"Could not calculate complexity for {file_path}: {e}")
        return 0

def get_code_churn(file_path):
    """Calculates the code churn of a file."""
    try:
        output = subprocess.check_output(['git', 'log', '--follow', '--format=%H', '--', file_path])
        commits = output.decode('utf-8').strip().split('\n')
        return len(commits)
    except Exception as e:
        print(f"Could not calculate code churn for {file_path}: {e}")
        return 0
