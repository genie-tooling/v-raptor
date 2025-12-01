import os

# Silence GitPython's initialization error.
# This allows the test suite to be collected even if the git executable
# is not present in the environment (e.g., inside a minimal container).
os.environ["GIT_PYTHON_REFRESH"] = "quiet"