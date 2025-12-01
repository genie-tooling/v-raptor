import os
from collections import defaultdict

# A simplified mapping of file extensions to languages.
# This can be expanded.
EXTENSION_TO_LANGUAGE = {
    # Python
    '.py': 'Python',
    '.pyw': 'Python',
    # JavaScript / Node.js
    '.js': 'JavaScript',
    '.mjs': 'JavaScript',
    '.cjs': 'JavaScript',
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript',
    'package.json': 'Node.js',
    # Go
    '.go': 'Go',
    # Ruby
    '.rb': 'Ruby',
    'Gemfile': 'Ruby',
    # Rust
    '.rs': 'Rust',
    'Cargo.toml': 'Rust',
    # C/C++
    '.c': 'C',
    '.h': 'C',
    '.cpp': 'C++',
    '.hpp': 'C++',
    '.cc': 'C++',
    '.hh': 'C++',
    # Shell
    '.sh': 'Shell',
    # HTML
    '.html': 'HTML',
    '.htm': 'HTML',
    # Java
    '.java': 'Java',
    # PHP
    '.php': 'PHP',
}

def detect_languages(directory: str) -> list[str]:
    """
    Detects the programming languages used in a directory based on file extensions.

    Args:
        directory: The path to the directory to analyze.

    Returns:
        A list of detected language names, sorted by frequency.
    """
    language_counts = defaultdict(int)
    for root, _, files in os.walk(directory):
        for file in files:
            # Check for full filename matches first (e.g., 'Gemfile')
            if file in EXTENSION_TO_LANGUAGE:
                language_counts[EXTENSION_TO_LANGUAGE[file]] += 1
                continue

            # Check for extension matches
            _, ext = os.path.splitext(file)
            if ext in EXTENSION_TO_LANGUAGE:
                language_counts[EXTENSION_TO_LANGUAGE[ext]] += 1

    if not language_counts:
        return []

    # Sort languages by the number of files (descending), then by name (ascending)
    sorted_languages = sorted(language_counts.keys(), key=lambda lang: (-language_counts[lang], lang))
    return sorted_languages

def get_language_for_file(file_path: str) -> str | None:
    """
    Detects the programming language of a single file.

    Args:
        file_path: The path to the file.

    Returns:
        The language name, or None if not detected.
    """
    file_name = os.path.basename(file_path)
    if file_name in EXTENSION_TO_LANGUAGE:
        return EXTENSION_TO_LANGUAGE[file_name]

    _, ext = os.path.splitext(file_name)
    if ext in EXTENSION_TO_LANGUAGE:
        return EXTENSION_TO_LANGUAGE[ext]
    
    return None
