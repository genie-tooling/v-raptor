import os
import tempfile
import shutil
from src.language_detector import detect_languages, get_language_for_file

def test_detect_languages():
    # Create a temporary directory with some files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some files with different extensions
        with open(os.path.join(tmpdir, 'test.py'), 'w') as f:
            f.write('print("hello")')
        with open(os.path.join(tmpdir, 'test.js'), 'w') as f:
            f.write('console.log("hello")')
        with open(os.path.join(tmpdir, 'test.rb'), 'w') as f:
            f.write('puts "hello"')
        with open(os.path.join(tmpdir, 'test2.py'), 'w') as f:
            f.write('print("world")')

        languages = detect_languages(tmpdir)
        assert languages == ['Python', 'JavaScript', 'Ruby']

def test_get_language_for_file():
    assert get_language_for_file('test.py') == 'Python'
    assert get_language_for_file('test.js') == 'JavaScript'
    assert get_language_for_file('test.rb') == 'Ruby'
    assert get_language_for_file('test.go') == 'Go'
    assert get_language_for_file('test.rs') == 'Rust'
    assert get_language_for_file('test.c') == 'C'
    assert get_language_for_file('test.cpp') == 'C++'
    assert get_language_for_file('Gemfile') == 'Ruby'
    assert get_language_for_file('Cargo.toml') == 'Rust'
    assert get_language_for_file('package.json') == 'Node.js'
    assert get_language_for_file('unknown.txt') is None
