import os
import json
from .llm import LLMService

def scan_configuration(file_path, llm_service):
    """Analyzes a configuration file for security misconfigurations using an LLM."""
    print(f"--- Analyzing configuration file: {file_path} ---")
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return []
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

    if not content.strip():
        return [] # Skip empty files

    response_text = llm_service.analyze_configuration(content)
    
    try:
        # Assuming the LLM returns a JSON object with a list of misconfigurations
        data = llm_service.extract_json(response_text)
        misconfigurations = json.loads(data).get("misconfigurations", [])
        return misconfigurations
    except json.JSONDecodeError:
        print(f"Could not parse LLM response for configuration scan. Raw output: {response_text}")
        return []

def find_config_files(directory):
    """Finds common configuration files in a directory."""
    config_files = []
    supported_extensions = ('.yml', '.yaml', '.json', '.toml', '.ini', '.conf', '.tf')
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(supported_extensions):
                config_files.append(os.path.join(root, file))
    return config_files

if __name__ == '__main__':
    from .config import LLM_PROVIDER
    llm = LLMService(llm_provider=LLM_PROVIDER)
    
    # Create a dummy config file for testing
    dummy_file = "config.yaml"
    with open(dummy_file, "w") as f:
        f.write("services:\n  database:\n    image: postgres:latest\n    ports:\n      - \"5432:5432\"\n    environment:\n      POSTGRES_PASSWORD: mysecretpassword # Insecure\n")

    misconfigs = scan_configuration(dummy_file, llm)
    if misconfigs:
        print(f"\nFound {len(misconfigs)} misconfigurations:")
        for misconfig in misconfigs:
            print(f"  - Line: {misconfig.get('line_number')}, Description: {misconfig.get('description')}")
    else:
        print("\nNo misconfigurations found.")
    
    os.remove(dummy_file)
