import os
import re
import json
import logging
from . import config
from .llm_providers.base import BaseLLMProvider
from .llm_providers.gemini import GeminiProvider
from .llm_providers.llama_cpp import LlamaCppProvider
from .llm_providers.ollama import OllamaProvider

class LLMService:
    def __init__(self):
        self.scanner_client = self._initialize_client('scanner')
        self.patcher_client = self._initialize_client('patcher')
        self.tools = [
            {
                "name": "run_semgrep",
                "description": "Run semgrep on a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "The path to the file to scan."
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "run_bandit",
                "description": "Run bandit on a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "The path to the file to scan."
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "run_gitleaks",
                "description": "Run gitleaks on a repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "The path to the repository to scan."
                        }
                    },
                    "required": ["repo_path"]
                }
            },
            {
                "name": "google_web_search",
                "description": "Performs a web search using Google Search and returns the results.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The search query to find information on the web."
                        }
                    },
                    "required": ["query"]
                }
            }
        ]

    def _initialize_client(self, client_type: str) -> BaseLLMProvider:
        prefix = client_type.upper()
        provider = getattr(config, f"{prefix}_LLM_PROVIDER")
        print(f"Initializing '{client_type}' client with provider '{provider}'...")

        if provider == 'gemini':
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                try:
                    with open('api_key.txt', 'r') as f:
                        api_key = f.read().strip()
                except FileNotFoundError:
                    raise ValueError(f"GEMINI_API_KEY not found for {client_type}.")
            return GeminiProvider(api_key=api_key)
        elif provider == 'llama.cpp':
            model_path = getattr(config, f"{prefix}_LLAMA_CPP_MODEL_PATH")
            if not model_path or not os.path.exists(model_path):
                raise ValueError(f"Llama.cpp model path not found for {client_type}: {model_path}")
            return LlamaCppProvider(model_path=model_path)
        elif provider == 'ollama':
            host_url = getattr(config, f"{prefix}_OLLAMA_URL")
            return OllamaProvider(host_url=host_url)
        else:
            raise ValueError(f"Unsupported LLM provider for {client_type}: {provider}")

    def _get_model_name(self, client_type):
        prefix = client_type.upper()
        provider = getattr(config, f"{prefix}_LLM_PROVIDER")
        if provider == 'ollama':
            return getattr(config, f"{prefix}_OLLAMA_MODEL")
        elif provider == 'gemini':
            return getattr(config, f"{prefix}_GEMINI_MODEL")
        # llama.cpp doesn't have a model name in the same way, it's part of the client initialization.
        return None

    def _create_chat_completion(self, client: BaseLLMProvider, model_name, prompt, is_json=True):
        return client.create_chat_completion(model_name, prompt, is_json)

    def analyze_diff_with_tools(self, diff):
        prompt = f"""You are a senior security engineer. Analyze the following diff and identify potential vulnerabilities.

Diff:
```diff
{diff}
```

Respond with a JSON object containing a list of vulnerabilities. Each vulnerability should have the following fields:
- file_path: The path to the file where the vulnerability is located.
- line_number: The line number where the vulnerability is located.
- description: A short, one-sentence description of the vulnerability.
- code_snippet: The exact line(s) of vulnerable code from the diff.

Only report vulnerabilities with a high confidence score. Do not include any explanations or ask any questions.

If no vulnerabilities are found, respond with an empty JSON object: {{}}.
Example response:
```json
{{
  "vulnerabilities": [
    {{
      "file_path": "src/user.py",
      "line_number": 42,
      "description": "SQL injection vulnerability due to string formatting.",
      "code_snippet": "cursor.execute(f\\"SELECT * FROM users WHERE username = '{{username}}'\\")"
    }}
  ]
}}
"""
        return self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)

    def analyze_file(self, file_path):
        with open(file_path, 'r') as f:
            content = f.read()
        prompt = f"""You are a senior security engineer. Analyze the following file and identify potential vulnerabilities.

File: {file_path}

```
{content}
```

Respond with a JSON object containing a list of vulnerabilities. Each vulnerability should have the following fields:
- file_path: The path to the file where the vulnerability is located.
- line_number: The line number where the vulnerability is located.
- description: A short, one-sentence description of the vulnerability.
- code_snippet: The exact line(s) of vulnerable code from the file.

Important:
- The mere presence of a library (e.g., 'rich') is not a vulnerability unless a specific version is known to be vulnerable.
- Entries in `.gitignore` files (e.g., '*.msi') are not vulnerabilities.
- Only report vulnerabilities with a high confidence score. Do not include any explanations or ask any questions.

If no vulnerabilities are found, respond with an empty JSON object: {{}}.
Example response:
```json
{{
  "vulnerabilities": [
    {{
      "file_path": "src/user.py",
      "line_number": 42,
      "description": "SQL injection vulnerability due to string formatting.",
      "code_snippet": "cursor.execute(f\\"SELECT * FROM users WHERE username = '{{username}}'\\")"
    }}
  ]
}}
```"""
        return self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)

    def interpret_quality_metrics(self, metric):
        """Interprets the quality metrics for a file."""
        prompt = f"""
YouYou are a senior software engineer and code quality expert.
You are reviewing a file and its quality metrics.
Your task is to provide a concise and easy-to-understand interpretation of the metrics for a typical developer.
Focus on what the metrics mean in practice and what the developer should pay attention to.
Do not just repeat the numbers, but explain their implications.
For example, if the cyclomatic complexity is high, explain that it means the code is complex and might be difficult to test and maintain.

File: {metric.file_path}

Metrics:
- Cyclomatic Complexity: {metric.cyclomatic_complexity}
- Code Churn: {metric.code_churn} (number of times the file has been changed)
- Source Lines of Code (SLOC): {metric.sloc}
- Logical Lines of Code (LLOC): {metric.lloc}
- Comments: {metric.comments}
- Halstead Volume: {metric.halstead_volume}

Interpretation:
"""
        return self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt, is_json=False)

    def get_root_cause_analysis(self, code_snippet, vulnerability_type):
        prompt = f"""You are a senior security engineer. Provide a brief explanation of this potential '{vulnerability_type}' vulnerability in the provided code snippet.

Code Snippet:
```
{code_snippet}
```

Explain the vulnerability, its potential impact, and how to fix it. Format your response as clean Markdown. Do not ask any questions."""
        return self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt, is_json=False)

    def generate_test_script(self, code_snippet, vulnerability_hypothesis):
        prompt = f"""You are a security engineer. Write a standalone Python script to test for a potential '{vulnerability_hypothesis}' vulnerability in a function that contains this code:

```
{code_snippet}
```

The script must:
1.  Use only standard Python libraries or the 'requests' library.
2.  Be self-contained and ready to execute.
3.  Be a functional test that can actually confirm the vulnerability, not just an example.
4.  Print a clear message indicating whether the vulnerability was confirmed or not.
5.  Respond with ONLY the raw Python code inside a ```python markdown block. Do not include any explanations.
"""
        response = self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt, is_json=False)
        return self.extract_python_code(response)

    def interpret_results(self, analysis, test_script, script_output):
        prompt = f"""You are a senior security engineer. Based on the following analysis, test script, and its output, what is the confidence score for the vulnerability?

Analysis:
{analysis}

Test Script:
{test_script}

Script Output:
{script_output}

Respond with a single float number between 0.0 and 1.0, where 0.0 is not confident and 1.0 is very confident. Respond with ONLY the number. Example: 0.9"""
        response = self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt, is_json=False)
        try:
            return float(response.strip())
        except (ValueError, TypeError):
            return 0.0

    def generate_patch(self, vulnerable_code, root_cause_analysis):
        prompt = f"""You are a senior security engineer. The following code is vulnerable, as described in the root cause analysis.

Vulnerable Code:
```
{vulnerable_code}
```

Root Cause Analysis:
{root_cause_analysis}

Refactor the code to fix the vulnerability. Maintain existing logic and style.
Provide ONLY the fix in the git diff format. Do not include a commit message or any other text.
Start the diff with '--- a/' and '+++ b/'."""
        return self._create_chat_completion(self.patcher_client, self._get_model_name('patcher'), prompt, is_json=False)

    def analyze_configuration(self, config_content):
        prompt = f"""You are a senior security engineer. Analyze the following configuration file for security misconfigurations.

{config_content}

Respond with a JSON object containing a list of misconfigurations. Each misconfiguration should have "line_number" and "description". If none, respond with an empty list."""
        return self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)

    def extract_json(self, text):
        match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        if text.strip().startswith('{'):
            return text.strip()
        return "{}"

    def extract_python_code(self, text):
        match = re.search(r'```python\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()

    def validate_vulnerability(self, vulnerability_description, search_results):
        prompt = f"""You are a senior security engineer. Based on the following vulnerability description and search results, determine if the vulnerability is likely to be a false positive.

Vulnerability Description:
{vulnerability_description}

Search Results:
{search_results}

Respond with a JSON object with a single key, "false_positive", which is a boolean. Do not include any explanations or ask any questions."""
        return self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)

    def validate_cve(self, cve, technologies):
        """Validates if a CVE is relevant to a repository."""
        prompt = f"""You are a senior security engineer. Based on the following CVE and the technologies used in a repository, determine if the CVE is relevant to the repository.

CVE ID: {cve['id']}
CVE Description: {cve['description']}

Technologies:
{", ".join(technologies)}

Respond with a JSON object with a single key, "relevant", which is a boolean. Do not include any explanations or ask any questions.
Example:
{{
  "relevant": true
}}
"""
        response_text = self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)
        try:
            data = json.loads(response_text)
            return data.get("relevant", False)
        except json.JSONDecodeError:
            logging.error(f"Error: Could not decode LLM response for CVE validation as JSON: {response_text}")
            return False

    def extract_cves_from_search(self, technology, search_results):
        """Extracts CVEs from search results."""
        prompt = f"""You are a security researcher. Based on the following search results for "{technology} CVE", extract the CVE IDs and their descriptions.

Search results:
{search_results}

Respond with a JSON object containing a list of CVEs. Each CVE should have "id" and "description".
Example:
{{
  "cves": [
    {{
      "id": "CVE-2021-44228",
      "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."
    }}
  ]
}}
"""
        response_text = self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)
        try:
            data = json.loads(response_text)
            return data.get("cves", [])
        except json.JSONDecodeError:
            logging.error(f"Error: Could not decode LLM response for CVE extraction as JSON: {response_text}")
            return []

    def identify_technologies(self, file_paths):
        """Identifies the technologies used in a repository based on the file paths."""
        prompt = f"""You are a senior software engineer. Based on the following list of file paths, identify the programming languages, frameworks, and other significant technologies used in this repository.

File paths:
{", ".join(file_paths)}

Respond with a JSON object containing a single key "technologies", which is a list of strings. For example:
{{
  "technologies": ["Python", "Flask", "React", "Docker"]
}}
"""
        response_text = self._create_chat_completion(self.scanner_client, self._get_model_name('scanner'), prompt)
        try:
            data = json.loads(response_text)
            return data.get("technologies", [])
        except json.JSONDecodeError:
            logging.error(f"Error: Could not decode LLM response for technology identification as JSON: {response_text}")
            return []

    def get_available_models(self, client_type):
        client = self.scanner_client if client_type == 'scanner' else self.patcher_client
        return client.get_available_models()
