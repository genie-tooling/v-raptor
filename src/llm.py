import os
import re
import json
from .config import LLAMA_CPP_MODEL_PATH, OLLAMA_MODEL, OLLAMA_URL, GEMINI_MODEL

class LLMService:
    def __init__(self, llm_provider='gemini'):
        self.llm_provider = llm_provider
        if self.llm_provider == 'gemini':
            from google import genai
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                try:
                    with open('api_key.txt', 'r') as f:
                        api_key = f.read().strip()
                except FileNotFoundError:
                    raise ValueError("GEMINI_API_KEY not found as an environment variable or in api_key.txt.")
            
            if not api_key or api_key == "YOUR_API_KEY":
                raise ValueError("GEMINI_API_KEY is not set or is a placeholder.")

            self.model = genai.Client(api_key=api_key)
        elif self.llm_provider == 'llama.cpp':
            from llama_cpp import Llama
            self.model = Llama(model_path=LLAMA_CPP_MODEL_PATH, n_ctx=32767, n_gpu_layers=-1, verbose=False)
        elif self.llm_provider == 'ollama':
            try:
                from ollama import Client
                self.model = Client(host=OLLAMA_URL)
            except ImportError:
                raise ImportError("The 'ollama' library is not installed. Please install it to use the Ollama provider.")
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

    def _create_chat_completion(self, prompt, is_json=True):
        if self.llm_provider == 'gemini':
            response = self.model.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )
            return response.text
        elif self.llm_provider == 'llama.cpp':
            response = self.model.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer. Respond ONLY in the requested format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1
            )
            content = response['choices'][0]['message']['content']
            if is_json:
                return self.extract_json(content)
            return content
        elif self.llm_provider == 'ollama':
            response = self.model.chat(
                model=OLLAMA_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer. Respond ONLY in the requested format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                options={'num_ctx': 32767}
            )
            content = response['message']['content']
            if is_json:
                return self.extract_json(content)
            return content

    def analyze_diff_with_tools(self, diff):
        """Analyzes a diff and returns a list of potential vulnerabilities."""
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
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE username = '{{username}}'\")"
    }}
  ]
}}
"""
        if self.llm_provider == 'gemini':
            response = self.model.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                tools=self.tools
            )
            return response
        elif self.llm_provider in ['llama.cpp', 'ollama']:
            return self._create_chat_completion(prompt)

    def get_ollama_models(self):
        """Gets the list of available Ollama models."""
        if self.llm_provider == 'ollama':
            try:
                return [model['name'] for model in self.model.list()['models']]
            except Exception as e:
                print(f"Error getting Ollama models: {e}")
                return []
        return []

    def analyze_file(self, file_path):
        """Analyzes a file and returns a list of potential vulnerabilities."""
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
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE username = '{{username}}'\")"
    }}
  ]
}}
```"""
        if self.llm_provider == 'gemini':
            response = self.model.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                tools=self.tools
            )
            return response
        elif self.llm_provider in ['llama.cpp', 'ollama']:
            return self._create_chat_completion(prompt)

    def get_root_cause_analysis(self, code_snippet, vulnerability_type):
        """Gets a root cause analysis for a vulnerability."""
        prompt = f"""You are a senior security engineer. Provide a brief explanation of this potential '{vulnerability_type}' vulnerability in the provided code snippet.

Code Snippet:
```
{code_snippet}
```

Explain the vulnerability, its potential impact, and how to fix it. Format your response as clean Markdown. Do not ask any questions."""
        return self._create_chat_completion(prompt, is_json=False)

    def generate_test_script(self, code_snippet, vulnerability_hypothesis):
        """Generates a Python test script for a vulnerability.
        
        Note: The generated code is a test script to confirm the vulnerability, not 'fake code'.
        """
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
        response = self._create_chat_completion(prompt, is_json=False)
        return self.extract_python_code(response)

    def interpret_results(self, analysis, test_script, script_output):
        """Interprets the results of a test and returns a confidence score."""
        prompt = f"""You are a senior security engineer. Based on the following analysis, test script, and its output, what is the confidence score for the vulnerability?

Analysis:
{analysis}

Test Script:
{test_script}

Script Output:
{script_output}

Respond with a single float number between 0.0 and 1.0, where 0.0 is not confident and 1.0 is very confident. Respond with ONLY the number. Example: 0.9"""
        response = self._create_chat_completion(prompt, is_json=False)
        try:
            return float(response.strip())
        except (ValueError, TypeError):
            return 0.0

    def generate_patch(self, vulnerable_code, root_cause_analysis):
        """Generates a patch for a vulnerability."""
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
        return self._create_chat_completion(prompt, is_json=False)

    def analyze_configuration(self, config_content):
        """Analyzes a configuration file for security misconfigurations."""
        prompt = f"""You are a senior security engineer. Analyze the following configuration file for security misconfigurations.

{config_content}

Respond with a JSON object containing a list of misconfigurations. Each misconfiguration should have "line_number" and "description". If none, respond with an empty list."""
        return self._create_chat_completion(prompt)

    def extract_json(self, text):
        """Extracts a JSON object from a string, handling markdown code blocks."""
        match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Fallback for non-markdown wrapped JSON
        if text.strip().startswith('{'):
            return text.strip()
        return "{}"

    def extract_python_code(self, text):
        """Extracts Python code from a markdown block."""
        match = re.search(r'```python\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()

    def validate_vulnerability(self, vulnerability_description, search_results):
        """Validates a vulnerability based on search results."""
        prompt = f"""You are a senior security engineer. Based on the following vulnerability description and search results, determine if the vulnerability is likely to be a false positive.

Vulnerability Description:
{vulnerability_description}

Search Results:
{search_results}

Respond with a JSON object with a single key, "false_positive", which is a boolean. Do not include any explanations or ask any questions."""
        return self._create_chat_completion(prompt)
