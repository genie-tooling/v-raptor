
# src/llm_providers/ollama.py

import re
from ollama import Client
from .base import BaseLLMProvider

class OllamaProvider(BaseLLMProvider):
    def __init__(self, host_url):
        self.client = Client(host=host_url)

    def create_chat_completion(self, model_name, prompt, is_json=True):
        response = self.client.chat(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a senior security engineer. Respond ONLY in the requested format."},
                {"role": "user", "content": prompt}
            ],
            options={'num_ctx': 32767}
        )
        content = response['message']['content']
        return self.extract_json(content) if is_json else content

    def get_available_models(self):
        try:
            return [model['name'] for model in self.client.list()['models']]
        except Exception as e:
            print(f"Error getting Ollama models: {e}")
            return []

    def extract_json(self, text):
        match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        if text.strip().startswith('{'):
            return text.strip()
        return "{}"
