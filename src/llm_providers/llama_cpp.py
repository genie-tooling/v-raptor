
# src/llm_providers/llama_cpp.py

import re
from llama_cpp import Llama
from .base import BaseLLMProvider

class LlamaCppProvider(BaseLLMProvider):
    def __init__(self, model_path):
        self.client = Llama(model_path=model_path, n_ctx=32767, n_gpu_layers=-1, verbose=False)

    def create_chat_completion(self, model_name, prompt, is_json=True):
        response = self.client.create_chat_completion(
            messages=[
                {"role": "system", "content": "You are a senior security engineer. Respond ONLY in the requested format."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )
        content = response['choices'][0]['message']['content']
        return self.extract_json(content) if is_json else content

    def get_available_models(self):
        # llama.cpp doesn't have a way to list models, as it loads a single model file.
        # We'll return an empty list.
        return []

    def extract_json(self, text):
        match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        if text.strip().startswith('{'):
            return text.strip()
        return "{}"
