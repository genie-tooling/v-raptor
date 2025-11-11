
# src/llm_providers/gemini.py

import os
from google import genai
from .base import BaseLLMProvider

class GeminiProvider(BaseLLMProvider):
    def __init__(self, api_key, timeout: int = 60):
        super().__init__(timeout=timeout)
        if not api_key or "YOUR_API_KEY" in api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        self.client = genai.Client(api_key=api_key)

    def create_chat_completion(self, model_name, prompt, is_json=True):
        response = self.client.generate_content(
            model=model_name,
            contents=prompt,
            request_options={'timeout': self.timeout}
        )
        return response.text

    def get_available_models(self):
        # The Gemini API doesn't have a public method to list available models.
        # We'll return a hardcoded list of common models.
        return [
            'gemini-1.5-flash-latest',
            'gemini-1.5-pro-latest',
            'gemini-1.0-pro',
        ]
