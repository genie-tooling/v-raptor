
# src/llm_providers/base.py

from abc import ABC, abstractmethod

class BaseLLMProvider(ABC):
    @abstractmethod
    def create_chat_completion(self, model_name, prompt, is_json):
        pass

    @abstractmethod
    def get_available_models(self):
        pass
