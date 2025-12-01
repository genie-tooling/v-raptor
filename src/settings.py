# src/settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Dict, Union, Any

class Settings(BaseSettings):
    # --- Scanner Model Configuration ---
    SCANNER_LLM_PROVIDER: str = 'ollama'
    SCANNER_LLAMA_CPP_MODEL_PATH: str = '/path/to/your/scanner/model.gguf'
    SCANNER_OLLAMA_MODEL: str = 'gemma3:latest'
    SCANNER_OLLAMA_URL: str = 'http://localhost:11434'
    SCANNER_GEMINI_MODEL: str = 'gemini-1.5-flash-latest'

    # --- Patcher Model Configuration ---
    PATCHER_LLM_PROVIDER: str = 'ollama'
    PATCHER_LLAMA_CPP_MODEL_PATH: str = '/path/to/your/patcher/model.gguf'
    PATCHER_OLLAMA_MODEL: str = 'gemma3:latest'
    PATCHER_OLLAMA_URL: str = 'http://localhost:11434'
    PATCHER_GEMINI_MODEL: str = 'gemini-1.5-pro-latest'

    # --- LLM Timeout ---
    LLM_TIMEOUT: int = 60

    # --- Database Configuration ---
    DATABASE_URL: str = 'sqlite:///v-raptor.db'

    # --- Tool Paths ---
    GITLEAKS_PATH: str = 'gitleaks'
    SEMGREP_PATH: str = 'semgrep'
    BANDIT_PATH: str = 'bandit'
    BRAKEMAN_PATH: str = 'brakeman'
    NJSSCAN_PATH: str = 'njsscan'
    GOSEC_PATH: str = 'gosec'
    CPPCHECK_PATH: str = 'cppcheck'
    RUBYCRITIC_PATH: str = 'rubycritic'
    NODE_QUALITY_TOOL_PATH: str = 'plato'
    GOCYCLO_PATH: str = 'gocyclo'
    RUST_QUALITY_TOOL_PATH: str = 'rust-code-analysis'
    CPP_QUALITY_TOOL_PATH: str = 'lizard'
    SAST_GLOBAL_EXCLUSIONS: List[str] = ['.gitignore', '*.md']
    GENERATE_TEST_SCRIPT_DEFAULT: bool = False
    
    # --- Docker / Sandbox ---
    DOCKER_REGISTRY: str = 'docker.io' 
    RUN_TESTS_IN_CONTAINER_DEFAULT: bool = True # New Global Setting
    
    # Images list. Supports strings or dicts {'image': '...', 'entrypoint': '...'}
    TEST_CONTAINER_IMAGES: List[Union[str, Dict[str, str]]] = [
        {'image': 'ghcr.io/astral-sh/uv:python3.12-bookworm-slim', 'entrypoint': '/bin/sh'},
        {'image': 'python:3.10-slim-bookworm', 'entrypoint': '/bin/sh'}
    ]

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', case_sensitive=False)

settings = Settings()