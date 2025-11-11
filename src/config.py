    
# src/config.py

# --- Scanner Model Configuration ---
SCANNER_LLM_PROVIDER = 'ollama'  # gemini, llama.cpp, or ollama
SCANNER_LLAMA_CPP_MODEL_PATH = '/path/to/your/scanner/model.gguf'
SCANNER_OLLAMA_MODEL = 'gemma3:latest'
SCANNER_OLLAMA_URL = 'http://localhost:11434'
SCANNER_GEMINI_MODEL = 'gemini-1.5-flash-latest'

# --- Patcher Model Configuration ---
PATCHER_LLM_PROVIDER = 'ollama'  # gemini, llama.cpp, or ollama
PATCHER_LLAMA_CPP_MODEL_PATH = '/path/to/your/patcher/model.gguf'
PATCHER_OLLAMA_MODEL = 'gemma3:latest'
PATCHER_OLLAMA_URL = 'http://localhost:11434'
PATCHER_GEMINI_MODEL = 'gemini-1.5-pro-latest'

# --- LLM Timeout ---
LLM_TIMEOUT = 60 # in seconds

# --- Database Configuration ---
DATABASE_URL = 'sqlite:///v-raptor.db'

# --- Tool Paths ---
GITLEAKS_PATH = 'gitleaks'
SEMGREP_PATH = 'semgrep'
BANDIT_PATH = 'bandit'

  