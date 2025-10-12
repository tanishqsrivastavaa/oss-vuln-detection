from enum import Enum
from typing import List, Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv(dotenv_path=".env", override=True)


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OLLAMA = "ollama"  # Local, air-gapped friendly models
    GROQ = "groq"


class Settings(BaseSettings):
    """Global application configuration."""

    # Application metadata
    APP_NAME: str = "OSS Vulnerability Detection"
    APP_VERSION: str = "0.1.0"

    # LLM configuration (defaults to local provider)
    LLM_PROVIDER: LLMProvider = LLMProvider.OLLAMA
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1"
    GROQ_API_KEY: Optional[str] = None

    # Scan toggles
    ENABLE_SAST: bool = True
    ENABLE_DAST: bool = True
    ENABLE_INFRASTRUCTURE_SCAN: bool = True
    ENABLE_SECRET_SCAN: bool = True
    ENABLE_DEPENDENCY_SCAN: bool = True

    # Language support
    SUPPORTED_LANGUAGES: List[str] = [
        "python",
        "javascript",
        "typescript",
        "java",
        "c",
        "cpp",
        "csharp",
        "go",
        "rust",
        "php",
        "ruby",
        "kotlin",
        "swift",
        "scala",
        "shell",
        "dockerfile",
        "yaml",
        "json",
        "terraform",
    ]

    # Enterprise limits
    MAX_FILE_SIZE_MB: int = 20
    MAX_REPO_SIZE_MB: int = 1000
    MAX_CONCURRENT_SCANS: int = 4

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"