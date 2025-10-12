from __future__ import annotations

import pathlib
from typing import Optional

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".kt": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".tf": "terraform",
    "dockerfile": "dockerfile",
}


def detect_language(file_path: str, content: Optional[str] = None) -> str:
    """Best-effort language detection using file extension and heuristics."""

    path = pathlib.Path(file_path)
    suffix = path.suffix.lower()
    if suffix in LANGUAGE_MAP:
        return LANGUAGE_MAP[suffix]

    name = path.name.lower()
    if name in LANGUAGE_MAP:
        return LANGUAGE_MAP[name]

    if content:
        snippet = content.strip().splitlines()[:5]
        joined = "\n".join(snippet)
        if "terraform" in joined.lower() or "resource \"aws_" in joined:
            return "terraform"
        if joined.startswith("FROM "):
            return "dockerfile"
        if "apiVersion:" in joined and "kind:" in joined:
            return "kubernetes"

    return "unknown"


def should_scan_file(file_path: str) -> bool:
    """Return True if the file should be scanned based on extension."""

    language = detect_language(file_path)
    return language != "unknown"
