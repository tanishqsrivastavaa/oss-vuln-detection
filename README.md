# OSS Vulnerability Detection Platform

This project provides an enterprise-ready vulnerability detection service that combines
static (SAST), dynamic (DAST), and infrastructure configuration analysis. It is built
to run entirely within an organisation's firewall using locally hosted models such as
[Ollama](https://ollama.ai/), while optionally supporting Groq if external connectivity
is available.

## Features

- 🌐 Multi-language scanning (Python, JavaScript/TypeScript, Java, Go, Rust, C/C++, IaC, etc.)
- 🔒 SAST, DAST simulation, infrastructure/IaC misconfiguration, dependency, and secret checks
- 🧠 LLM enrichment pipeline designed for local-first deployments
- 📦 JSON-first API contract for easy integration with CI/CD and security tooling
- 🏢 Enterprise guardrails: file size limits, configurable concurrency, disable/enable scan types

## Getting Started

### Prerequisites

- Python 3.12+
- Optional: [Ollama](https://ollama.ai/) running locally with an available model (default `llama3.1`)

### Installation

```bash
uv sync
```

### Running the API

```bash
uv run python main.py
```

The FastAPI documentation is available at `http://localhost:8000/docs` once the server is running.

### Example Scan Request

```json
{
	"repository_path": "/path/to/repository",
	"include_paths": ["src"],
	"exclude_paths": ["tests"],
	"scan_types": ["sast", "dast", "infrastructure", "dependency"],
	"enable_llm_enrichment": true
}
```

Send the payload via `POST /v1/scan` to receive a comprehensive vulnerability report that includes
findings, dependency issues, remediation guidance, and summary statistics.

## Configuration

Settings are managed through environment variables (see `backend/app/core/config.py`). Key options:

- `LLM_PROVIDER`: `ollama` (default) or `groq`
- `OLLAMA_BASE_URL`, `OLLAMA_MODEL`: configure the local deployment
- `ENABLE_SAST`, `ENABLE_DAST`, `ENABLE_INFRASTRUCTURE_SCAN`, `ENABLE_SECRET_SCAN`, `ENABLE_DEPENDENCY_SCAN`
- `MAX_FILE_SIZE_MB`, `MAX_REPO_SIZE_MB`, `MAX_CONCURRENT_SCANS`

Create a `.env` file in the project root or export variables directly in your environment.

## Development

- Code style and formatting follow the defaults of the FastAPI/Pydantic ecosystem.
- Contributions should include automated checks before submission:

```bash
uv run ruff check
uv run pytest
```

## Roadmap

- Expand dependency intelligence by integrating OSS advisory feeds
- Provide PDF report rendering and dashboard visualisations
- Add integrations for ticketing systems and SIEM platforms