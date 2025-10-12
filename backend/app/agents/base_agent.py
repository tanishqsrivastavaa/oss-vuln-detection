from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List, Optional

from backend.app.core.config import Settings
from backend.app.core.llm import LLMClient, get_llm_client
from backend.app.core.models import Vulnerability


class VulnerabilityAgent(ABC):
	"""Base class that wraps LLM interactions for vulnerability detection."""

	def __init__(
		self,
		*,
		system_prompt: str,
		llm_client: Optional[LLMClient] = None,
		settings: Optional[Settings] = None,
	) -> None:
		self.settings = settings or Settings()
		self.system_prompt = system_prompt
		self.llm_client = llm_client or get_llm_client(self.settings)

	@abstractmethod
	async def analyze(self, *, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
		"""Analyze arbitrary content and return detected vulnerabilities."""
		raise NotImplementedError

	async def enrich_with_llm(self, prompt: str) -> str:
		"""Invoke the backing LLM if enrichment is enabled."""

		if isinstance(self.llm_client, LLMClient):
			return await self.llm_client.generate(prompt, system_prompt=self.system_prompt)

		return ""

	@staticmethod
	def deduplicate(vulnerabilities: Iterable[Vulnerability]) -> List[Vulnerability]:
		"""Remove duplicates while preserving severity ordering."""

		seen = set()
		ordered: List[Vulnerability] = []
		for vuln in vulnerabilities:
			key = (
				vuln.location.file_path,
				vuln.location.line_number,
				vuln.vulnerability_type,
			)
			if key in seen:
				continue
			seen.add(key)
			ordered.append(vuln)

		severity_order = {
			"critical": 0,
			"high": 1,
			"medium": 2,
			"low": 3,
			"info": 4,
		}
		ordered.sort(key=lambda v: severity_order.get(v.severity.value, 5))
		return ordered