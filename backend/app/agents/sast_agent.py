from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List

from backend.app.core.models import (
    CodeLocation,
    SeverityLevel,
    Vulnerability,
)
from backend.app.core.patterns import PATTERN_LIBRARY

from .base_agent import VulnerabilityAgent


SAST_SYSTEM_PROMPT = """
You are a static application security testing (SAST) assistant. Analyse the provided
source code and highlight concrete security vulnerabilities. Focus on:
- Injection flaws (SQL, command, code)
- Authentication and authorisation weaknesses
- Cryptographic misuse
- Insecure file handling and path traversal
- Data exposure and secret leakage

Return actionable findings with CWE references and precise remediation guidance.
"""


class SASTAgent(VulnerabilityAgent):
    """Detects code-level vulnerabilities using pattern libraries and LLM enrichment."""

    def __init__(self) -> None:
        super().__init__(system_prompt=SAST_SYSTEM_PROMPT)

    async def analyze(self, *, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        findings: List[Vulnerability] = []

        findings.extend(self._pattern_scan(content, context))

        if context.get("enable_llm", True) and findings:
            findings = await self._enrich_findings(findings, content, context)

        return self.deduplicate(findings)

    def _pattern_scan(self, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        file_path = context.get("file_path", "unknown")
        language = context.get("language", "unknown")
        lines = content.splitlines()

        for vuln_type, payload in PATTERN_LIBRARY.items():
            for pattern in payload["patterns"]:
                expression = re.compile(pattern)
                for line_number, line in enumerate(lines, start=1):
                    if expression.search(line):
                        results.append(
                            Vulnerability(
                                id=str(uuid.uuid4()),
                                title=f"Potential {vuln_type.value.replace('_', ' ').title()}",
                                description=payload["description"],
                                severity=payload["severity"],
                                vulnerability_type=vuln_type,
                                cwe_id=payload.get("cwe_id"),
                                owasp_category=payload.get("owasp"),
                                location=CodeLocation(
                                    file_path=file_path,
                                    line_number=line_number,
                                ),
                                affected_code=line.strip(),
                                impact="Could allow attackers to compromise the application.",
                                likelihood="Medium",
                                remediation="Apply input validation, sanitisation, or safer APIs.",
                                remediation_effort="Medium",
                                confidence=0.6,
                                references=[
                                    "https://cwe.mitre.org/data/definitions/" + payload.get("cwe_id", ""),
                                ],
                                tags=["sast", language],
                            )
                        )
        return results

    async def _enrich_findings(
        self,
        findings: List[Vulnerability],
        content: str,
        context: Dict[str, Any],
    ) -> List[Vulnerability]:
        prompt = (
            "Analyse the following source file and refine the vulnerability findings.\n"
            "Provide a JSON array keyed by vulnerability id with updated description,"
            " severity, remediation, and secure example if applicable. File path:"
            f" {context.get('file_path', 'unknown')}\n\n"
            f"Existing findings: {[f.dict() for f in findings]}\n\n"
            f"Code snippet:\n{content}\n"
        )

        response = await self.enrich_with_llm(prompt)
        if not response:
            return findings

        # Lightweight parser: expect JSON but fall back silently on failure.
        try:
            import json

            updates = json.loads(response)
        except json.JSONDecodeError:
            return findings

        if isinstance(updates, dict):
            for finding in findings:
                data = updates.get(finding.id)
                if not isinstance(data, dict):
                    continue
                if "severity" in data:
                    try:
                        finding.severity = SeverityLevel(data["severity"])
                    except ValueError:
                        pass
                finding.description = data.get("description", finding.description)
                finding.remediation = data.get("remediation", finding.remediation)
                finding.remediation_effort = data.get("remediation_effort", finding.remediation_effort)
                finding.impact = data.get("impact", finding.impact)
                if secure_example := data.get("secure_code_example"):
                    finding.secure_code_example = secure_example
                if confidence := data.get("confidence"):
                    try:
                        finding.confidence = float(confidence)
                    except (TypeError, ValueError):
                        pass
        return findings