from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List

from backend.app.core.models import CodeLocation, SeverityLevel, Vulnerability, VulnerabilityType

from .base_agent import VulnerabilityAgent


DAST_SYSTEM_PROMPT = """
You simulate dynamic application security testing (DAST) by virtually probing
HTTP endpoints, RPC handlers, and service interfaces based on their source code.
Focus on identifying runtime weaknesses such as:
- Insecure HTTP usage (missing TLS, HSTS)
- Lack of input validation on request handlers
- Unsanitised user controlled data being returned
- Missing rate limiting or brute-force protection
- Verbose error disclosure
Present each issue with remediation tactics suitable for production systems.
"""


class DASTAgent(VulnerabilityAgent):
    """Estimates runtime vulnerabilities from request-handling code."""

    FINDING_DEFINITIONS = [
        {
            "pattern": re.compile(r"https?://[\w.-]+", re.IGNORECASE),
            "title": "Potential insecure outbound HTTP request",
            "description": "HTTP requests should enforce TLS and certificate validation.",
            "vulnerability_type": VulnerabilityType.MISCONFIGURATION,
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Use HTTPS with certificate pinning or trusted CA bundles.",
            "cwe": "CWE-319",
        },
        {
            "pattern": re.compile(r"@app\.(get|post|put|delete|patch)\(.*\)", re.IGNORECASE),
            "title": "Unvalidated request handler",
            "description": "Endpoint definitions detected without explicit validation decorators.",
            "vulnerability_type": VulnerabilityType.AUTHORIZATION,
            "severity": SeverityLevel.HIGH,
            "remediation": "Add authentication/authorisation middleware and input validation schemas.",
            "cwe": "CWE-285",
        },
        {
            "pattern": re.compile(r"raise\s+HTTPException\([^)]*detail=.*\)", re.IGNORECASE),
            "title": "Verbose error message leak",
            "description": "Detailed exception messages may leak sensitive implementation details.",
            "vulnerability_type": VulnerabilityType.MISCONFIGURATION,
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Replace verbose messages with generic errors and audit logs.",
            "cwe": "CWE-209",
        },
    ]

    def __init__(self) -> None:
        super().__init__(system_prompt=DAST_SYSTEM_PROMPT)

    async def analyze(self, *, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        lines = content.splitlines()

        for definition in self.FINDING_DEFINITIONS:
            for line_number, line in enumerate(lines, start=1):
                if definition["pattern"].search(line):
                    findings.append(
                        Vulnerability(
                            id=str(uuid.uuid4()),
                            title=definition["title"],
                            description=definition["description"],
                            severity=definition["severity"],
                            vulnerability_type=definition["vulnerability_type"],
                            cwe_id=definition["cwe"],
                            owasp_category="A05:2021 - Security Misconfiguration",
                            location=CodeLocation(
                                file_path=context.get("file_path", "unknown"),
                                line_number=line_number,
                            ),
                            affected_code=line.strip(),
                            impact="Could enable attackers to exploit runtime weaknesses.",
                            likelihood="Medium",
                            remediation=definition["remediation"],
                            remediation_effort="Medium",
                            confidence=0.5,
                            tags=["dast", context.get("language", "unknown")],
                        )
                    )

        if context.get("enable_llm", True) and findings:
            return await self._llm_enrich(findings, content, context)

        return self.deduplicate(findings)

    async def _llm_enrich(
        self,
        findings: List[Vulnerability],
        content: str,
        context: Dict[str, Any],
    ) -> List[Vulnerability]:
        prompt = (
            "Act as a DAST engine reviewing these endpoints."
            " Validate whether the flagged issues are accurate and suggest"
            " missing runtime findings if any. Return JSON keyed by id with"
            " updated severity and remediation guidance."
            f" Existing findings: {[f.dict() for f in findings]}\n\n"
            f"Source code:\n{content}\n"
        )

        response = await self.enrich_with_llm(prompt)
        if not response:
            return self.deduplicate(findings)

        try:
            import json

            updates = json.loads(response)
        except json.JSONDecodeError:
            return self.deduplicate(findings)

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
                finding.remediation = data.get("remediation", finding.remediation)
                finding.description = data.get("description", finding.description)
                if extra := data.get("additional_findings"):
                    finding.tags.append("llm-notes")
                    finding.references.append(str(extra))
        return self.deduplicate(findings)