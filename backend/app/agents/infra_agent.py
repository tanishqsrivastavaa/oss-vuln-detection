from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List

from backend.app.core.models import (
    CodeLocation,
    SeverityLevel,
    Vulnerability,
    VulnerabilityType,
)

from .base_agent import VulnerabilityAgent


INFRA_SYSTEM_PROMPT = """
You perform infrastructure-as-code (IaC) and configuration reviews. Identify
settings that weaken security posture across Terraform, Kubernetes manifests,
Dockerfiles, CI pipelines, and shell scripts. Flag misconfigurations, missing
least privilege controls, insecure networking, weak cryptography, and
observability gaps. Provide remediation tailored for enterprise environments.
"""


class InfrastructureAgent(VulnerabilityAgent):
    """Detects infrastructure misconfigurations and insecure defaults."""

    RULES = [
        {
            "pattern": re.compile(r"0\.0\.0\.0/0"),
            "title": "Wide-open network access",
            "description": "CIDR 0.0.0.0/0 exposes services to the internet.",
            "type": VulnerabilityType.MISCONFIGURATION,
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Restrict access to trusted CIDR ranges or use private networking.",
            "cwe": "CWE-284",
        },
        {
            "pattern": re.compile(r"privileged:\s*true", re.IGNORECASE),
            "title": "Privileged container",
            "description": "Running containers in privileged mode breaks isolation guarantees.",
            "type": VulnerabilityType.MISCONFIGURATION,
            "severity": SeverityLevel.HIGH,
            "remediation": "Remove privileged mode and grant only necessary capabilities.",
            "cwe": "CWE-250",
        },
        {
            "pattern": re.compile(r"ALLOW_EMPTY_PASSWORD\s*=\s*yes", re.IGNORECASE),
            "title": "Default credential policy",
            "description": "Services allow empty passwords, enabling trivial compromise.",
            "type": VulnerabilityType.AUTHENTICATION,
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enforce strong authentication requirements and rotate credentials.",
            "cwe": "CWE-521",
        },
        {
            "pattern": re.compile(r"(?i)sslmode\s*=\s*disable"),
            "title": "Disabled TLS for database connection",
            "description": "Database connection disables TLS, risking data exposure.",
            "type": VulnerabilityType.MISCONFIGURATION,
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable TLS/SSL for all database connections.",
            "cwe": "CWE-319",
        },
    ]

    def __init__(self) -> None:
        super().__init__(system_prompt=INFRA_SYSTEM_PROMPT)

    async def analyze(self, *, content: str, context: Dict[str, Any]) -> List[Vulnerability]:
        file_path = context.get("file_path", "unknown")
        lines = content.splitlines()
        findings: List[Vulnerability] = []

        for rule in self.RULES:
            for line_number, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    findings.append(
                        Vulnerability(
                            id=str(uuid.uuid4()),
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            vulnerability_type=rule["type"],
                            cwe_id=rule["cwe"],
                            owasp_category="A05:2021 - Security Misconfiguration",
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=line_number,
                            ),
                            affected_code=line.strip(),
                            impact="Could expose infrastructure to attackers or reduce isolation.",
                            likelihood="High",
                            remediation=rule["remediation"],
                            remediation_effort="Medium",
                            confidence=0.65,
                            references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                            tags=["infrastructure", context.get("language", "config")],
                        )
                    )

        if context.get("enable_llm", True) and findings:
            return await self._llm_contextualise(findings, content, context)

        return self.deduplicate(findings)

    async def _llm_contextualise(
        self,
        findings: List[Vulnerability],
        content: str,
        context: Dict[str, Any],
    ) -> List[Vulnerability]:
        prompt = (
            "Review this infrastructure configuration and validate the findings."
            " Suggest additional hardening steps, network controls, or compliance"
            " considerations. Return JSON keyed by vulnerability id with optional"
            " notes field."
            f" Findings: {[f.dict() for f in findings]}\n\n"
            f"Configuration snippet:\n{content}\n"
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
                if "notes" in data:
                    finding.references.append(str(data["notes"]))
                if "remediation" in data:
                    finding.remediation = data["remediation"]
                if "severity" in data:
                    try:
                        finding.severity = SeverityLevel(data["severity"])
                    except ValueError:
                        pass
        return self.deduplicate(findings)
