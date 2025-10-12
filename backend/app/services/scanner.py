from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, cast

from packaging import version

from backend.app.core.config import Settings
from backend.app.core.models import (
    DependencyVulnerability,
    FileAnalysis,
    ScanRequest,
    ScanResult,
    SeverityLevel,
    Vulnerability,
)
from backend.app.services.language_detector import detect_language, should_scan_file

from backend.app.agents.dast_agent import DASTAgent
from backend.app.agents.infra_agent import InfrastructureAgent
from backend.app.agents.sast_agent import SASTAgent


class VulnerabilityScanner:
    """Coordinates SAST, DAST, and infrastructure scanning for repositories."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or Settings()
        self.sast_agent = SASTAgent() if self.settings.ENABLE_SAST else None
        self.dast_agent = DASTAgent() if self.settings.ENABLE_DAST else None
        self.infra_agent = (
            InfrastructureAgent() if self.settings.ENABLE_INFRASTRUCTURE_SCAN else None
        )

    async def scan(self, request: ScanRequest) -> ScanResult:
        scan_id = str(uuid.uuid4())
        started = datetime.utcnow()
        repository_path = Path(request.repository_path)
        if not repository_path.exists():
            raise FileNotFoundError(f"Path {repository_path} does not exist")

        files_to_scan = self._collect_files(repository_path, request)

        result = ScanResult(
            scan_id=scan_id,
            started_at=started,
            scan_request=request,
            files_analyzed=[],
        )

        for file_path in files_to_scan:
            try:
                analysis = await self._scan_file(file_path, request)
                if analysis:
                    result.files_analyzed.append(analysis)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"Failed to scan {file_path}: {exc}")

        result.dependency_vulnerabilities = self._scan_dependencies(repository_path)

        result.summary = self._summarise(result)
        result.completed_at = datetime.utcnow()
        result.status = "completed"
        return result

    def _collect_files(self, root: Path, request: ScanRequest) -> List[Path]:
        include_paths = {root / path for path in request.include_paths} if request.include_paths else None
        exclude_set = {root / path for path in request.exclude_paths}
        files: List[Path] = []

        for file in root.rglob("*"):
            if not file.is_file():
                continue
            if include_paths and not any(str(file).startswith(str(include_path)) for include_path in include_paths):
                continue
            if any(str(file).startswith(str(excluded)) for excluded in exclude_set):
                continue
            if not should_scan_file(str(file)):
                continue
            size_mb = file.stat().st_size / (1024 * 1024)
            if size_mb > self.settings.MAX_FILE_SIZE_MB:
                continue
            files.append(file)
        return files

    async def _scan_file(self, file_path: Path, request: ScanRequest) -> Optional[FileAnalysis]:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        language = detect_language(str(file_path), content)
        num_lines = content.count("\n") + 1

        vulnerabilities: List[Vulnerability] = []
        tasks: List[asyncio.Task[List[Vulnerability]]] = []

        context = {
            "file_path": str(file_path),
            "language": language,
            "enable_llm": request.enable_llm_enrichment,
        }

        if self.sast_agent and language not in {"yaml", "json", "terraform", "dockerfile", "kubernetes"}:
            tasks.append(asyncio.create_task(self.sast_agent.analyze(content=content, context=context)))
        if self.dast_agent and language in {"python", "javascript", "typescript", "go", "java"}:
            tasks.append(asyncio.create_task(self.dast_agent.analyze(content=content, context=context)))
        if self.infra_agent and language in {"terraform", "yaml", "json", "dockerfile", "kubernetes"}:
            tasks.append(asyncio.create_task(self.infra_agent.analyze(content=content, context=context)))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in results:
                if isinstance(outcome, Exception):
                    continue
                vulnerabilities.extend(cast(List[Vulnerability], outcome))

        if not vulnerabilities:
            return None

        return FileAnalysis(
            file_path=str(file_path),
            language=language,
            size_bytes=len(content.encode("utf-8")),
            num_lines=num_lines,
            vulnerabilities=vulnerabilities,
        )

    def _scan_dependencies(self, root: Path) -> List[DependencyVulnerability]:
        findings: List[DependencyVulnerability] = []

        requirements_file = root / "requirements.txt"
        if requirements_file.exists():
            for line in requirements_file.read_text().splitlines():
                if "==" not in line:
                    continue
                package, pkg_version = line.split("==", maxsplit=1)
                package = package.strip()
                pkg_version = pkg_version.strip()
                findings.extend(self._check_python_dependency(package, pkg_version))

        package_json = root / "package.json"
        if package_json.exists():
            data = json.loads(package_json.read_text())
            deps = data.get("dependencies", {}) | data.get("devDependencies", {})
            for package, pkg_version in deps.items():
                findings.extend(self._check_js_dependency(package, pkg_version))

        return findings

    def _check_python_dependency(self, package: str, pkg_version: str) -> List[DependencyVulnerability]:
        vulnerable: Dict[str, Dict[str, str]] = {
            "requests": {"fixed": "2.32.0", "cve": "CVE-2023-32681"},
            "django": {"fixed": "4.2.8", "cve": "CVE-2023-43665"},
        }

        details = vulnerable.get(package.lower())
        if not details:
            return []

        if version.parse(pkg_version) < version.parse(details["fixed"]):
            return [
                DependencyVulnerability(
                    package_name=package,
                    package_version=pkg_version,
                    advisory_id=details["cve"],
                    severity=SeverityLevel.HIGH,
                    description=f"{package} {pkg_version} is affected by {details['cve']}.",
                    fixed_versions=[details["fixed"]],
                    references=[f"https://nvd.nist.gov/vuln/detail/{details['cve']}"]
                )
            ]
        return []

    def _check_js_dependency(self, package: str, pkg_version: str) -> List[DependencyVulnerability]:
        vulnerable: Dict[str, Dict[str, str]] = {
            "lodash": {"fixed": "4.17.21", "cve": "CVE-2021-23337"},
            "express": {"fixed": "4.17.3", "cve": "CVE-2022-25840"},
        }

        pkg_version = pkg_version.lstrip("^~>=<")
        details = vulnerable.get(package.lower())
        if not details:
            return []

        if version.parse(pkg_version) < version.parse(details["fixed"]):
            return [
                DependencyVulnerability(
                    package_name=package,
                    package_version=pkg_version,
                    advisory_id=details["cve"],
                    severity=SeverityLevel.HIGH,
                    description=f"{package} {pkg_version} is affected by {details['cve']}.",
                    fixed_versions=[details["fixed"]],
                    references=[f"https://nvd.nist.gov/vuln/detail/{details['cve']}"]
                )
            ]
        return []

    def _summarise(self, result: ScanResult) -> Dict[str, int]:
        severity_counts: Dict[str, int] = {
            level.value: 0 for level in SeverityLevel
        }
        for analysis in result.files_analyzed:
            for finding in analysis.vulnerabilities:
                severity_counts[finding.severity.value] += 1
        for dep in result.dependency_vulnerabilities:
            severity_counts[dep.severity.value] += 1
        return severity_counts
