from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    CSRF = "csrf"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    DESERIALIZATION = "insecure_deserialization"
    AUTHORIZATION = "broken_authorization"
    AUTHENTICATION = "authentication_bypass"
    MISCONFIGURATION = "misconfiguration"
    SECRET_EXPOSURE = "secret_exposure"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    INSECURE_CRYPTO = "insecure_crypto"
    SSRF = "ssrf"
    RCE = "rce"
    OTHER = "other"


class CodeLocation(BaseModel):
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    severity: SeverityLevel
    vulnerability_type: VulnerabilityType
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    location: CodeLocation
    affected_code: str
    impact: str
    likelihood: str
    remediation: str
    remediation_effort: str
    secure_code_example: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class DependencyVulnerability(BaseModel):
    package_name: str
    package_version: str
    advisory_id: str
    severity: SeverityLevel
    description: str
    fixed_versions: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    repository_path: str = Field(..., description="Absolute path to repository or archive to scan")
    include_paths: List[str] = Field(default_factory=list)
    exclude_paths: List[str] = Field(default_factory=list)
    scan_types: List[str] = Field(default_factory=lambda: ["sast", "dast", "infrastructure", "secrets", "dependency"])
    enable_llm_enrichment: bool = True


class FileAnalysis(BaseModel):
    file_path: str
    language: str
    size_bytes: int
    num_lines: int
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"
    scan_request: ScanRequest
    files_analyzed: List[FileAnalysis] = Field(default_factory=list)
    dependency_vulnerabilities: List[DependencyVulnerability] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)


class RemediationItem(BaseModel):
    vulnerability_id: str
    priority: int
    effort_hours: float
    steps: List[str]
    owners: List[str] = Field(default_factory=list)
    testing_strategy: str


class ScanReport(BaseModel):
    metadata: Dict[str, Any]
    summary: Dict[str, Any]
    vulnerabilities: List[Vulnerability]
    dependency_vulnerabilities: List[DependencyVulnerability]
    remediation_plan: List[RemediationItem]