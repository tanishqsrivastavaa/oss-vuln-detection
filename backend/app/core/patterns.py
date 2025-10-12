from typing import Any, Dict

from backend.app.core.models import SeverityLevel, VulnerabilityType


PATTERN_LIBRARY: Dict[VulnerabilityType, Dict[str, Any]] = {
    VulnerabilityType.SQL_INJECTION: {
        "description": "Usage of dynamic SQL queries constructed via string concatenation",
        "patterns": [
            r"(?i)select\s+.+\s+from.+['\"]\s*\+",
            r"(?i)execute\s*\(.+\+.+\)",
            r"(?i)cursor\.execute\(.+%s.+\)",
        ],
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-89",
        "owasp": "A03:2021- Injection",
    },
    VulnerabilityType.COMMAND_INJECTION: {
        "description": "Execution of unsanitised command strings",
        "patterns": [
            r"os\.system\(.*\+.*\)",
            r"subprocess\.(Popen|call|run)\(.*shell=True",
            r"Runtime\.getRuntime\(\)\.exec",
        ],
        "severity": SeverityLevel.CRITICAL,
        "cwe_id": "CWE-78",
        "owasp": "A03:2021- Injection",
    },
    VulnerabilityType.DIRECTORY_TRAVERSAL: {
        "description": "Paths allowing traversal outside allowed directories",
        "patterns": [
            r"\.\./",
            r"(?i)path\.join\(.*user_input",
        ],
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-22",
        "owasp": "A01:2021- Broken Access Control",
    },
    VulnerabilityType.CROSS_SITE_SCRIPTING: {
        "description": "Unescaped user input written to HTML contexts",
        "patterns": [
            r"innerHTML\s*=.+",
            r"document\.write\(",
            r"res\.send\(.*\+.*\)",
        ],
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-79",
        "owasp": "A03:2021- Injection",
    },
    VulnerabilityType.SECRET_EXPOSURE: {
        "description": "Potential hard-coded secret or credential",
        "patterns": [
            r"(?i)(password|apikey|secret|token)\s*=\s*['\"][A-Za-z0-9+/=]{8,}['\"]",
            r"AKIA[0-9A-Z]{16}",
            r"xox[baprs]-[0-9A-Za-z-]{10,}",
        ],
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-798",
        "owasp": "A02:2021- Cryptographic Failures",
    },
}