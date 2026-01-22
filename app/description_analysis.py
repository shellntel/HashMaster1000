"""
AD Description Analysis Module

Analyzes Active Directory user account descriptions for sensitive information
including disclosed passwords, PII, and embedded credentials.

Categories detected:
- Passwords: Explicit password mentions ("password:", "pwd:", "p/w:")
- PII: SSNs, phone numbers, addresses, dates of birth
- Credentials: API keys, tokens, PINs, service account credentials
"""

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class FindingCategory(str, Enum):
    """Categories of sensitive information found in descriptions."""
    PASSWORD = "Password"
    PII_SSN = "SSN"
    PII_PHONE = "Phone Number"
    PII_DOB = "Date of Birth"
    PII_EMAIL = "Email Address"
    CREDENTIAL_API_KEY = "API Key"
    CREDENTIAL_TOKEN = "Token"
    CREDENTIAL_PIN = "PIN"


@dataclass
class DescriptionFinding:
    """A single finding in an account description."""
    category: str
    value: str  # The found value (masked for display)
    raw_value: str  # Original value for internal use
    confidence: float  # 0.0-1.0
    detection_method: str  # "regex"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "value": self.value,
            "confidence": self.confidence,
            "detection_method": self.detection_method
        }


@dataclass
class AccountDescriptionAnalysis:
    """Analysis results for a single account's description."""
    sam_account_name: str
    description: str
    has_findings: bool = False
    findings: list[DescriptionFinding] = field(default_factory=list)
    finding_count: int = 0
    severity: str = "None"  # "Critical", "High", "Medium", "Low", "None"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sam_account_name": self.sam_account_name,
            "description": self.description,
            "has_findings": self.has_findings,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": self.finding_count,
            "severity": self.severity
        }


@dataclass
class DescriptionAnalysisSummary:
    """Summary statistics for description analysis."""
    total_accounts_analyzed: int = 0
    accounts_with_description: int = 0
    accounts_without_description: int = 0
    accounts_with_findings: int = 0

    # By category
    password_disclosures: int = 0
    pii_findings: int = 0
    credential_findings: int = 0

    # Breakdown
    ssn_count: int = 0
    phone_count: int = 0
    dob_count: int = 0
    email_count: int = 0
    api_key_count: int = 0
    token_count: int = 0
    pin_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SampleDescription:
    """A sample description for display (proof that analysis ran)."""
    account_name: str
    description: str  # Truncated for display

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_name": self.account_name,
            "description": self.description
        }


@dataclass
class DescriptionAnalysisReport:
    """Complete description analysis report."""
    summary: DescriptionAnalysisSummary
    findings: list[AccountDescriptionAnalysis]
    chart_data: dict[str, Any]
    sample_descriptions: list[SampleDescription] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings if f.has_findings],
            "chart_data": self.chart_data,
            "sample_descriptions": [s.to_dict() for s in self.sample_descriptions],
            "generated_at": self.generated_at
        }


# Regex patterns for detection
PASSWORD_PATTERNS = [
    # Explicit password mentions
    (r"(?i)(?:password|pwd|p/w|pass)\s*[:=]\s*['\"]?(\S+)['\"]?", "high"),
    (r"(?i)(?:temp(?:orary)?\s*(?:password|pwd)|initial\s*(?:password|pwd))\s*[:=]?\s*['\"]?(\S+)['\"]?", "high"),
    (r"(?i)(?:default\s*(?:password|pwd))\s*[:=]?\s*['\"]?(\S+)['\"]?", "high"),
    # Password hints
    (r"(?i)(?:same\s*as|uses)\s*(?:password|pwd)\s*(?:for|from|as)\s+(\S+)", "medium"),
]

# SSN patterns - 9 digits with or without dashes
SSN_PATTERN = re.compile(r"\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b")

# US phone number patterns
PHONE_PATTERN = re.compile(
    r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b"
)

# Date of birth patterns
DOB_PATTERNS = [
    re.compile(r"(?i)\b(?:DOB|born|birthday|birth\s*date|d\.o\.b\.?)\s*[:=]?\s*(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b"),
    re.compile(r"(?i)\b(?:DOB|born|birthday|birth\s*date|d\.o\.b\.?)\s*[:=]?\s*(\d{4}[-/]\d{1,2}[-/]\d{1,2})\b"),
]

# Email pattern
EMAIL_PATTERN = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b")

# PIN patterns
PIN_PATTERN = re.compile(r"(?i)\bpin\s*[:=]\s*(\d{4,6})\b")

# API key patterns
API_KEY_PATTERNS = [
    re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
    re.compile(r"(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
]

# Token patterns
TOKEN_PATTERNS = [
    re.compile(r"(?i)(?:token|bearer|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?"),
    re.compile(r"(?i)(?:auth[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?"),
]


def mask_sensitive_value(value: str, category: str) -> str:
    """
    Mask sensitive values for display.

    Examples:
        SSN: 123-45-6789 -> ***-**-6789
        Phone: 555-123-4567 -> ***-***-4567
        Password: mypassword -> myp*******
    """
    if not value:
        return ""

    if category in [FindingCategory.PII_SSN.value, "SSN"]:
        # Show last 4 digits only
        clean = re.sub(r"[\s-]", "", value)
        if len(clean) >= 4:
            return f"***-**-{clean[-4:]}"
        return "***-**-****"

    if category in [FindingCategory.PII_PHONE.value, "Phone Number"]:
        # Show last 4 digits only
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "***-***-****"

    if category in [FindingCategory.PASSWORD.value, "Password"]:
        # Show first 3 chars then mask
        if len(value) > 3:
            return value[:3] + "*" * (len(value) - 3)
        return "*" * len(value)

    if category in [FindingCategory.CREDENTIAL_PIN.value, "PIN"]:
        # Show just asterisks
        return "*" * len(value)

    if category in [FindingCategory.CREDENTIAL_API_KEY.value, "API Key",
                    FindingCategory.CREDENTIAL_TOKEN.value, "Token"]:
        # Show first 4 and last 4 chars
        if len(value) > 12:
            return value[:4] + "..." + value[-4:]
        return value[:2] + "..." + value[-2:] if len(value) > 4 else "****"

    if category in [FindingCategory.PII_DOB.value, "Date of Birth"]:
        # Just indicate a date was found
        return "[date redacted]"

    if category in [FindingCategory.PII_EMAIL.value, "Email Address"]:
        # Mask middle of email
        if "@" in value:
            local, domain = value.split("@", 1)
            if len(local) > 2:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            else:
                masked_local = "*" * len(local)
            return f"{masked_local}@{domain}"

    # Default: show first 3 and mask rest
    if len(value) > 3:
        return value[:3] + "*" * min(len(value) - 3, 10)
    return "*" * len(value)


def analyze_description_regex(description: str) -> list[DescriptionFinding]:
    """
    Analyze description using regex patterns.

    Returns:
        List of findings detected in the description
    """
    findings = []

    if not description:
        return findings

    # Check for password disclosures
    for pattern, confidence_level in PASSWORD_PATTERNS:
        for match in re.finditer(pattern, description):
            raw_value = match.group(1) if match.groups() else match.group(0)
            # Skip very short matches (likely false positives)
            if len(raw_value) < 3:
                continue
            findings.append(DescriptionFinding(
                category=FindingCategory.PASSWORD.value,
                value=mask_sensitive_value(raw_value, FindingCategory.PASSWORD.value),
                raw_value=raw_value,
                confidence=0.9 if confidence_level == "high" else 0.7,
                detection_method="regex"
            ))

    # Check for SSNs
    for match in SSN_PATTERN.finditer(description):
        raw_value = match.group(1)
        # Validate it looks like SSN (not all same digits, not sequential)
        clean = re.sub(r"[\s-]", "", raw_value)
        if len(set(clean)) > 1:  # Not all same digit
            findings.append(DescriptionFinding(
                category=FindingCategory.PII_SSN.value,
                value=mask_sensitive_value(raw_value, FindingCategory.PII_SSN.value),
                raw_value=raw_value,
                confidence=0.85,
                detection_method="regex"
            ))

    # Check for phone numbers
    for match in PHONE_PATTERN.finditer(description):
        raw_value = match.group(0)
        findings.append(DescriptionFinding(
            category=FindingCategory.PII_PHONE.value,
            value=mask_sensitive_value(raw_value, FindingCategory.PII_PHONE.value),
            raw_value=raw_value,
            confidence=0.8,
            detection_method="regex"
        ))

    # Check for DOB
    for pattern in DOB_PATTERNS:
        for match in pattern.finditer(description):
            raw_value = match.group(1)
            findings.append(DescriptionFinding(
                category=FindingCategory.PII_DOB.value,
                value=mask_sensitive_value(raw_value, FindingCategory.PII_DOB.value),
                raw_value=raw_value,
                confidence=0.85,
                detection_method="regex"
            ))

    # Check for email addresses (only if they look like personal info, not generic)
    for match in EMAIL_PATTERN.finditer(description):
        raw_value = match.group(1)
        # Skip generic emails
        generic_patterns = ["noreply", "admin", "support", "info", "sales", "contact"]
        if not any(g in raw_value.lower() for g in generic_patterns):
            findings.append(DescriptionFinding(
                category=FindingCategory.PII_EMAIL.value,
                value=mask_sensitive_value(raw_value, FindingCategory.PII_EMAIL.value),
                raw_value=raw_value,
                confidence=0.7,
                detection_method="regex"
            ))

    # Check for PINs
    for match in PIN_PATTERN.finditer(description):
        raw_value = match.group(1)
        findings.append(DescriptionFinding(
            category=FindingCategory.CREDENTIAL_PIN.value,
            value=mask_sensitive_value(raw_value, FindingCategory.CREDENTIAL_PIN.value),
            raw_value=raw_value,
            confidence=0.9,
            detection_method="regex"
        ))

    # Check for API keys
    for pattern in API_KEY_PATTERNS:
        for match in pattern.finditer(description):
            raw_value = match.group(1)
            findings.append(DescriptionFinding(
                category=FindingCategory.CREDENTIAL_API_KEY.value,
                value=mask_sensitive_value(raw_value, FindingCategory.CREDENTIAL_API_KEY.value),
                raw_value=raw_value,
                confidence=0.85,
                detection_method="regex"
            ))

    # Check for tokens
    for pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(description):
            raw_value = match.group(1)
            findings.append(DescriptionFinding(
                category=FindingCategory.CREDENTIAL_TOKEN.value,
                value=mask_sensitive_value(raw_value, FindingCategory.CREDENTIAL_TOKEN.value),
                raw_value=raw_value,
                confidence=0.85,
                detection_method="regex"
            ))

    return findings


def determine_severity(findings: list[DescriptionFinding]) -> str:
    """
    Determine overall severity based on findings.

    Returns:
        "Critical", "High", "Medium", "Low", or "None"
    """
    if not findings:
        return "None"

    has_password = any(f.category == FindingCategory.PASSWORD.value for f in findings)
    has_credential = any(f.category in [
        FindingCategory.CREDENTIAL_API_KEY.value,
        FindingCategory.CREDENTIAL_TOKEN.value,
        FindingCategory.CREDENTIAL_PIN.value
    ] for f in findings)
    has_ssn = any(f.category == FindingCategory.PII_SSN.value for f in findings)
    has_pii = any(f.category in [
        FindingCategory.PII_PHONE.value,
        FindingCategory.PII_DOB.value,
        FindingCategory.PII_EMAIL.value
    ] for f in findings)

    if has_password or has_ssn:
        return "Critical"
    if has_credential:
        return "High"
    if has_pii:
        return "Medium"
    return "Low"


def analyze_account_description(user_data: dict[str, Any]) -> AccountDescriptionAnalysis:
    """
    Analyze a single account's description for sensitive info.

    Args:
        user_data: User dict from ADD JSON with at minimum 'SamAccountName' and 'Description'

    Returns:
        AccountDescriptionAnalysis with findings
    """
    sam_account_name = user_data.get("SamAccountName", user_data.get("sam_account_name", ""))
    description = user_data.get("Description", user_data.get("description", ""))

    findings = analyze_description_regex(description)
    severity = determine_severity(findings)

    return AccountDescriptionAnalysis(
        sam_account_name=sam_account_name,
        description=description,
        has_findings=len(findings) > 0,
        findings=findings,
        finding_count=len(findings),
        severity=severity
    )


def generate_chart_data(
    summary: DescriptionAnalysisSummary,
    findings: list[AccountDescriptionAnalysis]
) -> dict[str, Any]:
    """
    Generate Chart.js-compatible data for visualization.

    Returns:
        Dict with chart configurations
    """
    # Category distribution bar chart
    category_labels = []
    category_counts = []

    if summary.password_disclosures > 0:
        category_labels.append("Passwords")
        category_counts.append(summary.password_disclosures)

    if summary.ssn_count > 0:
        category_labels.append("SSNs")
        category_counts.append(summary.ssn_count)

    if summary.phone_count > 0:
        category_labels.append("Phone Numbers")
        category_counts.append(summary.phone_count)

    if summary.dob_count > 0:
        category_labels.append("Dates of Birth")
        category_counts.append(summary.dob_count)

    if summary.email_count > 0:
        category_labels.append("Email Addresses")
        category_counts.append(summary.email_count)

    if summary.api_key_count > 0:
        category_labels.append("API Keys")
        category_counts.append(summary.api_key_count)

    if summary.token_count > 0:
        category_labels.append("Tokens")
        category_counts.append(summary.token_count)

    if summary.pin_count > 0:
        category_labels.append("PINs")
        category_counts.append(summary.pin_count)

    category_distribution = {
        "labels": category_labels,
        "datasets": [{
            "label": "Findings by Category",
            "data": category_counts,
            "backgroundColor": [
                "rgba(239, 68, 68, 0.8)",   # Red for passwords
                "rgba(249, 115, 22, 0.8)",  # Orange for SSNs
                "rgba(234, 179, 8, 0.8)",   # Yellow for phones
                "rgba(34, 197, 94, 0.8)",   # Green for DOB
                "rgba(59, 130, 246, 0.8)",  # Blue for emails
                "rgba(168, 85, 247, 0.8)",  # Purple for API keys
                "rgba(236, 72, 153, 0.8)",  # Pink for tokens
                "rgba(107, 114, 128, 0.8)", # Gray for PINs
            ][:len(category_labels)],
            "borderColor": [
                "rgba(239, 68, 68, 1)",
                "rgba(249, 115, 22, 1)",
                "rgba(234, 179, 8, 1)",
                "rgba(34, 197, 94, 1)",
                "rgba(59, 130, 246, 1)",
                "rgba(168, 85, 247, 1)",
                "rgba(236, 72, 153, 1)",
                "rgba(107, 114, 128, 1)",
            ][:len(category_labels)],
            "borderWidth": 1
        }]
    }

    # Description coverage pie chart
    description_coverage = {
        "labels": ["With Description", "Without Description"],
        "datasets": [{
            "data": [
                summary.accounts_with_description,
                summary.accounts_without_description
            ],
            "backgroundColor": [
                "rgba(34, 197, 94, 0.8)",
                "rgba(107, 114, 128, 0.8)"
            ],
            "borderColor": [
                "rgba(34, 197, 94, 1)",
                "rgba(107, 114, 128, 1)"
            ],
            "borderWidth": 1
        }]
    }

    # Severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f.has_findings and f.severity in severity_counts:
            severity_counts[f.severity] += 1

    severity_distribution = {
        "labels": list(severity_counts.keys()),
        "datasets": [{
            "label": "Findings by Severity",
            "data": list(severity_counts.values()),
            "backgroundColor": [
                "rgba(239, 68, 68, 0.8)",   # Critical - Red
                "rgba(249, 115, 22, 0.8)",  # High - Orange
                "rgba(234, 179, 8, 0.8)",   # Medium - Yellow
                "rgba(34, 197, 94, 0.8)",   # Low - Green
            ],
            "borderWidth": 1
        }]
    }

    return {
        "category_distribution": category_distribution,
        "description_coverage": description_coverage,
        "severity_distribution": severity_distribution
    }


def analyze_descriptions(
    users: list[dict[str, Any]],
    use_llm: bool = False,
    llm_call_fn: Any = None,
    max_samples: int = 5
) -> DescriptionAnalysisReport:
    """
    Perform complete description analysis on all users.

    Args:
        users: List of user dicts from ADD JSON
        use_llm: Whether to use LLM for enhanced detection (not implemented yet)
        llm_call_fn: Function to call LLM if use_llm is True
        max_samples: Maximum number of sample descriptions to collect (for proof check ran)

    Returns:
        Complete DescriptionAnalysisReport
    """
    summary = DescriptionAnalysisSummary()
    all_findings: list[AccountDescriptionAnalysis] = []
    sample_descriptions: list[SampleDescription] = []

    summary.total_accounts_analyzed = len(users)

    for user in users:
        description = user.get("Description", user.get("description", ""))

        if description and description.strip():
            summary.accounts_with_description += 1
        else:
            summary.accounts_without_description += 1

        analysis = analyze_account_description(user)
        all_findings.append(analysis)

        if analysis.has_findings:
            summary.accounts_with_findings += 1

            # Count by category
            for finding in analysis.findings:
                if finding.category == FindingCategory.PASSWORD.value:
                    summary.password_disclosures += 1
                elif finding.category == FindingCategory.PII_SSN.value:
                    summary.ssn_count += 1
                    summary.pii_findings += 1
                elif finding.category == FindingCategory.PII_PHONE.value:
                    summary.phone_count += 1
                    summary.pii_findings += 1
                elif finding.category == FindingCategory.PII_DOB.value:
                    summary.dob_count += 1
                    summary.pii_findings += 1
                elif finding.category == FindingCategory.PII_EMAIL.value:
                    summary.email_count += 1
                    summary.pii_findings += 1
                elif finding.category == FindingCategory.CREDENTIAL_API_KEY.value:
                    summary.api_key_count += 1
                    summary.credential_findings += 1
                elif finding.category == FindingCategory.CREDENTIAL_TOKEN.value:
                    summary.token_count += 1
                    summary.credential_findings += 1
                elif finding.category == FindingCategory.CREDENTIAL_PIN.value:
                    summary.pin_count += 1
                    summary.credential_findings += 1
        else:
            # Collect sample descriptions from accounts without findings
            # (as proof the analysis ran)
            if description and description.strip() and len(sample_descriptions) < max_samples:
                sam_name = user.get("SamAccountName", user.get("sam_account_name", ""))
                # Truncate long descriptions for display
                truncated_desc = description[:100] + "..." if len(description) > 100 else description
                sample_descriptions.append(SampleDescription(
                    account_name=sam_name,
                    description=truncated_desc
                ))

    chart_data = generate_chart_data(summary, all_findings)

    return DescriptionAnalysisReport(
        summary=summary,
        findings=all_findings,
        chart_data=chart_data,
        sample_descriptions=sample_descriptions,
        generated_at=datetime.now().isoformat()
    )
