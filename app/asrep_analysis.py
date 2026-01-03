"""
AS-REP Roasting Exposure Analysis Module

Identifies accounts vulnerable to AS-REP roasting attacks because Kerberos
preauthentication is not required, then prioritizes based on operational risk.

AS-REP Roasting is possible when:
- DONT_REQ_PREAUTH (0x400000) flag is set in UserAccountControl
- Account is enabled

Risk is amplified by:
- Privilege level (adminCount=1 or privileged group membership)
- Password exposure (cracked, HIBP hit, reused)
- Password staleness (older pwdLastSet increases exposure window)
- Recent activity (interactive usage indicates active target)

Output:
- asrep_report.json with summary, chart data, and detailed table
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from app.service_account import (
    ServiceAccountInfo,
    identify_service_account,
    get_asrep_roastable_accounts,
)


class ASREPRiskCategory(str, Enum):
    """Risk categories for AS-REP roastable accounts."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ASREPRiskReason(str, Enum):
    """
    Risk factor reason tags for AS-REP roasting exposure.
    Each reason has an associated score weight.
    """
    # Core vulnerability (base)
    ASREP_ROASTABLE = "ASREP_ROASTABLE"

    # Password exposure (highest impact)
    CRACKED_PASSWORD = "CRACKED_PASSWORD"
    HIBP_EXPOSED = "HIBP_EXPOSED"
    REUSED_PASSWORD = "REUSED_PASSWORD"

    # Privilege (high impact - value of the account)
    PRIVILEGED_ACCOUNT = "PRIVILEGED_ACCOUNT"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"

    # Activity (indicates active target)
    RECENTLY_ACTIVE = "RECENTLY_ACTIVE"

    # Password staleness (exposure window amplifier)
    PASSWORD_STALE_3Y = "PASSWORD_STALE_3Y"
    PASSWORD_STALE_1Y = "PASSWORD_STALE_1Y"
    PASSWORD_NEVER_EXPIRES = "PASSWORD_NEVER_EXPIRES"

    # Mitigating factor
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"


# Risk scores for each factor
# Framing: These are exposure amplifiers, not "old = weak"
ASREP_RISK_SCORES: dict[ASREPRiskReason, int] = {
    # Base score for being AS-REP roastable
    ASREPRiskReason.ASREP_ROASTABLE: 15,

    # Password exposure - highest scores (compromised or at-risk)
    ASREPRiskReason.CRACKED_PASSWORD: 40,  # Password is known - critical
    ASREPRiskReason.HIBP_EXPOSED: 35,      # Password in breaches - very high
    ASREPRiskReason.REUSED_PASSWORD: 20,   # Shared password increases blast radius

    # Privilege - high value targets
    ASREPRiskReason.PRIVILEGED_ACCOUNT: 30,  # adminCount=1 or privileged group
    ASREPRiskReason.SERVICE_ACCOUNT: 15,      # Has SPNs (service-like)

    # Activity - indicates actively used account
    ASREPRiskReason.RECENTLY_ACTIVE: 10,  # Logged in within 30 days

    # Password staleness - exposure window amplifier
    # Not claiming "old = weak", but "old + risky = high impact if compromised"
    ASREPRiskReason.PASSWORD_STALE_3Y: 15,      # 3+ years - long exposure window
    ASREPRiskReason.PASSWORD_STALE_1Y: 8,       # 1+ years - moderate exposure
    ASREPRiskReason.PASSWORD_NEVER_EXPIRES: 10, # No rotation policy

    # Mitigating factor
    ASREPRiskReason.ACCOUNT_DISABLED: -50,  # Significantly reduces risk
}


def asrep_score_to_category(score: int) -> ASREPRiskCategory:
    """Convert numeric score to risk category."""
    if score >= 70:
        return ASREPRiskCategory.CRITICAL
    elif score >= 50:
        return ASREPRiskCategory.HIGH
    elif score >= 30:
        return ASREPRiskCategory.MEDIUM
    elif score >= 10:
        return ASREPRiskCategory.LOW
    else:
        return ASREPRiskCategory.INFO


@dataclass
class ASREPRiskAssessment:
    """Risk assessment result for a single AS-REP roastable account."""
    sam_account_name: str
    distinguished_name: str = ""
    description: str = ""

    # Account classification
    account_class: str = "User"  # "Privileged", "Service", "User", "Disabled"
    enabled: bool = True
    is_privileged: bool = False
    is_service_like: bool = False  # Has SPNs or svc_ prefix

    # Risk scoring
    risk_score: int = 0
    risk_category: str = "Info"
    risk_reasons: list[str] = field(default_factory=list)
    risk_details: dict[str, Any] = field(default_factory=dict)

    # Password info
    pwd_last_set: str = ""
    password_age_days: int | None = None
    password_never_expires: bool = False

    # Activity
    last_logon: str = ""
    last_logon_days_ago: int | None = None
    recently_active: bool = False

    # Password analysis results (populated externally)
    password_cracked: bool = False
    cracked_password: str = ""
    hibp_exposed: bool = False
    hibp_count: int = 0
    password_reused: bool = False
    reuse_cluster_size: int = 0


def parse_ad_timestamp(timestamp_str: str) -> datetime | None:
    """
    Parse various Active Directory timestamp formats.
    """
    if not timestamp_str or timestamp_str.lower() in ("never", "n/a", "null", "none", ""):
        return None

    # Try Windows FileTime (100-nanosecond intervals since 1601)
    if timestamp_str.isdigit() and len(timestamp_str) >= 16:
        try:
            filetime = int(timestamp_str)
            unix_time = (filetime - 116444736000000000) / 10000000
            if unix_time > 0:
                return datetime.fromtimestamp(unix_time)
        except (ValueError, OSError):
            pass

    # Try various date formats
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y",
    ]:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue

    return None


def calculate_days_ago(timestamp_str: str, reference_date: datetime | None = None) -> int | None:
    """Calculate days since a timestamp."""
    ts = parse_ad_timestamp(timestamp_str)
    if ts is None:
        return None

    ref_date = reference_date or datetime.now()
    delta = ref_date - ts

    return delta.days if delta.days >= 0 else None


def classify_account(
    enabled: bool,
    is_privileged: bool,
    is_service_like: bool
) -> str:
    """Classify account into category for reporting."""
    if not enabled:
        return "Disabled"
    if is_privileged:
        return "Privileged"
    if is_service_like:
        return "Service"
    return "User"


def assess_asrep_risk(
    user_data: dict[str, Any],
    cracked_accounts: dict[str, str] | None = None,
    hibp_results: dict[str, dict[str, Any]] | None = None,
    password_reuse_clusters: dict[str, list[str]] | None = None,
    reference_date: datetime | None = None,
) -> ASREPRiskAssessment:
    """
    Assess AS-REP roasting risk for a single account.

    Args:
        user_data: User dictionary from ADD JSON export
        cracked_accounts: Dict mapping account name to cracked password
        hibp_results: Dict mapping account name to HIBP result
        password_reuse_clusters: Dict mapping password hash to list of accounts
        reference_date: Reference date for age calculations

    Returns:
        ASREPRiskAssessment with risk score and details
    """
    svc_info = identify_service_account(user_data)
    cracked_accounts = cracked_accounts or {}
    hibp_results = hibp_results or {}
    password_reuse_clusters = password_reuse_clusters or {}

    # Determine if account is service-like (has SPNs or svc_ prefix)
    sam_lower = svc_info.sam_account_name.lower()
    is_service_like = (
        svc_info.is_service_account or  # Has SPNs
        sam_lower.startswith("svc_") or
        sam_lower.startswith("svc-") or
        sam_lower.startswith("service")
    )

    # Classify account
    account_class = classify_account(
        svc_info.enabled,
        svc_info.is_privileged,
        is_service_like
    )

    assessment = ASREPRiskAssessment(
        sam_account_name=svc_info.sam_account_name,
        distinguished_name=svc_info.distinguished_name,
        description=svc_info.description,
        account_class=account_class,
        enabled=svc_info.enabled,
        is_privileged=svc_info.is_privileged,
        is_service_like=is_service_like,
        pwd_last_set=svc_info.pwd_last_set,
        password_never_expires=svc_info.password_never_expires,
        last_logon=svc_info.last_logon,
    )

    # Calculate password age
    assessment.password_age_days = calculate_days_ago(svc_info.pwd_last_set, reference_date)

    # Calculate last logon age
    assessment.last_logon_days_ago = calculate_days_ago(svc_info.last_logon, reference_date)
    assessment.recently_active = (
        assessment.last_logon_days_ago is not None and
        assessment.last_logon_days_ago <= 30
    )

    # Collect risk reasons
    reasons: list[ASREPRiskReason] = []
    details: dict[str, Any] = {}

    # Base risk: AS-REP roastable
    reasons.append(ASREPRiskReason.ASREP_ROASTABLE)

    # Privilege level
    if svc_info.is_privileged:
        reasons.append(ASREPRiskReason.PRIVILEGED_ACCOUNT)

    if is_service_like:
        reasons.append(ASREPRiskReason.SERVICE_ACCOUNT)

    # Recent activity
    if assessment.recently_active:
        reasons.append(ASREPRiskReason.RECENTLY_ACTIVE)
        details["last_logon_days_ago"] = assessment.last_logon_days_ago

    # Password staleness (exposure window amplifier)
    if assessment.password_age_days is not None:
        if assessment.password_age_days >= 1095:  # 3 years
            reasons.append(ASREPRiskReason.PASSWORD_STALE_3Y)
            details["password_age_years"] = round(assessment.password_age_days / 365, 1)
        elif assessment.password_age_days >= 365:  # 1 year
            reasons.append(ASREPRiskReason.PASSWORD_STALE_1Y)
            details["password_age_years"] = round(assessment.password_age_days / 365, 1)

    if svc_info.password_never_expires:
        reasons.append(ASREPRiskReason.PASSWORD_NEVER_EXPIRES)

    # Check password analysis results
    account_lower = svc_info.sam_account_name.lower()

    # Cracked password
    for acct, pwd in cracked_accounts.items():
        if acct.lower() == account_lower:
            assessment.password_cracked = True
            assessment.cracked_password = pwd
            reasons.append(ASREPRiskReason.CRACKED_PASSWORD)
            break

    # HIBP exposure
    for acct, hibp_info in hibp_results.items():
        if acct.lower() == account_lower and hibp_info.get("found", False):
            assessment.hibp_exposed = True
            assessment.hibp_count = hibp_info.get("count", 0)
            reasons.append(ASREPRiskReason.HIBP_EXPOSED)
            details["hibp_count"] = assessment.hibp_count
            break

    # Password reuse
    for hash_val, accounts in password_reuse_clusters.items():
        if any(a.lower() == account_lower for a in accounts) and len(accounts) > 1:
            assessment.password_reused = True
            assessment.reuse_cluster_size = len(accounts)
            reasons.append(ASREPRiskReason.REUSED_PASSWORD)
            details["reuse_cluster_size"] = len(accounts)
            break

    # Disabled account reduces risk
    if not svc_info.enabled:
        reasons.append(ASREPRiskReason.ACCOUNT_DISABLED)

    # Calculate total score
    total_score = sum(ASREP_RISK_SCORES.get(r, 0) for r in reasons)
    total_score = max(0, total_score)  # Don't go negative

    assessment.risk_score = total_score
    assessment.risk_category = asrep_score_to_category(total_score).value
    assessment.risk_reasons = [r.value for r in reasons]
    assessment.risk_details = details

    return assessment


@dataclass
class ASREPReportSummary:
    """Summary statistics for the AS-REP roasting report."""
    # Totals
    total_user_count: int = 0
    total_asrep_roastable: int = 0
    enabled_asrep_roastable: int = 0
    disabled_asrep_roastable: int = 0

    # By account class
    privileged_asrep_roastable: int = 0
    service_like_asrep_roastable: int = 0
    normal_user_asrep_roastable: int = 0

    # Password exposure
    cracked_asrep_roastable: int = 0
    hibp_exposed_asrep_roastable: int = 0
    reused_password_asrep_roastable: int = 0

    # By risk category
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


@dataclass
class ASREPReport:
    """Complete AS-REP roasting analysis report."""
    summary: ASREPReportSummary
    assessments: list[ASREPRiskAssessment]
    chart_data: dict[str, Any]
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": asdict(self.summary),
            "assessments": [asdict(a) for a in self.assessments],
            "chart_data": self.chart_data,
            "generated_at": self.generated_at,
        }


def generate_asrep_chart_data(
    assessments: list[ASREPRiskAssessment],
    summary: ASREPReportSummary
) -> dict[str, Any]:
    """
    Generate Chart.js-compatible data for visualization.

    Returns:
        Dict with chart configurations for:
        - account_class_distribution: Bar chart by account class
        - enabled_disabled: Stacked bar for enabled vs disabled
        - password_age_histogram: Password age buckets
        - risk_distribution: Pie chart of risk categories
    """
    # Account class distribution (Privileged, Service, User, Disabled)
    class_counts = {
        "Privileged": 0,
        "Service": 0,
        "User": 0,
        "Disabled": 0,
    }
    for a in assessments:
        if a.account_class in class_counts:
            class_counts[a.account_class] += 1

    # Enabled vs Disabled stacked bar
    enabled_counts = {
        "Enabled": summary.enabled_asrep_roastable,
        "Disabled": summary.disabled_asrep_roastable,
    }

    # Password age histogram buckets
    age_buckets = {
        "< 90 days": 0,
        "90 days - 1 year": 0,
        "1 - 2 years": 0,
        "2 - 3 years": 0,
        "3+ years": 0,
        "Unknown": 0,
    }
    for a in assessments:
        if a.password_age_days is None:
            age_buckets["Unknown"] += 1
        elif a.password_age_days < 90:
            age_buckets["< 90 days"] += 1
        elif a.password_age_days < 365:
            age_buckets["90 days - 1 year"] += 1
        elif a.password_age_days < 730:
            age_buckets["1 - 2 years"] += 1
        elif a.password_age_days < 1095:
            age_buckets["2 - 3 years"] += 1
        else:
            age_buckets["3+ years"] += 1

    # Risk category distribution
    category_counts = {
        ASREPRiskCategory.CRITICAL.value: summary.critical_count,
        ASREPRiskCategory.HIGH.value: summary.high_count,
        ASREPRiskCategory.MEDIUM.value: summary.medium_count,
        ASREPRiskCategory.LOW.value: summary.low_count,
    }

    # Risk factor frequency
    reason_counts: dict[str, int] = {}
    for a in assessments:
        for reason in a.risk_reasons:
            if reason != ASREPRiskReason.ACCOUNT_DISABLED.value:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
    sorted_reasons = sorted(reason_counts.items(), key=lambda x: -x[1])

    return {
        "account_class_distribution": {
            "labels": list(class_counts.keys()),
            "datasets": [{
                "label": "AS-REP Roastable Accounts",
                "data": list(class_counts.values()),
                "backgroundColor": [
                    "#dc3545",  # Privileged - red
                    "#fd7e14",  # Service - orange
                    "#0d6efd",  # User - blue
                    "#6c757d",  # Disabled - gray
                ],
            }],
        },
        "enabled_disabled": {
            "labels": ["AS-REP Roastable"],
            "datasets": [
                {
                    "label": "Enabled",
                    "data": [enabled_counts["Enabled"]],
                    "backgroundColor": "#28a745",
                },
                {
                    "label": "Disabled",
                    "data": [enabled_counts["Disabled"]],
                    "backgroundColor": "#6c757d",
                },
            ],
        },
        "password_age_histogram": {
            "labels": list(age_buckets.keys()),
            "datasets": [{
                "label": "Accounts",
                "data": list(age_buckets.values()),
                "backgroundColor": [
                    "#28a745",  # < 90 days - green
                    "#17a2b8",  # 90d-1y - teal
                    "#ffc107",  # 1-2y - yellow
                    "#fd7e14",  # 2-3y - orange
                    "#dc3545",  # 3+ years - red
                    "#6c757d",  # Unknown - gray
                ],
            }],
        },
        "risk_distribution": {
            "labels": list(category_counts.keys()),
            "datasets": [{
                "data": list(category_counts.values()),
                "backgroundColor": [
                    "#dc3545",  # Critical - red
                    "#fd7e14",  # High - orange
                    "#ffc107",  # Medium - yellow
                    "#28a745",  # Low - green
                ],
            }],
        },
        "risk_factors": {
            "labels": [r[0] for r in sorted_reasons[:8]],
            "datasets": [{
                "label": "Accounts Affected",
                "data": [r[1] for r in sorted_reasons[:8]],
                "backgroundColor": "#6366f1",
            }],
        },
    }


def analyze_asrep_exposure(
    users: list[dict[str, Any]],
    cracked_accounts: dict[str, str] | None = None,
    hibp_results: dict[str, dict[str, Any]] | None = None,
    password_reuse_clusters: dict[str, list[str]] | None = None,
    reference_date: datetime | None = None,
) -> ASREPReport:
    """
    Perform complete AS-REP roasting exposure analysis.

    Args:
        users: List of user dictionaries from ADD JSON export
        cracked_accounts: Dict mapping account name to cracked password
        hibp_results: Dict mapping account name to HIBP result
        password_reuse_clusters: Dict mapping password hash to list of accounts
        reference_date: Reference date for age calculations

    Returns:
        ASREPReport with summary, assessments, and chart data
    """
    assessments: list[ASREPRiskAssessment] = []
    summary = ASREPReportSummary(total_user_count=len(users))

    for user in users:
        # Get service account info to check for DONT_REQ_PREAUTH
        svc_info = identify_service_account(user)

        # Only process AS-REP roastable accounts
        if not svc_info.preauth_not_required:
            continue

        assessment = assess_asrep_risk(
            user,
            cracked_accounts=cracked_accounts,
            hibp_results=hibp_results,
            password_reuse_clusters=password_reuse_clusters,
            reference_date=reference_date,
        )

        # Update summary counts
        summary.total_asrep_roastable += 1

        if assessment.enabled:
            summary.enabled_asrep_roastable += 1
        else:
            summary.disabled_asrep_roastable += 1

        # Account class counts
        if assessment.account_class == "Privileged":
            summary.privileged_asrep_roastable += 1
        elif assessment.account_class == "Service":
            summary.service_like_asrep_roastable += 1
        elif assessment.account_class == "User":
            summary.normal_user_asrep_roastable += 1

        # Password exposure counts
        if assessment.password_cracked:
            summary.cracked_asrep_roastable += 1
        if assessment.hibp_exposed:
            summary.hibp_exposed_asrep_roastable += 1
        if assessment.password_reused:
            summary.reused_password_asrep_roastable += 1

        # Risk category counts
        if assessment.risk_category == ASREPRiskCategory.CRITICAL.value:
            summary.critical_count += 1
        elif assessment.risk_category == ASREPRiskCategory.HIGH.value:
            summary.high_count += 1
        elif assessment.risk_category == ASREPRiskCategory.MEDIUM.value:
            summary.medium_count += 1
        elif assessment.risk_category == ASREPRiskCategory.LOW.value:
            summary.low_count += 1
        else:
            summary.info_count += 1

        assessments.append(assessment)

    # Sort assessments by risk score (highest first)
    assessments.sort(key=lambda a: (-a.risk_score, a.sam_account_name))

    # Generate chart data
    chart_data = generate_asrep_chart_data(assessments, summary)

    return ASREPReport(
        summary=summary,
        assessments=assessments,
        chart_data=chart_data,
        generated_at=datetime.now().isoformat(),
    )


def format_asrep_risk_reasons(reasons: list[str]) -> list[dict[str, str]]:
    """
    Format risk reasons for human-readable display.

    Returns:
        List of dicts with 'tag' and 'description' keys
    """
    descriptions = {
        "ASREP_ROASTABLE": "Pre-auth not required (AS-REP roastable)",
        "CRACKED_PASSWORD": "Password was cracked",
        "HIBP_EXPOSED": "Password in HIBP breaches",
        "REUSED_PASSWORD": "Password shared with other accounts",
        "PRIVILEGED_ACCOUNT": "Privileged account (adminCount=1)",
        "SERVICE_ACCOUNT": "Service account (has SPNs)",
        "RECENTLY_ACTIVE": "Recently active (logged in within 30 days)",
        "PASSWORD_STALE_3Y": "Password older than 3 years",
        "PASSWORD_STALE_1Y": "Password older than 1 year",
        "PASSWORD_NEVER_EXPIRES": "Password never expires",
        "ACCOUNT_DISABLED": "Account is disabled",
    }

    return [
        {"tag": r, "description": descriptions.get(r, r)}
        for r in reasons
    ]
