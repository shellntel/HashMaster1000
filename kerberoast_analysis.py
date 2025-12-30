"""
Kerberoast Exposure Analysis Module

Analyzes service accounts for Kerberoast attack exposure and risk factors.
Generates risk scores, categorizations, and Chart.js-compatible report data.

Risk Factors Scored:
- SPN_PRESENT: Account has Service Principal Names (Kerberoastable)
- ASREP_PREAUTH_DISABLED: Pre-authentication not required (AS-REP roastable)
- PRIVILEGED_ADMINCOUNT: Protected/privileged account (adminCount=1)
- PASSWORD_NEVER_EXPIRES: Password doesn't expire
- PASSWORD_AGE_3Y_PLUS: Password not changed in 3+ years
- DELEGATION_ENABLED: Unconstrained delegation configured
- CONSTRAINED_DELEGATION_SET: Constrained delegation with targets
- WEAK_ENCRYPTION: Uses RC4 or DES encryption
- CRACKED_PASSWORD: Password was cracked in this assessment
- HIBP_EXPOSED: Password found in HIBP breach database
- REUSED_PASSWORD_CLUSTER: Password shared with other accounts

Output:
- kerberoast_report.json with summary, chart data, and detailed table
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from service_account import (
    ServiceAccountInfo,
    identify_service_account,
    get_kerberoastable_accounts,
)


class RiskCategory(str, Enum):
    """Risk categories for service accounts."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class RiskReason(str, Enum):
    """
    Risk factor reason tags.
    Each reason has an associated score weight.
    """
    SPN_PRESENT = "SPN_PRESENT"
    ASREP_PREAUTH_DISABLED = "ASREP_PREAUTH_DISABLED"
    PRIVILEGED_ADMINCOUNT = "PRIVILEGED_ADMINCOUNT"
    PASSWORD_NEVER_EXPIRES = "PASSWORD_NEVER_EXPIRES"
    PASSWORD_AGE_3Y_PLUS = "PASSWORD_AGE_3Y_PLUS"
    PASSWORD_AGE_1Y_PLUS = "PASSWORD_AGE_1Y_PLUS"
    DELEGATION_ENABLED = "DELEGATION_ENABLED"
    CONSTRAINED_DELEGATION_SET = "CONSTRAINED_DELEGATION_SET"
    WEAK_ENCRYPTION_RC4 = "WEAK_ENCRYPTION_RC4"
    WEAK_ENCRYPTION_DES = "WEAK_ENCRYPTION_DES"
    CRACKED_PASSWORD = "CRACKED_PASSWORD"
    HIBP_EXPOSED = "HIBP_EXPOSED"
    REUSED_PASSWORD_CLUSTER = "REUSED_PASSWORD_CLUSTER"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"


# Risk scores for each reason
RISK_SCORES: dict[RiskReason, int] = {
    RiskReason.SPN_PRESENT: 10,  # Base risk - account is Kerberoastable
    RiskReason.ASREP_PREAUTH_DISABLED: 25,  # Critical - AS-REP roastable
    RiskReason.PRIVILEGED_ADMINCOUNT: 30,  # Critical - high-value target
    RiskReason.PASSWORD_NEVER_EXPIRES: 15,  # Medium - long-term exposure
    RiskReason.PASSWORD_AGE_3Y_PLUS: 20,  # High - stale password
    RiskReason.PASSWORD_AGE_1Y_PLUS: 10,  # Medium - aging password
    RiskReason.DELEGATION_ENABLED: 25,  # Critical - unconstrained delegation
    RiskReason.CONSTRAINED_DELEGATION_SET: 15,  # Medium - constrained delegation
    RiskReason.WEAK_ENCRYPTION_RC4: 10,  # Medium - vulnerable encryption
    RiskReason.WEAK_ENCRYPTION_DES: 15,  # High - very weak encryption
    RiskReason.CRACKED_PASSWORD: 40,  # Critical - password is known
    RiskReason.HIBP_EXPOSED: 35,  # Critical - password in breaches
    RiskReason.REUSED_PASSWORD_CLUSTER: 20,  # High - shared password risk
    RiskReason.ACCOUNT_DISABLED: -50,  # Reduces risk significantly
}


def score_to_category(score: int) -> RiskCategory:
    """Convert numeric score to risk category."""
    if score >= 70:
        return RiskCategory.CRITICAL
    elif score >= 50:
        return RiskCategory.HIGH
    elif score >= 30:
        return RiskCategory.MEDIUM
    elif score >= 10:
        return RiskCategory.LOW
    else:
        return RiskCategory.INFO


@dataclass
class KerberoastRiskAssessment:
    """Risk assessment result for a single account."""
    sam_account_name: str
    distinguished_name: str = ""
    description: str = ""

    # Service account info
    spns: list[str] = field(default_factory=list)
    is_service_account: bool = False
    enabled: bool = True

    # Risk scoring
    risk_score: int = 0
    risk_category: str = "Info"
    risk_reasons: list[str] = field(default_factory=list)
    risk_details: dict[str, Any] = field(default_factory=dict)

    # Account details
    is_privileged: bool = False
    password_never_expires: bool = False
    preauth_not_required: bool = False
    password_age_days: int | None = None
    pwd_last_set: str = ""
    last_logon: str = ""

    # Encryption
    encryption_types: list[str] = field(default_factory=list)
    supports_rc4: bool = True
    supports_aes: bool = False
    supports_des: bool = False

    # Delegation
    has_delegation: bool = False
    unconstrained_delegation: bool = False
    constrained_delegation: bool = False
    delegation_targets: list[str] = field(default_factory=list)

    # Password analysis results (populated externally)
    password_cracked: bool = False
    cracked_password: str = ""  # Only included if cracked
    hibp_exposed: bool = False
    hibp_count: int = 0
    password_reused: bool = False
    reuse_cluster_size: int = 0


def parse_ad_timestamp(timestamp_str: str) -> datetime | None:
    """
    Parse various Active Directory timestamp formats.

    Handles:
    - Windows FileTime (e.g., "133123456789000000")
    - ISO format (e.g., "2024-01-15T10:30:00Z")
    - Human-readable (e.g., "1/15/2024 10:30:00 AM")
    - "Never" or empty string
    """
    if not timestamp_str or timestamp_str.lower() in ("never", "n/a", "null", "none"):
        return None

    # Try Windows FileTime (100-nanosecond intervals since 1601)
    if timestamp_str.isdigit() and len(timestamp_str) >= 16:
        try:
            # FileTime to Unix epoch
            filetime = int(timestamp_str)
            # 116444736000000000 = diff between 1601 and 1970 in 100ns intervals
            unix_time = (filetime - 116444736000000000) / 10000000
            if unix_time > 0:
                return datetime.fromtimestamp(unix_time)
        except (ValueError, OSError):
            pass

    # Try ISO format
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


def calculate_password_age_days(pwd_last_set: str, reference_date: datetime | None = None) -> int | None:
    """
    Calculate password age in days.

    Args:
        pwd_last_set: Password last set timestamp string
        reference_date: Date to calculate age from (defaults to now)

    Returns:
        Number of days since password was last set, or None if can't parse
    """
    pwd_date = parse_ad_timestamp(pwd_last_set)
    if pwd_date is None:
        return None

    ref_date = reference_date or datetime.now()
    delta = ref_date - pwd_date

    return delta.days if delta.days >= 0 else None


def assess_account_risk(
    user_data: dict[str, Any],
    cracked_accounts: dict[str, str] | None = None,
    hibp_results: dict[str, dict[str, Any]] | None = None,
    password_reuse_clusters: dict[str, list[str]] | None = None,
    reference_date: datetime | None = None,
) -> KerberoastRiskAssessment:
    """
    Assess Kerberoast risk for a single account.

    Args:
        user_data: User dictionary from ADD JSON export
        cracked_accounts: Dict mapping account name to cracked password
        hibp_results: Dict mapping account name to HIBP result
        password_reuse_clusters: Dict mapping password hash to list of accounts
        reference_date: Reference date for age calculations

    Returns:
        KerberoastRiskAssessment with risk score and details
    """
    svc_info = identify_service_account(user_data)
    cracked_accounts = cracked_accounts or {}
    hibp_results = hibp_results or {}
    password_reuse_clusters = password_reuse_clusters or {}

    assessment = KerberoastRiskAssessment(
        sam_account_name=svc_info.sam_account_name,
        distinguished_name=svc_info.distinguished_name,
        description=svc_info.description,
        spns=svc_info.spns,
        is_service_account=svc_info.is_service_account,
        enabled=svc_info.enabled,
        is_privileged=svc_info.is_privileged,
        password_never_expires=svc_info.password_never_expires,
        preauth_not_required=svc_info.preauth_not_required,
        pwd_last_set=svc_info.pwd_last_set,
        last_logon=svc_info.last_logon,
        encryption_types=svc_info.encryption_type_names,
        supports_rc4=svc_info.supports_rc4,
        supports_aes=svc_info.supports_aes,
        supports_des=svc_info.supports_des,
        has_delegation=svc_info.delegation.has_delegation,
        unconstrained_delegation=svc_info.delegation.unconstrained,
        constrained_delegation=svc_info.delegation.constrained,
        delegation_targets=svc_info.delegation.delegation_targets,
    )

    # Calculate password age
    assessment.password_age_days = calculate_password_age_days(
        svc_info.pwd_last_set, reference_date
    )

    # Collect risk reasons
    reasons: list[RiskReason] = []
    details: dict[str, Any] = {}

    # Base risk: Has SPNs
    if svc_info.is_service_account:
        reasons.append(RiskReason.SPN_PRESENT)
        details["spn_count"] = len(svc_info.spns)

    # AS-REP roastable
    if svc_info.preauth_not_required:
        reasons.append(RiskReason.ASREP_PREAUTH_DISABLED)

    # Privileged account
    if svc_info.is_privileged:
        reasons.append(RiskReason.PRIVILEGED_ADMINCOUNT)

    # Password never expires
    if svc_info.password_never_expires:
        reasons.append(RiskReason.PASSWORD_NEVER_EXPIRES)

    # Password age
    if assessment.password_age_days is not None:
        if assessment.password_age_days >= 1095:  # 3 years
            reasons.append(RiskReason.PASSWORD_AGE_3Y_PLUS)
            details["password_age_years"] = round(assessment.password_age_days / 365, 1)
        elif assessment.password_age_days >= 365:  # 1 year
            reasons.append(RiskReason.PASSWORD_AGE_1Y_PLUS)
            details["password_age_years"] = round(assessment.password_age_days / 365, 1)

    # Delegation
    if svc_info.delegation.unconstrained:
        reasons.append(RiskReason.DELEGATION_ENABLED)
    if svc_info.delegation.constrained:
        reasons.append(RiskReason.CONSTRAINED_DELEGATION_SET)
        details["delegation_target_count"] = len(svc_info.delegation.delegation_targets)

    # Encryption types
    if svc_info.supports_des:
        reasons.append(RiskReason.WEAK_ENCRYPTION_DES)
    elif svc_info.supports_rc4 and not svc_info.supports_aes:
        reasons.append(RiskReason.WEAK_ENCRYPTION_RC4)

    # Check password analysis results
    account_lower = svc_info.sam_account_name.lower()

    # Cracked password
    for acct, pwd in cracked_accounts.items():
        if acct.lower() == account_lower:
            assessment.password_cracked = True
            assessment.cracked_password = pwd
            reasons.append(RiskReason.CRACKED_PASSWORD)
            break

    # HIBP exposure
    for acct, hibp_info in hibp_results.items():
        if acct.lower() == account_lower and hibp_info.get("found", False):
            assessment.hibp_exposed = True
            assessment.hibp_count = hibp_info.get("count", 0)
            reasons.append(RiskReason.HIBP_EXPOSED)
            details["hibp_count"] = assessment.hibp_count
            break

    # Password reuse
    for hash_val, accounts in password_reuse_clusters.items():
        if any(a.lower() == account_lower for a in accounts) and len(accounts) > 1:
            assessment.password_reused = True
            assessment.reuse_cluster_size = len(accounts)
            reasons.append(RiskReason.REUSED_PASSWORD_CLUSTER)
            details["reuse_cluster_size"] = len(accounts)
            break

    # Disabled account reduces risk
    if not svc_info.enabled:
        reasons.append(RiskReason.ACCOUNT_DISABLED)

    # Calculate total score
    total_score = sum(RISK_SCORES.get(r, 0) for r in reasons)
    total_score = max(0, total_score)  # Don't go negative

    assessment.risk_score = total_score
    assessment.risk_category = score_to_category(total_score).value
    assessment.risk_reasons = [r.value for r in reasons]
    assessment.risk_details = details

    return assessment


@dataclass
class KerberoastReportSummary:
    """Summary statistics for the Kerberoast report."""
    total_accounts_analyzed: int = 0
    total_service_accounts: int = 0
    total_kerberoastable: int = 0
    total_asrep_roastable: int = 0

    # By risk category
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0  # Accounts with score < 10 (secure/minimal risk)

    # Key risk factors
    privileged_with_spn: int = 0
    cracked_with_spn: int = 0
    hibp_exposed_with_spn: int = 0
    password_never_expires_count: int = 0
    stale_passwords_3y_count: int = 0
    unconstrained_delegation_count: int = 0
    constrained_delegation_count: int = 0
    weak_encryption_count: int = 0


@dataclass
class KerberoastReport:
    """Complete Kerberoast analysis report."""
    summary: KerberoastReportSummary
    assessments: list[KerberoastRiskAssessment]
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


def generate_chart_data(assessments: list[KerberoastRiskAssessment]) -> dict[str, Any]:
    """
    Generate Chart.js-compatible data for visualization.

    Returns:
        Dict with chart configurations for:
        - risk_distribution: Pie/doughnut chart of risk categories
        - risk_factors: Bar chart of risk reason frequency
        - encryption_types: Pie chart of encryption support
    """
    # Risk category distribution
    category_counts = {
        RiskCategory.CRITICAL.value: 0,
        RiskCategory.HIGH.value: 0,
        RiskCategory.MEDIUM.value: 0,
        RiskCategory.LOW.value: 0,
    }
    for a in assessments:
        if a.risk_category in category_counts:
            category_counts[a.risk_category] += 1

    # Risk factor frequency
    reason_counts: dict[str, int] = {}
    for a in assessments:
        for reason in a.risk_reasons:
            # Skip ACCOUNT_DISABLED as it's not a risk factor
            if reason != RiskReason.ACCOUNT_DISABLED.value:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

    # Sort by count
    sorted_reasons = sorted(reason_counts.items(), key=lambda x: -x[1])

    # Encryption type distribution
    enc_counts = {
        "RC4 Only": 0,
        "AES Enabled": 0,
        "DES Enabled": 0,
    }
    for a in assessments:
        if a.supports_aes:
            enc_counts["AES Enabled"] += 1
        elif a.supports_des:
            enc_counts["DES Enabled"] += 1
        elif a.supports_rc4:
            enc_counts["RC4 Only"] += 1

    return {
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
            "labels": [r[0] for r in sorted_reasons[:10]],  # Top 10
            "datasets": [{
                "label": "Accounts Affected",
                "data": [r[1] for r in sorted_reasons[:10]],
                "backgroundColor": "#0d6efd",
            }],
        },
        "encryption_types": {
            "labels": list(enc_counts.keys()),
            "datasets": [{
                "data": list(enc_counts.values()),
                "backgroundColor": [
                    "#dc3545",  # RC4 Only - red (vulnerable)
                    "#28a745",  # AES - green (better)
                    "#6c757d",  # DES - gray (deprecated)
                ],
            }],
        },
    }


def analyze_kerberoast_exposure(
    users: list[dict[str, Any]],
    cracked_accounts: dict[str, str] | None = None,
    hibp_results: dict[str, dict[str, Any]] | None = None,
    password_reuse_clusters: dict[str, list[str]] | None = None,
    include_non_service_accounts: bool = False,
    reference_date: datetime | None = None,
) -> KerberoastReport:
    """
    Perform complete Kerberoast exposure analysis.

    Args:
        users: List of user dictionaries from ADD JSON export
        cracked_accounts: Dict mapping account name to cracked password
        hibp_results: Dict mapping account name to HIBP result
        password_reuse_clusters: Dict mapping password hash to list of accounts
        include_non_service_accounts: If True, analyze all accounts, not just those with SPNs
        reference_date: Reference date for age calculations

    Returns:
        KerberoastReport with summary, assessments, and chart data
    """
    assessments: list[KerberoastRiskAssessment] = []
    summary = KerberoastReportSummary(total_accounts_analyzed=len(users))

    for user in users:
        assessment = assess_account_risk(
            user,
            cracked_accounts=cracked_accounts,
            hibp_results=hibp_results,
            password_reuse_clusters=password_reuse_clusters,
            reference_date=reference_date,
        )

        # Skip non-service accounts unless requested
        if not include_non_service_accounts and not assessment.is_service_account:
            continue

        # Update summary counts
        if assessment.is_service_account:
            summary.total_service_accounts += 1

            # Skip computer accounts and krbtgt for "kerberoastable" count
            if not assessment.sam_account_name.endswith("$") and \
               assessment.sam_account_name.lower() != "krbtgt" and \
               assessment.enabled:
                summary.total_kerberoastable += 1

        if assessment.preauth_not_required:
            summary.total_asrep_roastable += 1

        # Risk category counts
        if assessment.risk_category == RiskCategory.CRITICAL.value:
            summary.critical_count += 1
        elif assessment.risk_category == RiskCategory.HIGH.value:
            summary.high_count += 1
        elif assessment.risk_category == RiskCategory.MEDIUM.value:
            summary.medium_count += 1
        elif assessment.risk_category == RiskCategory.LOW.value:
            summary.low_count += 1
        elif assessment.risk_category == RiskCategory.INFO.value:
            summary.info_count += 1

        # Specific risk factor counts
        if assessment.is_privileged and assessment.is_service_account:
            summary.privileged_with_spn += 1
        if assessment.password_cracked and assessment.is_service_account:
            summary.cracked_with_spn += 1
        if assessment.hibp_exposed and assessment.is_service_account:
            summary.hibp_exposed_with_spn += 1
        if assessment.password_never_expires:
            summary.password_never_expires_count += 1
        if RiskReason.PASSWORD_AGE_3Y_PLUS.value in assessment.risk_reasons:
            summary.stale_passwords_3y_count += 1
        if assessment.unconstrained_delegation:
            summary.unconstrained_delegation_count += 1
        if assessment.constrained_delegation:
            summary.constrained_delegation_count += 1
        if RiskReason.WEAK_ENCRYPTION_RC4.value in assessment.risk_reasons or \
           RiskReason.WEAK_ENCRYPTION_DES.value in assessment.risk_reasons:
            summary.weak_encryption_count += 1

        assessments.append(assessment)

    # Sort assessments by risk score (highest first)
    assessments.sort(key=lambda a: (-a.risk_score, a.sam_account_name))

    # Generate chart data
    chart_data = generate_chart_data(assessments)

    return KerberoastReport(
        summary=summary,
        assessments=assessments,
        chart_data=chart_data,
        generated_at=datetime.now().isoformat(),
    )


def format_risk_reasons_for_display(reasons: list[str]) -> list[dict[str, str]]:
    """
    Format risk reasons for human-readable display.

    Returns:
        List of dicts with 'tag' and 'description' keys
    """
    descriptions = {
        "SPN_PRESENT": "Account has SPNs (Kerberoastable)",
        "ASREP_PREAUTH_DISABLED": "Pre-auth disabled (AS-REP roastable)",
        "PRIVILEGED_ADMINCOUNT": "Privileged account (adminCount=1)",
        "PASSWORD_NEVER_EXPIRES": "Password never expires",
        "PASSWORD_AGE_3Y_PLUS": "Password older than 3 years",
        "PASSWORD_AGE_1Y_PLUS": "Password older than 1 year",
        "DELEGATION_ENABLED": "Unconstrained delegation",
        "CONSTRAINED_DELEGATION_SET": "Constrained delegation configured",
        "WEAK_ENCRYPTION_RC4": "Uses RC4 encryption",
        "WEAK_ENCRYPTION_DES": "Uses DES encryption (deprecated)",
        "CRACKED_PASSWORD": "Password was cracked",
        "HIBP_EXPOSED": "Password in HIBP breaches",
        "REUSED_PASSWORD_CLUSTER": "Password shared with other accounts",
        "ACCOUNT_DISABLED": "Account is disabled",
    }

    return [
        {"tag": r, "description": descriptions.get(r, r)}
        for r in reasons
    ]
