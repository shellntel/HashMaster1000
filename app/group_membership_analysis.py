"""
Group Membership Analysis for HM1K

Analyzes Active Directory group memberships to identify accounts with
the most group memberships. High group membership counts can indicate:
- Over-provisioned accounts with excessive permissions
- Service accounts that have accumulated groups over time
- Potential security risks from privilege creep

This module provides:
- Top 25 accounts by group membership count
- Privilege level classification (Tier 0, Elevated, Standard)
- Group listing for each account
- JSON output for report display
"""

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class GroupMembershipEntry:
    """A single account's group membership data."""
    sam_account_name: str
    group_count: int
    groups: list[str]
    privilege_level: str  # "tier0", "elevated", "standard"
    privilege_groups: list[str]
    is_enabled: bool
    is_cracked: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GroupMembershipReport:
    """Complete group membership analysis report."""
    top_accounts: list[GroupMembershipEntry]
    summary: dict[str, Any]
    chart_data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "top_accounts": [a.to_dict() for a in self.top_accounts],
            "summary": self.summary,
            "chart_data": self.chart_data
        }


def analyze_group_memberships(
    account_data: list[dict[str, Any]],
    top_n: int = 25
) -> GroupMembershipReport:
    """
    Analyze group memberships and return top N accounts by group count.

    Args:
        account_data: List of account dictionaries from ADD JSON parsing.
                     Each should have: sam_account_name, member_of,
                     privilege_level, privilege_groups, is_enabled, password
        top_n: Number of top accounts to return (default 25)

    Returns:
        GroupMembershipReport with top accounts and summary statistics
    """
    entries: list[GroupMembershipEntry] = []

    for account in account_data:
        # Extract group membership data
        member_of = account.get("member_of", [])
        if isinstance(member_of, str):
            member_of = [member_of] if member_of else []

        group_count = len(member_of)

        # Skip accounts with no groups
        if group_count == 0:
            continue

        # Determine if password was cracked
        password = account.get("password", "")
        is_cracked = bool(password and password != "[NOT CRACKED]")

        entry = GroupMembershipEntry(
            sam_account_name=account.get("sam_account_name", account.get("username", "")),
            group_count=group_count,
            groups=member_of,
            privilege_level=account.get("privilege_level", "standard"),
            privilege_groups=account.get("privilege_groups", []),
            is_enabled=account.get("is_enabled", True),
            is_cracked=is_cracked
        )
        entries.append(entry)

    # Sort by group count descending, then by account name
    entries.sort(key=lambda x: (-x.group_count, x.sam_account_name.lower()))

    # Take top N
    top_accounts = entries[:top_n]

    # Generate summary statistics
    summary = _generate_summary(entries, top_accounts)

    # Generate chart data
    chart_data = _generate_chart_data(top_accounts)

    return GroupMembershipReport(
        top_accounts=top_accounts,
        summary=summary,
        chart_data=chart_data
    )


def _generate_summary(
    all_entries: list[GroupMembershipEntry],
    top_accounts: list[GroupMembershipEntry]
) -> dict[str, Any]:
    """Generate summary statistics for the report."""
    if not all_entries:
        return {
            "total_accounts_with_groups": 0,
            "max_group_count": 0,
            "avg_group_count": 0,
            "tier0_in_top": 0,
            "elevated_in_top": 0,
            "standard_in_top": 0,
            "cracked_in_top": 0
        }

    # Calculate statistics
    group_counts = [e.group_count for e in all_entries]
    max_count = max(group_counts) if group_counts else 0
    avg_count = sum(group_counts) / len(group_counts) if group_counts else 0

    # Count privilege levels in top accounts
    tier0_count = sum(1 for a in top_accounts if a.privilege_level == "tier0")
    elevated_count = sum(1 for a in top_accounts if a.privilege_level == "elevated")
    standard_count = sum(1 for a in top_accounts if a.privilege_level == "standard")
    cracked_count = sum(1 for a in top_accounts if a.is_cracked)

    return {
        "total_accounts_with_groups": len(all_entries),
        "max_group_count": max_count,
        "avg_group_count": round(avg_count, 1),
        "tier0_in_top": tier0_count,
        "elevated_in_top": elevated_count,
        "standard_in_top": standard_count,
        "cracked_in_top": cracked_count,
        "top_count": len(top_accounts)
    }


def _generate_chart_data(top_accounts: list[GroupMembershipEntry]) -> dict[str, Any]:
    """Generate Chart.js compatible data for visualization."""
    if not top_accounts:
        return {
            "group_count_chart": {"labels": [], "datasets": []},
            "privilege_distribution": {"labels": [], "datasets": []}
        }

    # Bar chart for top accounts by group count
    # Truncate long account names for chart labels
    labels = []
    for a in top_accounts[:15]:  # Top 15 for chart readability
        name = a.sam_account_name
        if len(name) > 15:
            name = name[:12] + "..."
        labels.append(name)

    # Color code by privilege level
    colors = []
    for a in top_accounts[:15]:
        if a.privilege_level == "tier0":
            colors.append("rgba(239, 68, 68, 0.8)")  # Red
        elif a.privilege_level == "elevated":
            colors.append("rgba(249, 115, 22, 0.8)")  # Orange
        else:
            colors.append("rgba(59, 130, 246, 0.8)")  # Blue

    group_count_chart = {
        "labels": labels,
        "datasets": [{
            "label": "Group Count",
            "data": [a.group_count for a in top_accounts[:15]],
            "backgroundColor": colors,
            "borderColor": [c.replace("0.8", "1") for c in colors],
            "borderWidth": 1
        }]
    }

    # Pie chart for privilege distribution in top accounts
    tier0_count = sum(1 for a in top_accounts if a.privilege_level == "tier0")
    elevated_count = sum(1 for a in top_accounts if a.privilege_level == "elevated")
    standard_count = sum(1 for a in top_accounts if a.privilege_level == "standard")

    privilege_distribution = {
        "labels": ["Tier 0", "Elevated", "Standard"],
        "datasets": [{
            "data": [tier0_count, elevated_count, standard_count],
            "backgroundColor": [
                "rgba(239, 68, 68, 0.8)",   # Red for Tier 0
                "rgba(249, 115, 22, 0.8)",  # Orange for Elevated
                "rgba(59, 130, 246, 0.8)"   # Blue for Standard
            ],
            "borderColor": [
                "rgba(239, 68, 68, 1)",
                "rgba(249, 115, 22, 1)",
                "rgba(59, 130, 246, 1)"
            ],
            "borderWidth": 1
        }]
    }

    return {
        "group_count_chart": group_count_chart,
        "privilege_distribution": privilege_distribution
    }
