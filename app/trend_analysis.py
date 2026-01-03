"""
Trend Analysis Module for Hash Master 1000

Extracts metrics from historical sessions and compares them to identify
improvements or regressions in password security over time.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.session_manager import SessionManager, SessionMetadata


@dataclass
class TrendMetrics:
    """Metrics extracted from a single session for trend comparison."""
    session_id: str
    session_date: str
    company_name: str
    project_description: str

    # Core cracking metrics
    total_accounts: int = 0
    cracked_count: int = 0
    crack_rate: float = 0.0
    unique_passwords: int = 0
    unique_hashes: int = 0

    # Password length metrics
    avg_password_length: float = 0.0
    min_password_length: int = 0
    max_password_length: int = 0

    # Policy violation counts
    min_length_violations: int = 0
    complexity_violations: int = 0
    blank_passwords: int = 0
    max_age_violations: int = 0
    lm_hash_count: int = 0

    # Reuse and sharing
    password_reuse_count: int = 0
    password_reuse_rate: float = 0.0

    # Bad practices (13 categories)
    bad_practices: dict[str, int] = field(default_factory=dict)
    total_bad_practices: int = 0

    # HIBP exposure (if available)
    hibp_checked: bool = False
    hibp_exposed_count: int = 0
    hibp_exposure_rate: float = 0.0


@dataclass
class TrendChange:
    """Represents a change between two metrics values."""
    metric_name: str
    display_name: str
    old_value: float
    new_value: float
    absolute_change: float
    percent_change: float
    direction: str  # "improvement", "regression", or "neutral"
    is_significant: bool  # True if change is notable


@dataclass
class TrendComparison:
    """Full comparison between multiple sessions."""
    company_name: str
    sessions: list[TrendMetrics]
    changes: list[TrendChange]
    overall_direction: str  # "improving", "regressing", "stable"
    summary: str


class TrendAnalyzer:
    """
    Analyzes trends across multiple assessment sessions.

    Extracts metrics from session JSON files and compares them to identify
    improvements or regressions in password security posture.
    """

    # Metrics where lower values are better (improvements show as negative change)
    LOWER_IS_BETTER = {
        "crack_rate", "min_length_violations", "complexity_violations",
        "blank_passwords", "max_age_violations", "lm_hash_count",
        "password_reuse_rate", "total_bad_practices", "hibp_exposure_rate"
    }

    # Metrics where higher values are better
    # Note: avg_password_length removed - it's misleading because as security improves
    # and fewer passwords are cracked, the remaining cracked passwords tend to be
    # the weakest (shortest), making the average appear to worsen when security
    # is actually improving.
    HIGHER_IS_BETTER = {
        "min_password_length"
    }

    # Thresholds for "significant" changes (as percentages)
    SIGNIFICANCE_THRESHOLDS = {
        "crack_rate": 5.0,
        "password_reuse_rate": 5.0,
        "blank_passwords": 10.0,
        "complexity_violations": 10.0,
        "min_length_violations": 10.0,
        "total_bad_practices": 10.0,
        "lm_hash_count": 10.0,
        "hibp_exposure_rate": 5.0,
    }

    # Display names for metrics
    METRIC_DISPLAY_NAMES = {
        "crack_rate": "Crack Rate",
        "avg_password_length": "Average Password Length",
        "min_password_length": "Minimum Password Length",
        "min_length_violations": "Min Length Violations",
        "complexity_violations": "Complexity Violations",
        "blank_passwords": "Blank Passwords",
        "max_age_violations": "Max Age Violations",
        "lm_hash_count": "LM Hash Count",
        "password_reuse_rate": "Password Reuse Rate",
        "total_bad_practices": "Total Bad Practices",
        "hibp_exposure_rate": "HIBP Exposure Rate",
        "total_accounts": "Total Accounts",
        "cracked_count": "Cracked Accounts",
    }

    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager

    def extract_metrics(self, session_id: str) -> TrendMetrics | None:
        """
        Extract metrics from a session's saved data files.

        Args:
            session_id: The session ID to extract metrics from

        Returns:
            TrendMetrics object or None if session not found
        """
        metadata = self.session_manager.get_session(session_id)
        if not metadata:
            logging.warning(f"Session not found: {session_id}")
            return None

        metrics = TrendMetrics(
            session_id=session_id,
            session_date=metadata.created_at,
            company_name=metadata.company_name,
            project_description=metadata.project_description,
        )

        # Load cracking stats
        stats = self._load_session_data(session_id, "cracking_stats_table.json")
        if stats:
            # Handle two formats:
            # 1. List of {key, value} pairs (real sessions)
            # 2. Dictionary with direct keys (generated test sessions)
            if isinstance(stats, list):
                # Convert list format to dictionary for easier access
                stats_dict = {}
                for item in stats:
                    if isinstance(item, dict) and "key" in item and "value" in item:
                        # Normalize key: "Cracked Accounts: " -> "cracked_accounts"
                        key = item["key"].strip().rstrip(":").lower().replace(" ", "_")
                        stats_dict[key] = item["value"]

                # Map to metrics
                metrics.total_accounts = stats_dict.get("total_accounts_analyzed", 0)
                metrics.cracked_count = stats_dict.get("cracked_accounts", 0)

                # Handle percentage format
                crack_rate = stats_dict.get("percent_of_accounts_cracked", "0")
                if isinstance(crack_rate, str):
                    try:
                        metrics.crack_rate = float(crack_rate.rstrip("%"))
                    except ValueError:
                        metrics.crack_rate = 0.0
                else:
                    metrics.crack_rate = float(crack_rate) if crack_rate else 0.0

                metrics.unique_hashes = stats_dict.get("unique_ntlm_hashes_analyzed", 0)

                # Get average password length if available
                avg_len = stats_dict.get("average_password_length", 0)
                if isinstance(avg_len, str):
                    try:
                        metrics.avg_password_length = float(avg_len)
                    except ValueError:
                        pass
                elif avg_len:
                    metrics.avg_password_length = float(avg_len)
            else:
                # Dictionary format (generated test sessions)
                metrics.total_accounts = stats.get("total_accounts", 0)
                metrics.cracked_count = stats.get("cracked_count", 0)
                if isinstance(stats.get("crack_rate"), str):
                    # Handle "45.2%" format
                    rate_str = stats.get("crack_rate", "0").rstrip("%")
                    try:
                        metrics.crack_rate = float(rate_str)
                    except ValueError:
                        metrics.crack_rate = 0.0
                else:
                    metrics.crack_rate = float(stats.get("crack_rate", 0))
                metrics.unique_passwords = stats.get("unique_passwords", 0)
                metrics.unique_hashes = stats.get("unique_hashes", 0)

        # Load password length distribution for avg calculation
        length_dist = self._load_session_data(session_id, "pw_length_distribution.json")
        if length_dist and isinstance(length_dist, list):
            total_chars = 0
            total_count = 0
            min_len = None
            max_len = 0
            for entry in length_dist:
                length = entry.get("length", 0)
                count = entry.get("count", 0)
                total_chars += length * count
                total_count += count
                if count > 0:
                    if min_len is None or length < min_len:
                        min_len = length
                    if length > max_len:
                        max_len = length
            if total_count > 0:
                metrics.avg_password_length = round(total_chars / total_count, 2)
                metrics.min_password_length = min_len or 0
                metrics.max_password_length = max_len

        # Load policy violation counts
        # These can be either dicts (keyed by username) or lists
        min_length = self._load_session_data(session_id, "pw_fails_min_length.json")
        if min_length:
            if isinstance(min_length, dict):
                metrics.min_length_violations = len(min_length)
            elif isinstance(min_length, list):
                metrics.min_length_violations = len(min_length)

        complexity = self._load_session_data(session_id, "pw_fails_complexity.json")
        if complexity:
            if isinstance(complexity, dict):
                metrics.complexity_violations = len(complexity)
            elif isinstance(complexity, list):
                metrics.complexity_violations = len(complexity)

        blank = self._load_session_data(session_id, "pw_fails_blank.json")
        if blank and isinstance(blank, list):
            metrics.blank_passwords = len(blank)

        max_age = self._load_session_data(session_id, "pw_fails_max_age.json")
        if max_age:
            if isinstance(max_age, dict):
                metrics.max_age_violations = len(max_age)
            elif isinstance(max_age, list):
                metrics.max_age_violations = len(max_age)

        lm_hashes = self._load_session_data(session_id, "pw_lm_hashes.json")
        if lm_hashes and isinstance(lm_hashes, list):
            metrics.lm_hash_count = len(lm_hashes)

        # Load password reuse
        reuse = self._load_session_data(session_id, "pw_reuse_table.json")
        if reuse and isinstance(reuse, list):
            # Count total accounts with reused passwords
            # Handle two formats:
            # 1. Array format: [[hash, count, [users]], ...]
            # 2. Object format: [{"password_hash": x, "users": [...], "count": n}, ...]
            reuse_count = 0
            for entry in reuse:
                if isinstance(entry, list) and len(entry) >= 3:
                    # Array format: [hash, count, [users]]
                    users = entry[2] if isinstance(entry[2], list) else []
                    if len(users) > 1:
                        reuse_count += len(users)
                elif isinstance(entry, dict):
                    # Object format
                    users = entry.get("users", [])
                    if len(users) > 1:
                        reuse_count += len(users)
            metrics.password_reuse_count = reuse_count
            if metrics.total_accounts > 0:
                metrics.password_reuse_rate = round(reuse_count / metrics.total_accounts * 100, 2)

        # Load bad practices
        bad_practices = self._load_session_data(session_id, "pw_bad_practices.json")
        if bad_practices and isinstance(bad_practices, dict):
            metrics.bad_practices = {}
            total = 0
            for category, entries in bad_practices.items():
                if isinstance(entries, list):
                    # Old format: list of entries
                    count = len(entries)
                    metrics.bad_practices[category] = count
                    total += count
                elif isinstance(entries, dict):
                    # New format: {"count": N, "examples": {...}}
                    count = entries.get("count", 0)
                    metrics.bad_practices[category] = count
                    total += count
            metrics.total_bad_practices = total

        # Load HIBP results if available
        hibp = self._load_session_data(session_id, "hibp_results.json")
        if hibp:
            metrics.hibp_checked = True
            if isinstance(hibp, dict):
                # Support both field naming conventions:
                # - "total_found" (current format from HIBP check)
                # - "exposed_count" (legacy/alternative format)
                metrics.hibp_exposed_count = hibp.get("total_found", hibp.get("exposed_count", 0))
                total_checked = hibp.get("total_checked", 0)
                if total_checked > 0:
                    # Use found_percentage if available, otherwise calculate
                    if "found_percentage" in hibp:
                        metrics.hibp_exposure_rate = hibp.get("found_percentage", 0)
                    else:
                        metrics.hibp_exposure_rate = round(
                            metrics.hibp_exposed_count / total_checked * 100, 2
                        )

        return metrics

    def _load_session_data(self, session_id: str, filename: str) -> Any | None:
        """Load a JSON data file from a session."""
        try:
            data = self.session_manager.load_session_data(filename, session_id)
            return data
        except Exception as e:
            logging.debug(f"Could not load {filename} from session {session_id}: {e}")
            return None

    def compare_sessions(
        self,
        session_ids: list[str],
        company_name: str | None = None
    ) -> TrendComparison | None:
        """
        Compare metrics across multiple sessions.

        Args:
            session_ids: List of session IDs to compare (in chronological order)
            company_name: Optional company name override

        Returns:
            TrendComparison object or None if insufficient sessions
        """
        if len(session_ids) < 2:
            logging.warning("Need at least 2 sessions for trend analysis")
            return None

        # Extract metrics from all sessions
        metrics_list = []
        for sid in session_ids:
            metrics = self.extract_metrics(sid)
            if metrics:
                metrics_list.append(metrics)

        if len(metrics_list) < 2:
            logging.warning("Could not extract metrics from enough sessions")
            return None

        # Sort by date (oldest first)
        metrics_list.sort(key=lambda m: m.session_date)

        # Use provided company name or from first session
        if not company_name:
            company_name = metrics_list[0].company_name

        # Calculate changes between first and last session
        oldest = metrics_list[0]
        newest = metrics_list[-1]
        changes = self._calculate_changes(oldest, newest)

        # Determine overall direction
        improvement_count = sum(1 for c in changes if c.direction == "improvement" and c.is_significant)
        regression_count = sum(1 for c in changes if c.direction == "regression" and c.is_significant)

        if improvement_count > regression_count + 1:
            overall_direction = "improving"
        elif regression_count > improvement_count + 1:
            overall_direction = "regressing"
        else:
            overall_direction = "stable"

        # Generate summary
        summary = self._generate_summary(oldest, newest, changes, overall_direction)

        return TrendComparison(
            company_name=company_name,
            sessions=metrics_list,
            changes=changes,
            overall_direction=overall_direction,
            summary=summary
        )

    def _calculate_changes(
        self,
        old_metrics: TrendMetrics,
        new_metrics: TrendMetrics
    ) -> list[TrendChange]:
        """Calculate changes between two sets of metrics."""
        changes = []

        # Key metrics to compare (ordered by importance)
        # Note: avg_password_length intentionally excluded - it's misleading because
        # as security improves and crack rate decreases, the remaining cracked
        # passwords tend to be the weakest (shortest), making the metric appear
        # to worsen when security is actually improving.
        metrics_to_compare = [
            ("crack_rate", old_metrics.crack_rate, new_metrics.crack_rate),
            ("password_reuse_rate", old_metrics.password_reuse_rate, new_metrics.password_reuse_rate),
            ("blank_passwords", old_metrics.blank_passwords, new_metrics.blank_passwords),
            ("complexity_violations", old_metrics.complexity_violations, new_metrics.complexity_violations),
            ("min_length_violations", old_metrics.min_length_violations, new_metrics.min_length_violations),
            ("total_bad_practices", old_metrics.total_bad_practices, new_metrics.total_bad_practices),
            ("lm_hash_count", old_metrics.lm_hash_count, new_metrics.lm_hash_count),
        ]

        # Add HIBP if both sessions have it
        if old_metrics.hibp_checked and new_metrics.hibp_checked:
            metrics_to_compare.append(
                ("hibp_exposure_rate", old_metrics.hibp_exposure_rate, new_metrics.hibp_exposure_rate)
            )

        for metric_name, old_val, new_val in metrics_to_compare:
            absolute_change = new_val - old_val

            # Calculate percent change (avoid division by zero)
            if old_val != 0:
                percent_change = round((absolute_change / old_val) * 100, 2)
            elif new_val != 0:
                percent_change = 100.0 if new_val > 0 else -100.0
            else:
                percent_change = 0.0

            # Determine direction
            if metric_name in self.LOWER_IS_BETTER:
                if absolute_change < 0:
                    direction = "improvement"
                elif absolute_change > 0:
                    direction = "regression"
                else:
                    direction = "neutral"
            elif metric_name in self.HIGHER_IS_BETTER:
                if absolute_change > 0:
                    direction = "improvement"
                elif absolute_change < 0:
                    direction = "regression"
                else:
                    direction = "neutral"
            else:
                direction = "neutral"

            # Check significance
            threshold = self.SIGNIFICANCE_THRESHOLDS.get(metric_name, 10.0)
            is_significant = abs(percent_change) >= threshold

            changes.append(TrendChange(
                metric_name=metric_name,
                display_name=self.METRIC_DISPLAY_NAMES.get(metric_name, metric_name),
                old_value=old_val,
                new_value=new_val,
                absolute_change=round(absolute_change, 2),
                percent_change=percent_change,
                direction=direction,
                is_significant=is_significant
            ))

        return changes

    def _generate_summary(
        self,
        oldest: TrendMetrics,
        newest: TrendMetrics,
        changes: list[TrendChange],
        overall_direction: str
    ) -> str:
        """Generate a human-readable summary of the trend analysis."""
        parts = []

        # Overall direction statement
        if overall_direction == "improving":
            parts.append("Password security posture has improved overall.")
        elif overall_direction == "regressing":
            parts.append("Password security posture has declined.")
        else:
            parts.append("Password security posture remains relatively stable.")

        # Key metric highlights
        crack_change = next((c for c in changes if c.metric_name == "crack_rate"), None)
        if crack_change and crack_change.is_significant:
            if crack_change.direction == "improvement":
                parts.append(
                    f"Crack rate decreased from {crack_change.old_value}% to "
                    f"{crack_change.new_value}% ({abs(crack_change.percent_change):.1f}% improvement)."
                )
            else:
                parts.append(
                    f"Crack rate increased from {crack_change.old_value}% to "
                    f"{crack_change.new_value}% ({abs(crack_change.percent_change):.1f}% regression)."
                )

        # Add password reuse change to summary
        reuse_change = next((c for c in changes if c.metric_name == "password_reuse_rate"), None)
        if reuse_change and reuse_change.is_significant:
            if reuse_change.direction == "improvement":
                parts.append(
                    f"Password reuse decreased from {reuse_change.old_value}% to "
                    f"{reuse_change.new_value}% ({abs(reuse_change.percent_change):.1f}% improvement)."
                )
            else:
                parts.append(
                    f"Password reuse increased from {reuse_change.old_value}% to "
                    f"{reuse_change.new_value}%."
                )

        # Count significant improvements and regressions
        improvements = [c for c in changes if c.direction == "improvement" and c.is_significant]
        regressions = [c for c in changes if c.direction == "regression" and c.is_significant]

        if improvements:
            names = [c.display_name for c in improvements[:3]]
            if len(improvements) > 3:
                names.append(f"and {len(improvements) - 3} more")
            parts.append(f"Improvements in: {', '.join(names)}.")

        if regressions:
            names = [c.display_name for c in regressions[:3]]
            if len(regressions) > 3:
                names.append(f"and {len(regressions) - 3} more")
            parts.append(f"Areas needing attention: {', '.join(names)}.")

        return " ".join(parts)

    def get_trend_data_for_chart(
        self,
        comparison: TrendComparison
    ) -> dict[str, Any]:
        """
        Format trend data for Chart.js visualization.

        Returns a dictionary suitable for rendering trend charts in the UI.
        """
        sessions = comparison.sessions

        # Labels are session dates (or project descriptions for readability)
        labels = [
            s.project_description[:30] + "..." if len(s.project_description) > 30
            else s.project_description
            for s in sessions
        ]

        # Prepare datasets for different metric groups (ordered by importance)
        # Note: avg_password_length removed - misleading metric (see comment in _calculate_changes)
        return {
            "labels": labels,
            "dates": [s.session_date for s in sessions],
            "datasets": {
                "crack_rate": {
                    "label": "Crack Rate (%)",
                    "data": [s.crack_rate for s in sessions],
                    "borderColor": "#e74c3c",
                    "backgroundColor": "rgba(231, 76, 60, 0.1)",
                },
                "password_reuse_rate": {
                    "label": "Password Reuse Rate (%)",
                    "data": [s.password_reuse_rate for s in sessions],
                    "borderColor": "#3498db",
                    "backgroundColor": "rgba(52, 152, 219, 0.1)",
                },
                "policy_violations": {
                    "label": "Total Policy Violations",
                    "data": [
                        s.min_length_violations + s.complexity_violations + s.blank_passwords
                        for s in sessions
                    ],
                    "borderColor": "#f39c12",
                    "backgroundColor": "rgba(243, 156, 18, 0.1)",
                },
                "bad_practices": {
                    "label": "Bad Practices Count",
                    "data": [s.total_bad_practices for s in sessions],
                    "borderColor": "#9b59b6",
                    "backgroundColor": "rgba(155, 89, 182, 0.1)",
                },
                "total_accounts": {
                    "label": "Total Accounts",
                    "data": [s.total_accounts for s in sessions],
                    "borderColor": "#2ecc71",
                    "backgroundColor": "rgba(46, 204, 113, 0.1)",
                },
                "hibp_exposure_count": {
                    "label": "HIBP Exposed Accounts",
                    "data": [s.hibp_exposed_count for s in sessions],
                    "borderColor": "#e67e22",
                    "backgroundColor": "rgba(230, 126, 34, 0.1)",
                },
            },
            "summary": {
                "company": comparison.company_name,
                "session_count": len(sessions),
                "date_range": f"{sessions[0].session_date[:10]} to {sessions[-1].session_date[:10]}",
                "overall_direction": comparison.overall_direction,
                "summary_text": comparison.summary,
            },
            "changes": [
                {
                    "metric": c.metric_name,
                    "display_name": c.display_name,
                    "old_value": c.old_value,
                    "new_value": c.new_value,
                    "absolute_change": c.absolute_change,
                    "percent_change": c.percent_change,
                    "direction": c.direction,
                    "is_significant": c.is_significant,
                }
                for c in comparison.changes
            ],
        }

    def to_dict(self, comparison: TrendComparison) -> dict[str, Any]:
        """Convert TrendComparison to a JSON-serializable dictionary."""
        return {
            "company_name": comparison.company_name,
            "overall_direction": comparison.overall_direction,
            "summary": comparison.summary,
            "sessions": [
                {
                    "session_id": s.session_id,
                    "session_date": s.session_date,
                    "company_name": s.company_name,
                    "project_description": s.project_description,
                    "metrics": {
                        "total_accounts": s.total_accounts,
                        "cracked_count": s.cracked_count,
                        "crack_rate": s.crack_rate,
                        "avg_password_length": s.avg_password_length,
                        "min_length_violations": s.min_length_violations,
                        "complexity_violations": s.complexity_violations,
                        "blank_passwords": s.blank_passwords,
                        "max_age_violations": s.max_age_violations,
                        "lm_hash_count": s.lm_hash_count,
                        "password_reuse_rate": s.password_reuse_rate,
                        "total_bad_practices": s.total_bad_practices,
                        "hibp_checked": s.hibp_checked,
                        "hibp_exposure_rate": s.hibp_exposure_rate,
                    }
                }
                for s in comparison.sessions
            ],
            "changes": [
                {
                    "metric": c.metric_name,
                    "display_name": c.display_name,
                    "old_value": c.old_value,
                    "new_value": c.new_value,
                    "absolute_change": c.absolute_change,
                    "percent_change": c.percent_change,
                    "direction": c.direction,
                    "is_significant": c.is_significant,
                }
                for c in comparison.changes
            ],
            "chart_data": self.get_trend_data_for_chart(comparison),
        }
