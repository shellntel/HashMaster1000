"""
Company Intelligence (CI) Analyzer

This module handles the extraction, validation, and report generation for Company Intelligence analysis.
It orchestrates the LLM calls to produce organizational intelligence findings.

The workflow:
1. Get unique passwords and account names from the session data
2. For each CI category, call the LLM to extract findings
3. Parse and structure the LLM results
4. Generate formatted report sections
"""

import json
import re
from pathlib import Path
from typing import Generator
from dataclasses import dataclass, field

from .company_intel_prompts import (
    get_ci_prompt,
    get_category_display_name,
    get_all_category_keys,
    CI_CATEGORIES
)


@dataclass
class CIFinding:
    """A single finding within a category."""
    what: str  # What was found
    evidence: list[str] = field(default_factory=list)  # Supporting evidence
    confidence: str = "LOW"  # HIGH/MEDIUM/LOW
    justification: str = ""


@dataclass
class CICategoryResult:
    """Results for a single CI category."""
    category_key: str
    category_name: str
    findings: list[CIFinding] = field(default_factory=list)
    error: str | None = None


@dataclass
class CIResults:
    """Complete CI analysis results."""
    total_passwords: int
    total_accounts: int
    categories: dict[str, CICategoryResult] = field(default_factory=dict)
    sampling_used: bool = False
    sampling_note: str = ""

    def has_findings(self) -> bool:
        """Check if any findings were discovered."""
        for cat in self.categories.values():
            if cat.findings:
                return True
        return False


class CIAnalyzer:
    """
    Company Intelligence Analyzer.

    Coordinates LLM extraction and report generation for organizational intelligence.
    """

    # Default maximum items to send to LLM (sampling threshold)
    # Can be overridden in __init__ or set to None to disable sampling
    DEFAULT_MAX_PASSWORDS = 2000
    DEFAULT_MAX_ACCOUNTS = 2000

    def __init__(
        self,
        session_dir: Path | str,
        max_passwords: int | None = None,
        max_accounts: int | None = None,
        intelligent_sampling: bool = True
    ):
        """
        Initialize analyzer with session directory.

        Args:
            session_dir: Path to session directory containing account_data.json
            max_passwords: Maximum passwords for LLM analysis. None = no limit
                          Default uses DEFAULT_MAX_PASSWORDS (2000)
            max_accounts: Maximum accounts for LLM analysis. None = no limit
                         Default uses DEFAULT_MAX_ACCOUNTS (2000)
            intelligent_sampling: Use smart filtering to exclude likely non-matches
                                 (e.g., random character passwords) from sample
        """
        self.session_dir = Path(session_dir)
        self.max_passwords = max_passwords if max_passwords is not None else self.DEFAULT_MAX_PASSWORDS
        self.max_accounts = max_accounts if max_accounts is not None else self.DEFAULT_MAX_ACCOUNTS
        self.intelligent_sampling = intelligent_sampling
        self._account_data: dict | None = None
        self._password_counts: dict[str, int] | None = None
        self._account_list: list[str] | None = None

    def _load_account_data(self) -> dict:
        """Load account data from session."""
        if self._account_data is not None:
            return self._account_data

        account_file = self.session_dir / "account_data.json"
        if not account_file.exists():
            return {}

        try:
            with open(account_file, "r", encoding="utf-8") as f:
                self._account_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            self._account_data = {}

        return self._account_data

    def _get_password_counts(self) -> dict[str, int]:
        """Get password frequency counts."""
        if self._password_counts is not None:
            return self._password_counts

        account_data = self._load_account_data()
        self._password_counts = {}

        for account in account_data.values():
            pw = account.get("cracked_pw")
            if pw:
                self._password_counts[pw] = self._password_counts.get(pw, 0) + 1

        return self._password_counts

    def _is_likely_semantic_password(self, password: str) -> bool:
        """
        Determine if a password is likely to contain semantic content.

        Filters out random character passwords that are unlikely to match
        any CI categories (company names, locations, etc.).

        Returns:
            True if password might contain semantic content, False if likely random
        """
        # Don't filter if intelligent sampling is disabled
        if not self.intelligent_sampling:
            return True

        # Very short passwords (<4 chars) are unlikely to have semantic meaning
        if len(password) < 4:
            return False

        # Count character types
        has_letter = any(c.isalpha() for c in password)
        letter_count = sum(c.isalpha() for c in password)

        # Must have at least some letters for semantic content
        if not has_letter:
            return False

        # Check for consecutive letters (indicates potential words)
        consecutive_letters = 0
        max_consecutive = 0
        for c in password:
            if c.isalpha():
                consecutive_letters += 1
                max_consecutive = max(max_consecutive, consecutive_letters)
            else:
                consecutive_letters = 0

        # If longest letter sequence is < 3, likely random (e.g., "a2!b9#c")
        if max_consecutive < 3:
            return False

        # Check for patterns that suggest semantic content:
        letter_ratio = letter_count / len(password)

        # If mostly letters (>50%), likely semantic
        if letter_ratio >= 0.5:
            return True

        # If mix of types but has decent letter sequences, might be semantic
        if max_consecutive >= 4:
            return True

        # Otherwise, likely random
        return False

    def _get_account_list(self) -> list[str]:
        """Get list of account names."""
        if self._account_list is not None:
            return self._account_list

        account_data = self._load_account_data()
        accounts = []

        for account_id, account in account_data.items():
            # Try to get a clean account name
            name = account.get("account_name", account_id)
            # Strip domain prefixes like DOMAIN\
            if "\\" in name:
                name = name.split("\\", 1)[1]
            # Strip domain suffixes like @domain.com
            if "@" in name:
                name = name.split("@", 1)[0]
            accounts.append(name)

        self._account_list = list(set(accounts))  # Unique
        return self._account_list

    def get_passwords_for_analysis(self) -> tuple[list[str], bool, str]:
        """
        Get passwords ready for LLM analysis with optional sampling and filtering.

        Returns:
            Tuple of (password_list, sampling_used, sampling_note)
        """
        password_counts = self._get_password_counts()
        total_unique = len(password_counts)

        if not password_counts:
            return [], False, ""

        # Sort by frequency (most common first)
        sorted_passwords = sorted(
            password_counts.items(),
            key=lambda x: (-x[1], x[0])
        )

        sampling_used = False
        sampling_note = ""
        filtered_count = 0

        # Check if sampling is needed
        if self.max_passwords and total_unique > self.max_passwords:
            sampling_used = True
            import random

            # Separate reused vs unique passwords
            reused = [(pw, count) for pw, count in sorted_passwords if count > 1]
            unique = [(pw, count) for pw, count in sorted_passwords if count == 1]

            # Apply intelligent filtering to unique passwords if enabled
            if self.intelligent_sampling:
                unique_before = len(unique)
                unique = [(pw, count) for pw, count in unique if self._is_likely_semantic_password(pw)]
                filtered_count = unique_before - len(unique)

            # Calculate how many slots we have for sampling
            remaining_slots = self.max_passwords - len(reused)

            if remaining_slots > 0 and unique:
                # Sample from filtered unique passwords
                sampled_unique = random.sample(unique, min(remaining_slots, len(unique)))
                sorted_passwords = reused + sampled_unique
            else:
                # If reused alone exceeds limit, just take first N reused
                sorted_passwords = reused[:self.max_passwords]

            # Build sampling note
            parts = [
                f"Dataset contains {total_unique:,} unique passwords.",
                f"Analysis based on {len(sorted_passwords)} passwords",
                f"({len(reused)} reused + {len(sorted_passwords) - len(reused)} sampled)"
            ]

            if filtered_count > 0:
                parts.append(f"Filtered out {filtered_count} likely non-semantic passwords")

            sampling_note = " ".join(parts) + "."

        # Return just the passwords (without counts)
        return [pw for pw, _ in sorted_passwords], sampling_used, sampling_note

    def get_data_for_analysis(self) -> tuple[list[str], list[str], bool, str]:
        """
        Get passwords and accounts ready for LLM analysis.

        Returns:
            Tuple of (password_list, account_list, sampling_used, sampling_note)
        """
        passwords, sampling_used, sampling_note = self.get_passwords_for_analysis()
        accounts = self._get_account_list()[:self.max_accounts]
        return passwords, accounts, sampling_used, sampling_note

    def parse_llm_response(self, response: str, category_key: str) -> list[CIFinding]:
        """
        Parse LLM response and extract findings.

        Args:
            response: Raw LLM response text
            category_key: The category being analyzed

        Returns:
            List of CIFinding objects
        """
        findings = []

        # Handle NO_FINDINGS sentinel
        if "NO_FINDINGS" in response:
            return []

        # Split by finding sections (### Finding N)
        finding_pattern = r'###\s*Finding\s*\d+'
        sections = re.split(finding_pattern, response)

        for section in sections[1:]:  # Skip content before first finding
            finding = self._parse_finding_section(section, category_key)
            if finding:
                findings.append(finding)

        return findings

    def _parse_finding_section(self, section: str, category_key: str) -> CIFinding | None:
        """Parse a single finding section."""
        lines = section.strip().split("\n")

        finding = CIFinding(what="")
        current_field = None
        evidence_lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect field headers
            if line.startswith("**What:**") or line.startswith("**Industry:**") or line.startswith("**Location:**"):
                finding.what = line.split(":", 1)[1].strip().strip("*")
                current_field = "what"
            elif line.startswith("**Evidence"):
                current_field = "evidence"
                # Check if there's content on the same line
                if ":" in line:
                    rest = line.split(":", 1)[1].strip()
                    if rest:
                        evidence_lines.append(rest)
            elif line.startswith("**Confidence:**"):
                conf_text = line.split(":", 1)[1].strip()
                # Extract confidence level
                if "HIGH" in conf_text.upper():
                    finding.confidence = "HIGH"
                elif "MEDIUM" in conf_text.upper():
                    finding.confidence = "MEDIUM"
                else:
                    finding.confidence = "LOW"
                # Get justification (after the level)
                parts = re.split(r'(HIGH|MEDIUM|LOW)', conf_text, flags=re.IGNORECASE)
                if len(parts) > 2:
                    finding.justification = parts[2].strip(" -")
                current_field = "confidence"
            elif current_field == "evidence":
                # Continuation of evidence
                evidence_lines.append(line)

        # Parse evidence lines for passwords/accounts
        for eline in evidence_lines:
            # Extract items in backticks
            backtick_items = re.findall(r'`([^`]+)`', eline)
            finding.evidence.extend(backtick_items)

            # Also try to extract items after common prefixes
            if not backtick_items:
                # Try comma-separated or just the line itself
                items = [item.strip() for item in eline.replace("-", ",").split(",")]
                finding.evidence.extend([i for i in items if i and len(i) > 2])

        if finding.what:
            return finding
        return None

    def analyze_category(
        self,
        category_key: str,
        passwords: list[str],
        accounts: list[str],
        llm_call_fn
    ) -> CICategoryResult:
        """
        Analyze a single category.

        Args:
            category_key: The CI category to analyze
            passwords: List of passwords to analyze
            accounts: List of account names to analyze
            llm_call_fn: Function to call LLM with (prompt: str) -> str

        Returns:
            CICategoryResult with findings
        """
        result = CICategoryResult(
            category_key=category_key,
            category_name=get_category_display_name(category_key)
        )

        if not passwords and not accounts:
            return result

        try:
            # Generate prompt
            prompt = get_ci_prompt(category_key, passwords, accounts)

            # Call LLM
            response = llm_call_fn(prompt)

            # Parse response
            findings = self.parse_llm_response(response, category_key)
            result.findings = findings

        except Exception as e:
            result.error = str(e)

        return result

    def analyze_category_streaming(
        self,
        category_key: str,
        passwords: list[str],
        accounts: list[str],
        llm_stream_fn
    ) -> Generator[tuple[str, CICategoryResult | None], None, None]:
        """
        Analyze a single category with streaming support.

        Args:
            category_key: The CI category to analyze
            passwords: List of passwords to analyze
            accounts: List of account names to analyze
            llm_stream_fn: Generator function that yields (chunk: str) from LLM

        Yields:
            Tuple of (partial_response, final_result)
            - During streaming: (chunk, None)
            - On completion: ("", CICategoryResult)
        """
        result = CICategoryResult(
            category_key=category_key,
            category_name=get_category_display_name(category_key)
        )

        if not passwords and not accounts:
            yield ("", result)
            return

        try:
            # Generate prompt
            prompt = get_ci_prompt(category_key, passwords, accounts)

            # Stream from LLM and accumulate response
            full_response = ""
            for chunk in llm_stream_fn(prompt):
                full_response += chunk
                yield (chunk, None)

            # Parse findings
            findings = self.parse_llm_response(full_response, category_key)
            result.findings = findings

        except Exception as e:
            result.error = str(e)

        yield ("", result)

    def run_full_analysis(self, llm_call_fn) -> CIResults:
        """
        Run complete CI analysis across all categories.

        Args:
            llm_call_fn: Function to call LLM with (prompt: str) -> str

        Returns:
            CIResults with all category results
        """
        passwords, accounts, sampling_used, sampling_note = self.get_data_for_analysis()

        results = CIResults(
            total_passwords=len(self._get_password_counts()),
            total_accounts=len(self._get_account_list()),
            sampling_used=sampling_used,
            sampling_note=sampling_note
        )

        for category_key in get_all_category_keys():
            category_result = self.analyze_category(
                category_key, passwords, accounts, llm_call_fn
            )
            results.categories[category_key] = category_result

        return results

    def format_report_html(self, results: CIResults) -> str:
        """
        Format CI results as HTML for the report page.

        Args:
            results: Complete CI analysis results

        Returns:
            HTML string for the company-intel report section
        """
        html_parts = []

        # Header
        html_parts.append('<div class="ci-analysis">')
        html_parts.append('<h3>Company Intelligence</h3>')
        html_parts.append(f'<p class="ci-overview">Intelligence derived from {results.total_passwords:,} passwords and {results.total_accounts:,} account names.</p>')

        if not results.has_findings():
            html_parts.append('<p class="ci-no-findings">No significant organizational intelligence could be derived from the available data.</p>')
            html_parts.append('</div>')
            return "\n".join(html_parts)

        # Category results
        for category_key in get_all_category_keys():
            if category_key not in results.categories:
                continue

            cat_result = results.categories[category_key]
            if not cat_result.findings:
                continue

            html_parts.append(f'<div class="ci-category">')
            html_parts.append(f'<h4>{cat_result.category_name}</h4>')

            for finding in cat_result.findings:
                confidence_class = finding.confidence.lower()
                html_parts.append(f'<div class="ci-finding confidence-{confidence_class}">')
                html_parts.append(f'<div class="ci-finding-what">{_escape_html(finding.what)}</div>')

                if finding.evidence:
                    html_parts.append('<div class="ci-finding-evidence">')
                    html_parts.append('<strong>Evidence:</strong> ')
                    evidence_html = ", ".join(f'<code>{_escape_html(e)}</code>' for e in finding.evidence[:10])
                    html_parts.append(evidence_html)
                    if len(finding.evidence) > 10:
                        html_parts.append(f' <em>... and {len(finding.evidence) - 10} more</em>')
                    html_parts.append('</div>')

                html_parts.append(f'<div class="ci-finding-confidence">')
                html_parts.append(f'<span class="confidence-badge {confidence_class}">{finding.confidence}</span>')
                if finding.justification:
                    html_parts.append(f' {_escape_html(finding.justification)}')
                html_parts.append('</div>')

                html_parts.append('</div>')  # ci-finding

            html_parts.append('</div>')  # ci-category

        html_parts.append('</div>')  # ci-analysis

        return "\n".join(html_parts)

    def format_report_text(self, results: CIResults) -> str:
        """
        Format CI results as plain text.

        Args:
            results: Complete CI analysis results

        Returns:
            Plain text report string
        """
        lines = []
        lines.append("COMPANY INTELLIGENCE ANALYSIS")
        lines.append("=" * 50)
        lines.append(f"Passwords analyzed: {results.total_passwords:,}")
        lines.append(f"Accounts analyzed: {results.total_accounts:,}")
        lines.append("")

        if not results.has_findings():
            lines.append("No significant organizational intelligence could be derived from the available data.")
            return "\n".join(lines)

        for category_key in get_all_category_keys():
            if category_key not in results.categories:
                continue

            cat_result = results.categories[category_key]
            if not cat_result.findings:
                continue

            lines.append(f"\n{cat_result.category_name.upper()}")
            lines.append("-" * 30)

            for i, finding in enumerate(cat_result.findings, 1):
                lines.append(f"\n{i}. {finding.what}")
                lines.append(f"   Confidence: {finding.confidence}")
                if finding.evidence:
                    evidence_str = ", ".join(finding.evidence[:5])
                    if len(finding.evidence) > 5:
                        evidence_str += f" (+{len(finding.evidence) - 5} more)"
                    lines.append(f"   Evidence: {evidence_str}")

        return "\n".join(lines)

    def format_report_markdown(self, results: CIResults) -> str:
        """
        Format CI results as markdown for the AAIA report.

        Args:
            results: Complete CI analysis results

        Returns:
            Markdown report string
        """
        lines = []

        if not results.has_findings():
            lines.append("No significant organizational intelligence could be derived from the available data.")
            return "\n".join(lines)

        for category_key in get_all_category_keys():
            if category_key not in results.categories:
                continue

            cat_result = results.categories[category_key]
            if not cat_result.findings:
                continue

            lines.append(f"### {cat_result.category_name}")
            lines.append("")

            for finding in cat_result.findings:
                lines.append(f"**Finding:** {finding.what}")
                lines.append("")

                if finding.evidence:
                    evidence_formatted = ", ".join(f"`{e}`" for e in finding.evidence[:10])
                    if len(finding.evidence) > 10:
                        evidence_formatted += f" ... and {len(finding.evidence) - 10} more"
                    lines.append(f"**Evidence:** {evidence_formatted}")
                    lines.append("")

                lines.append(f"**Confidence:** {finding.confidence}")
                if finding.justification:
                    lines.append(f" - {finding.justification}")
                lines.append("")

        return "\n".join(lines)


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def results_to_dict(results: CIResults) -> dict:
    """Convert CIResults to a JSON-serializable dictionary."""
    return {
        "total_passwords": results.total_passwords,
        "total_accounts": results.total_accounts,
        "sampling_used": results.sampling_used,
        "sampling_note": results.sampling_note,
        "categories": {
            key: {
                "name": cat.category_name,
                "findings": [
                    {
                        "what": f.what,
                        "evidence": f.evidence,
                        "confidence": f.confidence,
                        "justification": f.justification
                    }
                    for f in cat.findings
                ],
                "finding_count": len(cat.findings),
                "error": cat.error
            }
            for key, cat in results.categories.items()
        }
    }


def dict_to_results(data: dict) -> CIResults:
    """Convert a dictionary back to CIResults."""
    results = CIResults(
        total_passwords=data.get("total_passwords", 0),
        total_accounts=data.get("total_accounts", 0),
        sampling_used=data.get("sampling_used", False),
        sampling_note=data.get("sampling_note", "")
    )

    for key, cat_data in data.get("categories", {}).items():
        findings = []
        for f_data in cat_data.get("findings", []):
            findings.append(CIFinding(
                what=f_data.get("what", ""),
                evidence=f_data.get("evidence", []),
                confidence=f_data.get("confidence", "LOW"),
                justification=f_data.get("justification", "")
            ))

        results.categories[key] = CICategoryResult(
            category_key=key,
            category_name=cat_data.get("name", key),
            findings=findings,
            error=cat_data.get("error")
        )

    return results
