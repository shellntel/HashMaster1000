"""
Semantic Password Intelligence (SPI) Analyzer

This module handles the extraction, validation, and report generation for SPI analysis.
It orchestrates the LLM calls and Python validation to produce accurate statistics.

The workflow:
1. Get unique passwords from the session data
2. For each SPI category, call the LLM to extract matching passwords
3. Validate LLM results against the original password list
4. Count matches and calculate prevalence
5. Generate formatted report sections
"""

import json
import re
from pathlib import Path
from typing import Generator
from dataclasses import dataclass, field

from .spi_prompts import (
    get_spi_prompt,
    get_category_display_name,
    get_all_category_keys,
    SPI_CATEGORIES
)


@dataclass
class SPICategoryResult:
    """Results for a single SPI category."""
    category_key: str
    category_name: str
    matches: list[str] = field(default_factory=list)
    # For language category: maps password -> detected language
    language_map: dict[str, str] = field(default_factory=dict)
    error: str | None = None


@dataclass
class SPIResults:
    """Complete SPI analysis results."""
    total_passwords: int
    categories: dict[str, SPICategoryResult] = field(default_factory=dict)
    sampling_used: bool = False
    sampling_note: str = ""

    def get_category_stats(self, category_key: str) -> tuple[int, float]:
        """Get match count and percentage for a category."""
        if category_key not in self.categories:
            return 0, 0.0
        matches = len(self.categories[category_key].matches)
        pct = (matches / self.total_passwords * 100) if self.total_passwords > 0 else 0.0
        return matches, pct


class SPIAnalyzer:
    """
    Semantic Password Intelligence Analyzer.

    Coordinates LLM extraction, validation, and report generation.
    """

    # Default maximum passwords to send to LLM (sampling threshold)
    # Can be overridden in __init__ or set to None to disable sampling
    DEFAULT_MAX_PASSWORDS = 2000

    def __init__(
        self,
        session_dir: Path | str,
        max_passwords: int | None = None,
        intelligent_sampling: bool = True
    ):
        """
        Initialize analyzer with session directory.

        Args:
            session_dir: Path to session directory containing account_data.json
            max_passwords: Maximum passwords for LLM analysis. None = no limit (analyze all)
                          Default uses DEFAULT_MAX_PASSWORDS (500)
            intelligent_sampling: Use smart filtering to exclude likely non-matches
                                 (e.g., random character passwords) from sample
        """
        self.session_dir = Path(session_dir)
        self.max_passwords = max_passwords if max_passwords is not None else self.DEFAULT_MAX_PASSWORDS
        self.intelligent_sampling = intelligent_sampling
        self._account_data: dict | None = None
        self._password_set: set[str] | None = None
        self._password_counts: dict[str, int] | None = None

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

    def _get_password_set(self) -> set[str]:
        """Get set of all unique passwords for validation."""
        if self._password_set is not None:
            return self._password_set

        self._password_set = set(self._get_password_counts().keys())
        return self._password_set

    def _is_likely_semantic_password(self, password: str) -> bool:
        """
        Determine if a password is likely to contain semantic content.

        Filters out random character passwords that are unlikely to match
        any SPI categories (languages, brands, sports, etc.).

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
        digit_count = sum(c.isdigit() for c in password)
        special_count = sum(not c.isalnum() for c in password)

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
        # - Mostly letters with some numbers/special (like "Summer2024!")
        # - Has word-like structure (consonant-vowel patterns)
        letter_ratio = letter_count / len(password)

        # If mostly letters (>50%), likely semantic
        if letter_ratio >= 0.5:
            return True

        # If mix of types but has decent letter sequences, might be semantic
        if max_consecutive >= 4:
            return True

        # Otherwise, likely random
        return False

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

    def parse_llm_response(self, response: str, category_key: str) -> tuple[list[str], dict[str, str]]:
        """
        Parse LLM response and extract password matches.

        Args:
            response: Raw LLM response text
            category_key: The category being analyzed (for special handling)

        Returns:
            Tuple of (matched_passwords, language_map)
            language_map is only populated for the 'language' category
        """
        matches = []
        language_map = {}

        # Handle NO_MATCHES sentinel
        if "NO_MATCHES" in response:
            return [], {}

        # Split into lines and clean up
        lines = response.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Skip common LLM artifacts
            if line.startswith("MATCHING") or line.startswith("Here"):
                continue
            if line.startswith("-") or line.startswith("*") or line.startswith("•"):
                # Remove list markers
                line = line.lstrip("-*• ").strip()

            # Handle language category special format: password|Language
            if category_key == "language" and "|" in line:
                parts = line.split("|", 1)
                password = parts[0].strip()
                language = parts[1].strip() if len(parts) > 1 else "Unknown"
                matches.append(password)
                language_map[password] = language
            else:
                matches.append(line)

        return matches, language_map

    def validate_matches(self, extracted: list[str]) -> list[str]:
        """
        Validate extracted passwords against actual password set.

        Only returns passwords that actually exist in the dataset.
        """
        password_set = self._get_password_set()
        return [pw for pw in extracted if pw in password_set]

    def analyze_category(
        self,
        category_key: str,
        passwords: list[str],
        llm_call_fn
    ) -> SPICategoryResult:
        """
        Analyze a single category.

        Args:
            category_key: The SPI category to analyze
            passwords: List of passwords to analyze
            llm_call_fn: Function to call LLM with (prompt: str) -> str

        Returns:
            SPICategoryResult with matches and metadata
        """
        result = SPICategoryResult(
            category_key=category_key,
            category_name=get_category_display_name(category_key)
        )

        if not passwords:
            return result

        try:
            # Generate prompt
            prompt = get_spi_prompt(category_key, passwords)

            # Call LLM
            response = llm_call_fn(prompt)

            # Parse response
            extracted, language_map = self.parse_llm_response(response, category_key)

            # Validate against actual passwords
            validated = self.validate_matches(extracted)

            result.matches = validated
            result.language_map = {
                pw: lang for pw, lang in language_map.items()
                if pw in validated
            }

        except Exception as e:
            result.error = str(e)

        return result

    def analyze_category_streaming(
        self,
        category_key: str,
        passwords: list[str],
        llm_stream_fn
    ) -> Generator[tuple[str, SPICategoryResult | None], None, None]:
        """
        Analyze a single category with streaming support.

        Args:
            category_key: The SPI category to analyze
            passwords: List of passwords to analyze
            llm_stream_fn: Generator function that yields (chunk: str) from LLM

        Yields:
            Tuple of (partial_response, final_result)
            - During streaming: (chunk, None)
            - On completion: ("", SPICategoryResult)
        """
        result = SPICategoryResult(
            category_key=category_key,
            category_name=get_category_display_name(category_key)
        )

        if not passwords:
            yield ("", result)
            return

        try:
            # Generate prompt
            prompt = get_spi_prompt(category_key, passwords)

            # Stream from LLM and accumulate response
            full_response = ""
            for chunk in llm_stream_fn(prompt):
                full_response += chunk
                yield (chunk, None)

            # Parse and validate
            extracted, language_map = self.parse_llm_response(full_response, category_key)
            validated = self.validate_matches(extracted)

            result.matches = validated
            result.language_map = {
                pw: lang for pw, lang in language_map.items()
                if pw in validated
            }

        except Exception as e:
            result.error = str(e)

        yield ("", result)

    def run_full_analysis(self, llm_call_fn) -> SPIResults:
        """
        Run complete SPI analysis across all categories.

        Args:
            llm_call_fn: Function to call LLM with (prompt: str) -> str

        Returns:
            SPIResults with all category results
        """
        passwords, sampling_used, sampling_note = self.get_passwords_for_analysis()

        results = SPIResults(
            total_passwords=len(self._get_password_set()),
            sampling_used=sampling_used,
            sampling_note=sampling_note
        )

        for category_key in get_all_category_keys():
            category_result = self.analyze_category(
                category_key, passwords, llm_call_fn
            )
            results.categories[category_key] = category_result

        return results

    def format_report_html(self, results: SPIResults) -> str:
        """
        Format SPI results as HTML for the report page.

        Args:
            results: Complete SPI analysis results

        Returns:
            HTML string for the weak-habits report section
        """
        html_parts = []

        # Header with overview
        html_parts.append('<div class="spi-analysis">')
        html_parts.append('<h3>Semantic Password Intelligence</h3>')
        html_parts.append(f'<p class="spi-overview">Analysis of {results.total_passwords:,} unique passwords across {len(results.categories)} semantic categories.</p>')

        if results.sampling_used:
            html_parts.append(f'<p class="spi-sampling-note">⚠️ {results.sampling_note}</p>')

        # Category results table
        html_parts.append('<table class="spi-results-table">')
        html_parts.append('<thead><tr><th>Category</th><th>Matches</th><th>Prevalence</th></tr></thead>')
        html_parts.append('<tbody>')

        for category_key in get_all_category_keys():
            if category_key not in results.categories:
                continue

            cat_result = results.categories[category_key]
            count, pct = results.get_category_stats(category_key)

            # Determine severity class based on prevalence
            if pct >= 10:
                severity = "high"
            elif pct >= 5:
                severity = "medium"
            elif pct > 0:
                severity = "low"
            else:
                severity = "none"

            html_parts.append(f'<tr class="severity-{severity}">')
            html_parts.append(f'<td>{cat_result.category_name}</td>')
            html_parts.append(f'<td>{count:,}</td>')
            html_parts.append(f'<td>{pct:.1f}%</td>')
            html_parts.append('</tr>')

        html_parts.append('</tbody></table>')

        # Detailed findings for categories with matches
        html_parts.append('<div class="spi-details">')
        html_parts.append('<h4>Detailed Findings</h4>')

        for category_key in get_all_category_keys():
            if category_key not in results.categories:
                continue

            cat_result = results.categories[category_key]
            if not cat_result.matches:
                continue

            count, pct = results.get_category_stats(category_key)
            html_parts.append(f'<div class="spi-category-detail">')
            html_parts.append(f'<h5>{cat_result.category_name} ({count} passwords, {pct:.1f}%)</h5>')

            # Show example matches (limit to avoid huge reports)
            examples = cat_result.matches[:10]
            html_parts.append('<ul class="spi-examples">')
            for pw in examples:
                if category_key == "language" and pw in cat_result.language_map:
                    html_parts.append(f'<li><code>{_escape_html(pw)}</code> ({cat_result.language_map[pw]})</li>')
                else:
                    html_parts.append(f'<li><code>{_escape_html(pw)}</code></li>')

            if len(cat_result.matches) > 10:
                html_parts.append(f'<li><em>... and {len(cat_result.matches) - 10} more</em></li>')
            html_parts.append('</ul>')
            html_parts.append('</div>')

        html_parts.append('</div>')  # spi-details
        html_parts.append('</div>')  # spi-analysis

        return "\n".join(html_parts)

    def format_report_text(self, results: SPIResults) -> str:
        """
        Format SPI results as plain text.

        Args:
            results: Complete SPI analysis results

        Returns:
            Plain text report string
        """
        lines = []
        lines.append("SEMANTIC PASSWORD INTELLIGENCE ANALYSIS")
        lines.append("=" * 50)
        lines.append(f"Total unique passwords analyzed: {results.total_passwords:,}")
        lines.append("")

        if results.sampling_used:
            lines.append(f"Note: {results.sampling_note}")
            lines.append("")

        lines.append("CATEGORY BREAKDOWN:")
        lines.append("-" * 30)

        for category_key in get_all_category_keys():
            if category_key not in results.categories:
                continue

            cat_result = results.categories[category_key]
            count, pct = results.get_category_stats(category_key)

            lines.append(f"{cat_result.category_name}: {count:,} ({pct:.1f}%)")

        lines.append("")
        lines.append("TOP FINDINGS:")
        lines.append("-" * 30)

        # Sort categories by match count (descending)
        sorted_cats = sorted(
            results.categories.items(),
            key=lambda x: len(x[1].matches),
            reverse=True
        )

        for category_key, cat_result in sorted_cats[:5]:  # Top 5
            if not cat_result.matches:
                continue

            lines.append(f"\n{cat_result.category_name}:")
            for pw in cat_result.matches[:5]:
                if category_key == "language" and pw in cat_result.language_map:
                    lines.append(f"  - {pw} ({cat_result.language_map[pw]})")
                else:
                    lines.append(f"  - {pw}")

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


def results_to_dict(results: SPIResults) -> dict:
    """Convert SPIResults to a JSON-serializable dictionary."""
    return {
        "total_passwords": results.total_passwords,
        "sampling_used": results.sampling_used,
        "sampling_note": results.sampling_note,
        "categories": {
            key: {
                "name": cat.category_name,
                "matches": cat.matches,
                "match_count": len(cat.matches),
                "percentage": (len(cat.matches) / results.total_passwords * 100)
                    if results.total_passwords > 0 else 0.0,
                "language_map": cat.language_map,
                "error": cat.error
            }
            for key, cat in results.categories.items()
        }
    }


def dict_to_results(data: dict) -> SPIResults:
    """Convert a dictionary back to SPIResults."""
    results = SPIResults(
        total_passwords=data.get("total_passwords", 0),
        sampling_used=data.get("sampling_used", False),
        sampling_note=data.get("sampling_note", "")
    )

    for key, cat_data in data.get("categories", {}).items():
        results.categories[key] = SPICategoryResult(
            category_key=key,
            category_name=cat_data.get("name", key),
            matches=cat_data.get("matches", []),
            language_map=cat_data.get("language_map", {}),
            error=cat_data.get("error")
        )

    return results
