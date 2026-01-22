"""
LLM-Enhanced Description Analysis for AAIA

Complements regex-based description_analysis.py with semantic LLM detection
for finding sensitive information that regex patterns miss.

Uses chunked processing for complete dataset coverage without sampling loss.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Any, Callable
import json
import re

from .chunk_manager import ChunkManager, ChunkConfig, ChunkProgress, AggregatedResults, TimeEstimate
from .description_llm_prompts import get_da_prompt, get_all_category_keys, DA_CATEGORIES


@dataclass
class LLMDescriptionFinding:
    """A single finding from LLM analysis."""
    category: str  # e.g., "Password", "PII_SSN", "API_Key"
    value: str  # Masked value for display
    raw_value: str  # Original unmasked value (if available)
    confidence: float  # 0.0-1.0
    reasoning: str  # LLM's explanation
    detection_method: str = "llm"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "value": self.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "detection_method": self.detection_method
        }


@dataclass
class LLMAccountResult:
    """LLM analysis results for a single account."""
    sam_account_name: str
    description: str
    findings: list[LLMDescriptionFinding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sam_account_name": self.sam_account_name,
            "description": self.description[:100] + "..." if len(self.description) > 100 else self.description,
            "has_findings": self.has_findings,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings]
        }


@dataclass
class LLMCategoryResult:
    """Results for a single category analysis."""
    category_key: str
    category_name: str
    accounts_analyzed: int
    accounts_with_findings: int
    total_findings: int
    findings: list[LLMAccountResult]
    processing_time: float
    chunks_processed: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category_key": self.category_key,
            "category_name": self.category_name,
            "accounts_analyzed": self.accounts_analyzed,
            "accounts_with_findings": self.accounts_with_findings,
            "total_findings": self.total_findings,
            "processing_time": round(self.processing_time, 2),
            "chunks_processed": self.chunks_processed,
            "success": self.error is None,
            "error": self.error
        }


@dataclass
class LLMDescriptionAnalysisResults:
    """Complete LLM description analysis results across all categories."""
    total_accounts: int
    accounts_with_descriptions: int
    accounts_analyzed: int
    total_findings: int
    unique_accounts_with_findings: int
    category_results: dict[str, LLMCategoryResult]
    all_findings: list[LLMAccountResult]
    total_time: float
    chunk_size: int
    total_chunks: int
    model_used: str = ""
    temperature: float = 0.1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_accounts": self.total_accounts,
            "accounts_with_descriptions": self.accounts_with_descriptions,
            "accounts_analyzed": self.accounts_analyzed,
            "total_findings": self.total_findings,
            "unique_accounts_with_findings": self.unique_accounts_with_findings,
            "category_results": {k: v.to_dict() for k, v in self.category_results.items()},
            "total_time": round(self.total_time, 2),
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "model_used": self.model_used,
            "temperature": self.temperature
        }


class DescriptionLLMAnalyzer:
    """
    LLM-enhanced description analyzer with chunked processing.

    Complements regex analysis with semantic understanding for finding
    sensitive information that pattern matching misses.

    Features:
    - Chunked processing for large datasets
    - Progress streaming for UI updates
    - Time estimation with warnings
    - Result deduplication across chunks
    """

    DEFAULT_CHUNK_SIZE = 100
    MIN_CHUNK_SIZE = 25
    MAX_CHUNK_SIZE = 500
    RECOMMENDED_MODEL = "llama3.1:70b"
    RECOMMENDED_TEMPERATURE = 0.1

    def __init__(
        self,
        session_dir: Path | str,
        chunk_size: int | None = None
    ):
        self.session_dir = Path(session_dir)
        self.chunk_size = self._validate_chunk_size(chunk_size)
        self._users: list[dict] | None = None
        self._users_with_desc: list[dict] | None = None

    def _validate_chunk_size(self, chunk_size: int | None) -> int:
        """Validate and return chunk size within allowed range."""
        if chunk_size is None:
            return self.DEFAULT_CHUNK_SIZE
        return max(self.MIN_CHUNK_SIZE, min(self.MAX_CHUNK_SIZE, chunk_size))

    def _load_users(self) -> list[dict]:
        """Load user data from ADD JSON."""
        if self._users is not None:
            return self._users

        add_file = self.session_dir / "add_data.json"
        if not add_file.exists():
            self._users = []
            return self._users

        try:
            with open(add_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle different ADD JSON structures
            if isinstance(data, dict) and "Users" in data:
                self._users = data["Users"]
            elif isinstance(data, list):
                self._users = data
            else:
                self._users = []

        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading ADD data: {e}")
            self._users = []

        return self._users

    def get_users_with_descriptions(self) -> list[dict]:
        """Get users that have non-empty descriptions."""
        if self._users_with_desc is not None:
            return self._users_with_desc

        users = self._load_users()
        self._users_with_desc = [
            u for u in users
            if u.get("Description", u.get("description", "")).strip()
        ]
        return self._users_with_desc

    def get_total_user_count(self) -> int:
        """Get total number of users in the dataset."""
        return len(self._load_users())

    def estimate_analysis_time(self, sample_time: float | None = None) -> TimeEstimate:
        """
        Estimate time for complete analysis across all categories.

        Args:
            sample_time: Optional measured time per chunk from a previous run

        Returns:
            TimeEstimate with time and warning level
        """
        users = self.get_users_with_descriptions()
        num_categories = len(get_all_category_keys())

        config = ChunkConfig(chunk_size=self.chunk_size)
        manager: ChunkManager[dict, LLMAccountResult] = ChunkManager(config)

        return manager.estimate_time(
            total_items=len(users),
            sample_time=sample_time,
            categories=num_categories
        )

    def _format_accounts_for_prompt(self, users: list[dict]) -> str:
        """Format user accounts for LLM prompt."""
        lines = []
        for user in users:
            sam = user.get("SamAccountName", user.get("sam_account_name", ""))
            desc = user.get("Description", user.get("description", ""))
            if sam and desc:
                # Escape any special characters and limit description length
                desc_clean = desc.replace("\n", " ").replace("\r", " ")
                if len(desc_clean) > 500:
                    desc_clean = desc_clean[:500] + "..."
                lines.append(f"[{sam}]: {desc_clean}")
        return "\n".join(lines)

    def _parse_llm_response(
        self,
        response: str,
        category_key: str,
        users_in_chunk: list[dict]
    ) -> list[LLMAccountResult]:
        """
        Parse LLM response into structured findings.

        Args:
            response: Raw LLM response text
            category_key: The category being analyzed
            users_in_chunk: Users that were analyzed (for description lookup)

        Returns:
            List of LLMAccountResult with findings
        """
        results: list[LLMAccountResult] = []

        # Check for no findings
        if "NO_FINDINGS" in response.upper():
            return results

        # Build lookup for user descriptions
        desc_lookup = {
            u.get("SamAccountName", u.get("sam_account_name", "")).lower(): u.get("Description", u.get("description", ""))
            for u in users_in_chunk
        }

        # Parse findings using the structured format
        # Expected format per finding:
        # ACCOUNT: xxx
        # CATEGORY: xxx
        # VALUE: xxx
        # CONFIDENCE: xxx
        # REASONING: xxx
        # ---

        current_finding: dict[str, str] = {}
        current_field = None

        for line in response.split("\n"):
            line = line.strip()

            if line == "---":
                # End of a finding block
                if current_finding.get("account"):
                    account_name = current_finding["account"]
                    finding = LLMDescriptionFinding(
                        category=current_finding.get("category", category_key),
                        value=current_finding.get("value", ""),
                        raw_value=current_finding.get("value", ""),
                        confidence=self._parse_confidence(current_finding.get("confidence", "0.8")),
                        reasoning=current_finding.get("reasoning", "")
                    )

                    # Find or create account result
                    existing = next((r for r in results if r.sam_account_name.lower() == account_name.lower()), None)
                    if existing:
                        existing.findings.append(finding)
                    else:
                        desc = desc_lookup.get(account_name.lower(), "")
                        results.append(LLMAccountResult(
                            sam_account_name=account_name,
                            description=desc,
                            findings=[finding]
                        ))

                current_finding = {}
                current_field = None

            elif line.upper().startswith("ACCOUNT:"):
                current_finding["account"] = line.split(":", 1)[1].strip()
                current_field = "account"
            elif line.upper().startswith("CATEGORY:"):
                current_finding["category"] = line.split(":", 1)[1].strip()
                current_field = "category"
            elif line.upper().startswith("VALUE:"):
                current_finding["value"] = line.split(":", 1)[1].strip()
                current_field = "value"
            elif line.upper().startswith("CONFIDENCE:"):
                current_finding["confidence"] = line.split(":", 1)[1].strip()
                current_field = "confidence"
            elif line.upper().startswith("REASONING:"):
                current_finding["reasoning"] = line.split(":", 1)[1].strip()
                current_field = "reasoning"
            elif current_field == "reasoning" and line:
                # Continue multi-line reasoning
                current_finding["reasoning"] = current_finding.get("reasoning", "") + " " + line

        # Handle last finding if no trailing ---
        if current_finding.get("account"):
            account_name = current_finding["account"]
            finding = LLMDescriptionFinding(
                category=current_finding.get("category", category_key),
                value=current_finding.get("value", ""),
                raw_value=current_finding.get("value", ""),
                confidence=self._parse_confidence(current_finding.get("confidence", "0.8")),
                reasoning=current_finding.get("reasoning", "")
            )

            existing = next((r for r in results if r.sam_account_name.lower() == account_name.lower()), None)
            if existing:
                existing.findings.append(finding)
            else:
                desc = desc_lookup.get(account_name.lower(), "")
                results.append(LLMAccountResult(
                    sam_account_name=account_name,
                    description=desc,
                    findings=[finding]
                ))

        return results

    def _parse_confidence(self, value: str) -> float:
        """Parse confidence value from string."""
        try:
            # Handle formats like "0.95", "95%", "0.95 (high)"
            cleaned = re.sub(r'[^\d.]', '', value.split()[0] if value.split() else value)
            conf = float(cleaned)
            if conf > 1:
                conf = conf / 100  # Convert percentage
            return min(1.0, max(0.0, conf))
        except (ValueError, IndexError):
            return 0.8  # Default confidence

    def analyze_category(
        self,
        category_key: str,
        llm_call_fn: Callable[[str], str]
    ) -> LLMCategoryResult:
        """
        Analyze a single category with chunked processing.

        Args:
            category_key: Category to analyze ("passwords", "pii", "credentials")
            llm_call_fn: Function that takes prompt and returns LLM response

        Returns:
            LLMCategoryResult with all findings for this category
        """
        import time

        users = self.get_users_with_descriptions()
        category_info = DA_CATEGORIES.get(category_key, {})
        category_name = category_info.get("name", category_key)

        if not users:
            return LLMCategoryResult(
                category_key=category_key,
                category_name=category_name,
                accounts_analyzed=0,
                accounts_with_findings=0,
                total_findings=0,
                findings=[],
                processing_time=0.0,
                chunks_processed=0
            )

        config = ChunkConfig(chunk_size=self.chunk_size)
        manager: ChunkManager[dict, LLMAccountResult] = ChunkManager(config)

        start_time = time.time()
        all_findings: list[LLMAccountResult] = []

        def process_chunk(chunk: list[dict], chunk_idx: int) -> list[LLMAccountResult]:
            accounts_data = self._format_accounts_for_prompt(chunk)
            prompt = get_da_prompt(category_key, accounts_data)
            response = llm_call_fn(prompt)
            return self._parse_llm_response(response, category_key, chunk)

        # Process all chunks
        for progress, chunk_result in manager.process_chunks(users, process_chunk):
            if chunk_result and chunk_result.success:
                all_findings.extend(chunk_result.results)

        # Aggregate and deduplicate
        aggregated = manager.get_aggregated_results(
            dedupe_key_fn=lambda r: f"{r.sam_account_name.lower()}"
        )

        # Merge findings for same account
        merged_findings = self._merge_account_findings(aggregated.unique_results)

        total_time = time.time() - start_time

        return LLMCategoryResult(
            category_key=category_key,
            category_name=category_name,
            accounts_analyzed=len(users),
            accounts_with_findings=len([f for f in merged_findings if f.has_findings]),
            total_findings=sum(f.finding_count for f in merged_findings),
            findings=merged_findings,
            processing_time=total_time,
            chunks_processed=aggregated.total_chunks
        )

    def analyze_category_streaming(
        self,
        category_key: str,
        llm_call_fn: Callable[[str], str]
    ) -> Generator[tuple[ChunkProgress, list[LLMAccountResult] | None], None, LLMCategoryResult]:
        """
        Analyze a category with chunked streaming for progress updates.

        Yields progress updates during processing, returns final result.

        Args:
            category_key: Category to analyze
            llm_call_fn: Function that takes prompt and returns LLM response

        Yields:
            Tuple of (ChunkProgress, findings or None)

        Returns:
            LLMCategoryResult when complete
        """
        import time

        users = self.get_users_with_descriptions()
        category_info = DA_CATEGORIES.get(category_key, {})
        category_name = category_info.get("name", category_key)

        if not users:
            empty_result = LLMCategoryResult(
                category_key=category_key,
                category_name=category_name,
                accounts_analyzed=0,
                accounts_with_findings=0,
                total_findings=0,
                findings=[],
                processing_time=0.0,
                chunks_processed=0
            )
            return empty_result

        config = ChunkConfig(chunk_size=self.chunk_size)
        manager: ChunkManager[dict, LLMAccountResult] = ChunkManager(config)

        start_time = time.time()
        all_findings: list[LLMAccountResult] = []

        def process_chunk(chunk: list[dict], chunk_idx: int) -> list[LLMAccountResult]:
            accounts_data = self._format_accounts_for_prompt(chunk)
            prompt = get_da_prompt(category_key, accounts_data)
            response = llm_call_fn(prompt)
            return self._parse_llm_response(response, category_key, chunk)

        # Process with streaming
        for progress, chunk_result in manager.process_chunks(users, process_chunk):
            if chunk_result:
                if chunk_result.success:
                    all_findings.extend(chunk_result.results)
                yield progress, chunk_result.results if chunk_result.success else None
            else:
                yield progress, None

        # Final aggregation
        aggregated = manager.get_aggregated_results(
            dedupe_key_fn=lambda r: f"{r.sam_account_name.lower()}"
        )

        merged_findings = self._merge_account_findings(aggregated.unique_results)
        total_time = time.time() - start_time

        return LLMCategoryResult(
            category_key=category_key,
            category_name=category_name,
            accounts_analyzed=len(users),
            accounts_with_findings=len([f for f in merged_findings if f.has_findings]),
            total_findings=sum(f.finding_count for f in merged_findings),
            findings=merged_findings,
            processing_time=total_time,
            chunks_processed=aggregated.total_chunks
        )

    def _merge_account_findings(
        self,
        results: list[LLMAccountResult]
    ) -> list[LLMAccountResult]:
        """Merge findings for the same account from different chunks."""
        by_account: dict[str, LLMAccountResult] = {}

        for r in results:
            key = r.sam_account_name.lower()
            if key in by_account:
                # Merge findings
                existing_finding_keys = {
                    (f.category, f.value) for f in by_account[key].findings
                }
                for finding in r.findings:
                    if (finding.category, finding.value) not in existing_finding_keys:
                        by_account[key].findings.append(finding)
            else:
                by_account[key] = r

        return list(by_account.values())

    def run_full_analysis(
        self,
        llm_call_fn: Callable[[str], str],
        model_name: str = "",
        temperature: float = 0.1
    ) -> LLMDescriptionAnalysisResults:
        """
        Run complete analysis across all categories.

        Args:
            llm_call_fn: Function that takes prompt and returns LLM response
            model_name: Name of the model being used (for metadata)
            temperature: Temperature used (for metadata)

        Returns:
            LLMDescriptionAnalysisResults with all findings
        """
        import time

        users = self._load_users()
        users_with_desc = self.get_users_with_descriptions()

        start_time = time.time()
        category_results: dict[str, LLMCategoryResult] = {}
        all_findings: list[LLMAccountResult] = []

        # Run each category
        for category_key in get_all_category_keys():
            result = self.analyze_category(category_key, llm_call_fn)
            category_results[category_key] = result
            all_findings.extend(result.findings)

        # Merge findings across categories for same accounts
        merged_all = self._merge_account_findings(all_findings)

        total_time = time.time() - start_time
        total_chunks = sum(cr.chunks_processed for cr in category_results.values())

        return LLMDescriptionAnalysisResults(
            total_accounts=len(users),
            accounts_with_descriptions=len(users_with_desc),
            accounts_analyzed=len(users_with_desc),
            total_findings=sum(f.finding_count for f in merged_all),
            unique_accounts_with_findings=len([f for f in merged_all if f.has_findings]),
            category_results=category_results,
            all_findings=merged_all,
            total_time=total_time,
            chunk_size=self.chunk_size,
            total_chunks=total_chunks,
            model_used=model_name,
            temperature=temperature
        )

    def format_report_html(self, results: LLMDescriptionAnalysisResults) -> str:
        """Format results as HTML for display in the report."""
        html_parts = [
            '<div class="da-llm-results">',
            '<div class="da-llm-summary">',
            f'<div class="da-stat"><span class="da-stat-value">{results.accounts_analyzed}</span>',
            '<span class="da-stat-label">Accounts Analyzed</span></div>',
            f'<div class="da-stat"><span class="da-stat-value">{results.unique_accounts_with_findings}</span>',
            '<span class="da-stat-label">Accounts with Findings</span></div>',
            f'<div class="da-stat"><span class="da-stat-value">{results.total_findings}</span>',
            '<span class="da-stat-label">Total Findings</span></div>',
            '</div>',
        ]

        # Category breakdown
        html_parts.append('<div class="da-categories">')
        for cat_key, cat_result in results.category_results.items():
            html_parts.append(f'''
                <div class="da-category-card">
                    <h4>{cat_result.category_name}</h4>
                    <div class="da-category-stats">
                        <span>{cat_result.accounts_with_findings} accounts</span>
                        <span>{cat_result.total_findings} findings</span>
                    </div>
                </div>
            ''')
        html_parts.append('</div>')

        # Findings table
        if results.all_findings:
            html_parts.append('<div class="da-findings-table">')
            html_parts.append('<table class="data-table"><thead><tr>')
            html_parts.append('<th>Account</th><th>Category</th><th>Value</th><th>Confidence</th><th>Reasoning</th>')
            html_parts.append('</tr></thead><tbody>')

            for account in results.all_findings:
                if account.has_findings:
                    for finding in account.findings:
                        conf_class = "high" if finding.confidence >= 0.9 else "medium" if finding.confidence >= 0.7 else "low"
                        html_parts.append(f'''
                            <tr>
                                <td class="account-cell">{account.sam_account_name}</td>
                                <td><span class="category-badge">{finding.category}</span></td>
                                <td class="value-cell">{finding.value}</td>
                                <td><span class="confidence-{conf_class}">{finding.confidence:.0%}</span></td>
                                <td class="reasoning-cell">{finding.reasoning}</td>
                            </tr>
                        ''')

            html_parts.append('</tbody></table>')
            html_parts.append('</div>')
        else:
            html_parts.append('<div class="da-no-findings">')
            html_parts.append('<p>No sensitive information detected in account descriptions.</p>')
            html_parts.append('</div>')

        html_parts.append('</div>')

        return '\n'.join(html_parts)
