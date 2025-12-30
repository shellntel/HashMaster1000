"""
Have I Been Pwned (HIBP) integration for checking NTLM hashes against the Pwned Passwords database.

Supports two modes:
1. API Mode: Uses the k-Anonymity model where only the first 5 characters of each hash
   are sent to the HIBP API, preserving privacy while enabling breach detection.
2. Local Mode: Uses a local copy of the HIBP NTLM database for air-gapped environments
   or faster lookups. Download from: https://haveibeenpwned.com/Passwords

API Documentation: https://haveibeenpwned.com/API/v3#PwnedPasswordsNTLM
"""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# HIBP API Configuration
HIBP_API_URL = "https://api.pwnedpasswords.com/range"
HIBP_PREFIX_LENGTH = 5
HIBP_NTLM_SUFFIX_LENGTH = 27  # NTLM suffixes are 27 chars (32 - 5)

# Parallelism settings - HIBP has no rate limit, so we can be aggressive
# See: https://haveibeenpwned.com/API/v3#PwnedPasswords
DEFAULT_DELAY_BETWEEN_REQUESTS = 0.0  # No delay needed - HIBP has no rate limit
# Default parallel workers - can be overridden via HIBP_API_WORKERS environment variable
# Higher values = faster but more network/CPU load. HIBP has no rate limit.
DEFAULT_MAX_WORKERS = 200
MAX_WORKERS = int(os.environ.get("HIBP_API_WORKERS", DEFAULT_MAX_WORKERS))

# Log the configured worker count at module load
if MAX_WORKERS != DEFAULT_MAX_WORKERS:
    logger.info(f"HIBP API workers configured via env: {MAX_WORKERS}")

# Local database state (binary search mode - no memory loading required)
_local_db_path: Optional[str] = None
_local_db_file_size: int = 0
_local_db_estimated_entries: int = 0
_local_db_ready: bool = False


@dataclass
class HIBPResult:
    """Result of checking a single hash against HIBP."""
    ntlm_hash: str
    username: str
    found_in_breach: bool
    breach_count: int = 0
    error: Optional[str] = None


@dataclass
class HIBPCheckResults:
    """Aggregate results from checking multiple hashes."""
    total_checked: int = 0
    total_found: int = 0
    total_errors: int = 0
    results: list[HIBPResult] = field(default_factory=list)
    check_duration_seconds: float = 0.0

    @property
    def found_percentage(self) -> float:
        if self.total_checked == 0:
            return 0.0
        return (self.total_found / self.total_checked) * 100

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        # Convert results to dicts
        results_dicts = [
            {
                "username": r.username,
                "ntlm_hash": r.ntlm_hash,
                "found_in_breach": r.found_in_breach,
                "breach_count": r.breach_count,
                "error": r.error
            }
            for r in self.results
        ]

        # Top breached passwords (sorted by breach count)
        top_breached = sorted(
            [r for r in results_dicts if r["found_in_breach"]],
            key=lambda x: x["breach_count"],
            reverse=True
        )[:20]  # Top 20

        return {
            "total_checked": self.total_checked,
            "total_found": self.total_found,
            "total_errors": self.total_errors,
            "found_percentage": round(self.found_percentage, 1),
            "check_duration_seconds": round(self.check_duration_seconds, 2),
            "results": results_dicts,
            "top_breached": top_breached
        }


# ============================================================================
# Local HIBP Database Support (Binary Search - No Memory Loading Required)
# ============================================================================

def init_local_hibp_database(db_path: str) -> Tuple[bool, str, int]:
    """
    Initialize the local HIBP database for binary search lookups.

    This does NOT load the database into memory. Instead, it validates the file
    and prepares it for binary search lookups. The file must be sorted by hash.

    Args:
        db_path: Path to the pwnedpasswords_ntlm.txt file (sorted by hash)

    Returns:
        Tuple of (success, message, estimated_entries)
    """
    global _local_db_path, _local_db_file_size, _local_db_estimated_entries, _local_db_ready

    # Validate file exists
    if not os.path.exists(db_path):
        _local_db_ready = False
        return False, f"Database file not found: {db_path}", 0

    if not os.path.isfile(db_path):
        _local_db_ready = False
        return False, f"Path is not a file: {db_path}", 0

    # Get file size
    file_size = os.path.getsize(db_path)
    file_size_gb = file_size / (1024 ** 3)

    if file_size < 1000:
        _local_db_ready = False
        return False, "File is too small to be a valid HIBP database", 0

    # Validate format by checking first few lines
    try:
        valid_lines = 0
        prev_hash = ""

        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 100:  # Check first 100 lines
                    break

                line = line.strip()
                if not line or ':' not in line:
                    continue

                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue

                ntlm_hash = parts[0].upper().strip()

                if len(ntlm_hash) != 32:
                    continue

                try:
                    int(ntlm_hash, 16)  # Check it's valid hex
                    int(parts[1].strip())  # Check count is numeric
                    valid_lines += 1

                    # Verify sorting (each hash should be >= previous)
                    if prev_hash and ntlm_hash < prev_hash:
                        _local_db_ready = False
                        return False, "Database file is not sorted by hash (required for binary search)", 0
                    prev_hash = ntlm_hash

                except ValueError:
                    continue

        if valid_lines < 10:
            _local_db_ready = False
            return False, "File does not appear to be in HIBP format (HASH:COUNT)", 0

        # Estimate entries based on file size
        avg_line_size = 40  # Approx: 32-char hash + colon + count + newline
        estimated_entries = file_size // avg_line_size

        # Store database info
        _local_db_path = db_path
        _local_db_file_size = file_size
        _local_db_estimated_entries = estimated_entries
        _local_db_ready = True

        message = f"HIBP database ready: ~{estimated_entries:,} entries ({file_size_gb:.1f} GB) - using binary search"
        logger.info(message)

        return True, message, estimated_entries

    except Exception as e:
        _local_db_ready = False
        logger.error(f"Failed to initialize HIBP database: {e}")
        return False, f"Failed to initialize database: {str(e)}", 0


# Backwards compatibility alias
def load_local_hibp_database(db_path: str, force_reload: bool = False) -> Tuple[bool, str, int]:
    """Alias for init_local_hibp_database (backwards compatibility)."""
    return init_local_hibp_database(db_path)


def get_local_db_status() -> Dict:
    """
    Get the current status of the local HIBP database.

    Returns:
        Dict with status information
    """
    file_date = None
    if _local_db_path and os.path.exists(_local_db_path):
        try:
            from datetime import datetime
            stat_info = os.stat(_local_db_path)
            # Use birth time (creation time) if available (macOS/Windows)
            # Fall back to modification time on Linux (more meaningful than ctime)
            if hasattr(stat_info, 'st_birthtime'):
                timestamp = stat_info.st_birthtime
            else:
                timestamp = stat_info.st_mtime
            file_date = datetime.fromtimestamp(timestamp).strftime("%B %d, %Y")
        except Exception:
            pass

    return {
        "loaded": _local_db_ready,
        "path": _local_db_path,
        "hash_count": _local_db_estimated_entries,
        "file_size_gb": round(_local_db_file_size / (1024 ** 3), 2) if _local_db_file_size else 0,
        "mode": "binary_search",
        "file_date": file_date
    }


def _binary_search_hash(db_path: str, target_hash: str, file_size: int) -> Tuple[bool, int]:
    """
    Perform binary search on the sorted HIBP database file.

    Args:
        db_path: Path to the sorted database file
        target_hash: The NTLM hash to search for (uppercase)
        file_size: Size of the file in bytes

    Returns:
        Tuple of (found, breach_count)
    """
    target_hash = target_hash.upper()

    with open(db_path, 'rb') as f:
        low = 0
        high = file_size

        while low < high:
            mid = (low + high) // 2

            # Seek to mid position
            f.seek(mid)

            # Skip to start of next line (we might be in the middle of a line)
            if mid > 0:
                f.readline()  # Skip partial line

            # Read the current line
            line = f.readline()
            if not line:
                high = mid
                continue

            # Decode and parse the line
            try:
                line_str = line.decode('utf-8', errors='ignore').strip()
                if not line_str or ':' not in line_str:
                    # Empty or malformed line, adjust search
                    high = mid
                    continue

                parts = line_str.split(':', 1)
                if len(parts) != 2:
                    high = mid
                    continue

                current_hash = parts[0].upper()

                if current_hash == target_hash:
                    # Found it!
                    try:
                        count = int(parts[1])
                        return True, count
                    except ValueError:
                        return True, 1  # Found but count parse error

                elif current_hash < target_hash:
                    # Target is after current position
                    low = f.tell()
                else:
                    # Target is before current position
                    high = mid

            except Exception:
                # Error parsing, adjust search
                high = mid

        # Final check: read a few lines around the final position
        f.seek(max(0, low - 100))
        if low > 0:
            f.readline()  # Skip partial line

        for _ in range(10):  # Check up to 10 lines
            line = f.readline()
            if not line:
                break

            try:
                line_str = line.decode('utf-8', errors='ignore').strip()
                if not line_str or ':' not in line_str:
                    continue

                parts = line_str.split(':', 1)
                if len(parts) != 2:
                    continue

                current_hash = parts[0].upper()
                if current_hash == target_hash:
                    try:
                        count = int(parts[1])
                        return True, count
                    except ValueError:
                        return True, 1

                # If we've passed the target hash, stop
                if current_hash > target_hash:
                    break

            except Exception:
                continue

    return False, 0


def check_hash_local(ntlm_hash: str) -> Tuple[bool, int]:
    """
    Check a single hash against the local database using binary search.

    Args:
        ntlm_hash: The NTLM hash to check (case-insensitive)

    Returns:
        Tuple of (found_in_breach, breach_count)
    """
    if not _local_db_ready or not _local_db_path:
        return False, 0

    ntlm_hash = ntlm_hash.upper().strip()
    return _binary_search_hash(_local_db_path, ntlm_hash, _local_db_file_size)


def check_hashes_local(
    account_data: list[dict],
    progress_callback: Optional[callable] = None
) -> HIBPCheckResults:
    """
    Check multiple NTLM hashes against the local HIBP database using binary search.

    Each lookup requires a few disk seeks (O(log n)), making this efficient even
    for very large databases without loading them into memory.

    Args:
        account_data: List of account dicts with 'ntlm_hash' and 'username' keys
        progress_callback: Optional callback(checked, total) for progress updates

    Returns:
        HIBPCheckResults with all results and statistics
    """
    results = HIBPCheckResults()
    start_time = time.time()

    if not _local_db_ready:
        logger.error("Local HIBP database not initialized")
        results.total_errors = len(account_data)
        return results

    # Blank password hash - handle specially
    BLANK_HASH = "31D6CFE0D16AE931B73C59D7E0C089C0"

    total = len(account_data)
    checked = 0
    # Update progress every 500 items or at 1%, whichever is smaller
    progress_interval = min(500, max(1, total // 100))

    # Cache results for duplicate hashes to avoid redundant disk seeks
    hash_cache: Dict[str, Tuple[bool, int]] = {}

    for account in account_data:
        ntlm_hash = account.get("ntlm_hash", "").upper().strip()
        username = account.get("username", "")

        if not ntlm_hash or len(ntlm_hash) != 32:
            results.results.append(HIBPResult(
                ntlm_hash=ntlm_hash,
                username=username,
                found_in_breach=False,
                error="Invalid hash format"
            ))
            results.total_errors += 1
            results.total_checked += 1
            continue

        # Handle blank password hash
        if ntlm_hash == BLANK_HASH:
            results.results.append(HIBPResult(
                ntlm_hash=ntlm_hash,
                username=username,
                found_in_breach=True,
                breach_count=999999999
            ))
            results.total_found += 1
            results.total_checked += 1
            checked += 1
            continue

        # Check cache first
        if ntlm_hash in hash_cache:
            found, count = hash_cache[ntlm_hash]
        else:
            # Binary search lookup
            found, count = check_hash_local(ntlm_hash)
            hash_cache[ntlm_hash] = (found, count)

        results.results.append(HIBPResult(
            ntlm_hash=ntlm_hash,
            username=username,
            found_in_breach=found,
            breach_count=count
        ))

        if found:
            results.total_found += 1
        results.total_checked += 1

        checked += 1
        if progress_callback and (checked % progress_interval == 0 or checked == 1):
            progress_callback(checked, total)

    results.check_duration_seconds = time.time() - start_time

    logger.info(
        f"Local HIBP check complete: {results.total_found}/{results.total_checked} "
        f"found in breaches ({results.found_percentage:.1f}%) "
        f"in {results.check_duration_seconds:.2f}s (binary search, {len(hash_cache)} unique lookups)"
    )

    return results


def validate_local_db_path(db_path: str) -> Tuple[bool, str, Dict]:
    """
    Validate a local HIBP database file without loading it.

    Args:
        db_path: Path to the database file

    Returns:
        Tuple of (is_valid, message, info_dict)
    """
    if not db_path:
        return False, "No path provided", {}

    if not os.path.exists(db_path):
        return False, f"File not found: {db_path}", {}

    if not os.path.isfile(db_path):
        return False, f"Path is not a file: {db_path}", {}

    # Check file size
    file_size = os.path.getsize(db_path)
    if file_size < 1000:
        return False, "File is too small to be a valid HIBP database", {}

    # Read first few lines to validate format and sorting
    try:
        valid_lines = 0
        sample_hashes = []
        prev_hash = ""
        is_sorted = True

        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 100:  # Check first 100 lines
                    break

                line = line.strip()
                if not line or ':' not in line:
                    continue

                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue

                ntlm_hash = parts[0].upper().strip()
                count_str = parts[1].strip()

                if len(ntlm_hash) != 32:
                    continue

                try:
                    int(ntlm_hash, 16)  # Check it's valid hex
                    int(count_str)  # Check count is numeric
                    valid_lines += 1

                    if len(sample_hashes) < 3:
                        sample_hashes.append(ntlm_hash[:8] + "...")

                    # Check sorting
                    if prev_hash and ntlm_hash < prev_hash:
                        is_sorted = False
                    prev_hash = ntlm_hash

                except ValueError:
                    continue

        if valid_lines < 10:
            return False, "File does not appear to be in HIBP format (HASH:COUNT)", {}

        # Estimate total entries based on file size and average line length
        avg_line_size = 40  # Approx: 32-char hash + colon + count + newline
        estimated_entries = file_size // avg_line_size

        info = {
            "file_size_bytes": file_size,
            "file_size_gb": round(file_size / (1024 ** 3), 2),
            "estimated_entries": estimated_entries,
            "sample_hashes": sample_hashes,
            "format_valid": True,
            "is_sorted": is_sorted,
            "mode": "binary_search"
        }

        if not is_sorted:
            return False, "Database file is not sorted (required for binary search)", info

        return True, f"Valid HIBP database (~{estimated_entries:,} entries, binary search ready)", info

    except Exception as e:
        return False, f"Error reading file: {str(e)}", {}


# ============================================================================
# API-based HIBP Functions
# ============================================================================

def check_single_hash_hibp(ntlm_hash: str, username: str = "") -> HIBPResult:
    """
    Check a single NTLM hash against the HIBP Pwned Passwords API.

    Uses k-Anonymity: only sends first 5 characters of the hash.

    Args:
        ntlm_hash: The full 32-character NTLM hash (case-insensitive)
        username: Optional username for tracking purposes

    Returns:
        HIBPResult with breach status and count
    """
    # Normalize hash
    ntlm_hash = ntlm_hash.upper().strip()

    # Skip blank password hash - we already know it's common
    if ntlm_hash == "31D6CFE0D16AE931B73C59D7E0C089C0":
        return HIBPResult(
            ntlm_hash=ntlm_hash,
            username=username,
            found_in_breach=True,
            breach_count=999999999,  # Extremely common
            error=None
        )

    # Validate hash format
    if len(ntlm_hash) != 32:
        return HIBPResult(
            ntlm_hash=ntlm_hash,
            username=username,
            found_in_breach=False,
            error=f"Invalid hash length: {len(ntlm_hash)} (expected 32)"
        )

    prefix = ntlm_hash[:HIBP_PREFIX_LENGTH]
    suffix = ntlm_hash[HIBP_PREFIX_LENGTH:]

    try:
        # Make request to HIBP API with NTLM mode
        response = requests.get(
            f"{HIBP_API_URL}/{prefix}",
            params={"mode": "ntlm"},
            headers={
                "User-Agent": "HashMaster1000-PasswordAudit",
                "Add-Padding": "true"  # Enhanced privacy
            },
            timeout=10
        )

        if response.status_code != 200:
            return HIBPResult(
                ntlm_hash=ntlm_hash,
                username=username,
                found_in_breach=False,
                error=f"API returned status {response.status_code}"
            )

        # Parse response - format is "SUFFIX:COUNT\r\n"
        for line in response.text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue

            parts = line.split(":")
            if len(parts) != 2:
                continue

            response_suffix, count_str = parts

            # Compare suffixes (case-insensitive)
            if response_suffix.upper() == suffix:
                try:
                    breach_count = int(count_str)
                    return HIBPResult(
                        ntlm_hash=ntlm_hash,
                        username=username,
                        found_in_breach=True,
                        breach_count=breach_count
                    )
                except ValueError:
                    pass

        # Not found in breach database
        return HIBPResult(
            ntlm_hash=ntlm_hash,
            username=username,
            found_in_breach=False,
            breach_count=0
        )

    except requests.RequestException as e:
        logger.error(f"HIBP API request failed for hash prefix {prefix}: {e}")
        return HIBPResult(
            ntlm_hash=ntlm_hash,
            username=username,
            found_in_breach=False,
            error=str(e)
        )


def check_hashes_hibp(
    account_data: list[dict],
    delay_between_requests: float = DEFAULT_DELAY_BETWEEN_REQUESTS,
    max_workers: int = MAX_WORKERS,
    progress_callback: Optional[callable] = None
) -> HIBPCheckResults:
    """
    Check multiple NTLM hashes against HIBP using parallel requests.

    Args:
        account_data: List of account dicts with 'ntlm_hash' and 'username' keys
        delay_between_requests: Seconds to wait between API calls (per thread)
        max_workers: Number of parallel threads
        progress_callback: Optional callback(checked, total) for progress updates

    Returns:
        HIBPCheckResults with all results and statistics
    """
    results = HIBPCheckResults()
    start_time = time.time()

    # Deduplicate hashes to minimize API calls
    hash_to_usernames: dict[str, list[str]] = {}
    for account in account_data:
        ntlm_hash = account.get("ntlm_hash", "").upper().strip()
        username = account.get("username", "")

        if not ntlm_hash or len(ntlm_hash) != 32:
            continue

        if ntlm_hash not in hash_to_usernames:
            hash_to_usernames[ntlm_hash] = []
        hash_to_usernames[ntlm_hash].append(username)

    unique_hashes = list(hash_to_usernames.keys())
    total_unique = len(unique_hashes)

    logger.info(f"Checking {total_unique} unique hashes against HIBP ({len(account_data)} total accounts)")

    # Further optimize by grouping hashes by prefix
    # This way we only make one API call per unique prefix
    prefix_to_hashes: dict[str, list[str]] = {}
    for ntlm_hash in unique_hashes:
        prefix = ntlm_hash[:HIBP_PREFIX_LENGTH]
        if prefix not in prefix_to_hashes:
            prefix_to_hashes[prefix] = []
        prefix_to_hashes[prefix].append(ntlm_hash)

    total_prefixes = len(prefix_to_hashes)
    logger.info(f"Optimized to {total_prefixes} unique prefixes (API calls)")

    # Use a list to make counter mutable in nested scope
    progress_counter = [0]  # [checked_prefixes]
    hash_results: dict[str, HIBPResult] = {}

    # Create a session with connection pooling for better performance
    # This reuses TCP connections across requests instead of creating new ones
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=max_workers,
        pool_maxsize=max_workers,
        max_retries=1
    )
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "HashMaster1000-PasswordAudit",
        "Add-Padding": "true"
    })

    def check_prefix(prefix: str, hashes: list[str]) -> list[HIBPResult]:
        """Check all hashes with a given prefix in one API call."""
        results = []

        try:
            response = session.get(
                f"{HIBP_API_URL}/{prefix}",
                params={"mode": "ntlm"},
                timeout=5  # HIBP typically responds in <1s
            )

            if response.status_code != 200:
                for ntlm_hash in hashes:
                    usernames = hash_to_usernames.get(ntlm_hash, [""])
                    results.append(HIBPResult(
                        ntlm_hash=ntlm_hash,
                        username=usernames[0] if usernames else "",
                        found_in_breach=False,
                        error=f"API returned status {response.status_code}"
                    ))
                return results

            # Parse all suffixes from response
            breach_data: dict[str, int] = {}
            for line in response.text.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                parts = line.split(":")
                if len(parts) == 2:
                    try:
                        breach_data[parts[0].upper()] = int(parts[1])
                    except ValueError:
                        pass

            # Check each hash against the response
            for ntlm_hash in hashes:
                suffix = ntlm_hash[HIBP_PREFIX_LENGTH:]
                usernames = hash_to_usernames.get(ntlm_hash, [""])

                if suffix in breach_data:
                    results.append(HIBPResult(
                        ntlm_hash=ntlm_hash,
                        username=usernames[0] if usernames else "",
                        found_in_breach=True,
                        breach_count=breach_data[suffix]
                    ))
                else:
                    results.append(HIBPResult(
                        ntlm_hash=ntlm_hash,
                        username=usernames[0] if usernames else "",
                        found_in_breach=False,
                        breach_count=0
                    ))

        except requests.RequestException as e:
            logger.error(f"HIBP API request failed for prefix {prefix}: {e}")
            for ntlm_hash in hashes:
                usernames = hash_to_usernames.get(ntlm_hash, [""])
                results.append(HIBPResult(
                    ntlm_hash=ntlm_hash,
                    username=usernames[0] if usernames else "",
                    found_in_breach=False,
                    error=str(e)
                ))

        # Only sleep if delay is configured (default is 0)
        if delay_between_requests > 0:
            time.sleep(delay_between_requests)
        return results

    # Process prefixes in parallel
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_prefix = {
                executor.submit(check_prefix, prefix, hashes): prefix
                for prefix, hashes in prefix_to_hashes.items()
            }

            for future in as_completed(future_to_prefix):
                prefix = future_to_prefix[future]
                try:
                    prefix_results = future.result()
                    for result in prefix_results:
                        hash_results[result.ntlm_hash] = result
                    progress_counter[0] += 1

                    # Log progress periodically
                    if progress_counter[0] % 1000 == 0 or progress_counter[0] == 1:
                        logger.info(f"HIBP progress: {progress_counter[0]}/{total_prefixes} prefixes checked")

                    if progress_callback:
                        try:
                            progress_callback(progress_counter[0], total_prefixes)
                        except Exception as cb_err:
                            logger.error(f"Progress callback error: {cb_err}")

                except Exception as e:
                    logger.error(f"Error processing prefix {prefix}: {e}")
    finally:
        # Close the session to release connection pool resources
        session.close()

    # Build final results, expanding back to all usernames
    for ntlm_hash, usernames in hash_to_usernames.items():
        base_result = hash_results.get(ntlm_hash)
        if not base_result:
            continue

        # Add a result for each username with this hash
        for username in usernames:
            results.results.append(HIBPResult(
                ntlm_hash=ntlm_hash,
                username=username,
                found_in_breach=base_result.found_in_breach,
                breach_count=base_result.breach_count,
                error=base_result.error
            ))

            results.total_checked += 1
            if base_result.found_in_breach:
                results.total_found += 1
            if base_result.error:
                results.total_errors += 1

    results.check_duration_seconds = time.time() - start_time

    logger.info(
        f"HIBP check complete: {results.total_found}/{results.total_checked} "
        f"found in breaches ({results.found_percentage:.1f}%) "
        f"in {results.check_duration_seconds:.1f}s"
    )

    return results


def test_hibp_connection() -> tuple[bool, str]:
    """
    Test connectivity to the HIBP API.

    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        # Use a known common hash prefix for testing
        test_prefix = "8846F"  # Prefix of "password" hash

        response = requests.get(
            f"{HIBP_API_URL}/{test_prefix}",
            params={"mode": "ntlm"},
            headers={"User-Agent": "HashMaster1000-PasswordAudit"},
            timeout=10
        )

        if response.status_code == 200:
            # Verify we got valid response data
            lines = response.text.strip().split("\n")
            if len(lines) > 0:
                return True, f"HIBP API connected successfully. Received {len(lines)} hash suffixes."
            else:
                return False, "HIBP API returned empty response."
        else:
            return False, f"HIBP API returned status code {response.status_code}"

    except requests.RequestException as e:
        return False, f"Failed to connect to HIBP API: {str(e)}"
