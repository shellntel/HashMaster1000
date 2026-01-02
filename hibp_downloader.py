"""
HIBP (Have I Been Pwned) Pwned Passwords Database Downloader

Downloads the complete NTLM hash database from the HIBP API for local/offline use.
This eliminates dependency on the k-anonymity API for breach checks.

Based on the approach used by the official PwnedPasswordsDownloader tool:
https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader

The HIBP API uses a k-anonymity model with 1,048,576 hash prefixes (00000-FFFFF).
Each prefix returns ~800 hash suffixes with their breach counts.
Total database size is approximately 70-80GB for NTLM hashes.

API Documentation: https://haveibeenpwned.com/API/v3#PwnedPasswords
Note: There is NO rate limit on the Pwned Passwords API.

SQLite Conversion:
The downloaded text file can be converted to SQLite for faster indexed lookups.
Use convert_text_to_sqlite() to convert an existing text file, or
convert_temp_files_to_sqlite() to convert directly from downloaded temp files.
"""

import asyncio
import logging
import os
import shutil
import sqlite3
import time
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from collections.abc import Callable

# Try to import aiohttp, fall back to requests if not available
try:
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    import requests
    ASYNC_AVAILABLE = False

logger = logging.getLogger(__name__)

# HIBP API Configuration
HIBP_API_URL = "https://api.pwnedpasswords.com/range"
TOTAL_PREFIXES = 1048576  # 16^5 = 00000 to FFFFF

# Default download settings
DEFAULT_PARALLELISM = 100  # Concurrent download connections (HIBP has no rate limit)
DEFAULT_OUTPUT_DIR = "data"
DEFAULT_OUTPUT_FILENAME = "pwnedpasswords-ntlm.txt"

# Global download state (for tracking active downloads)
_active_download: "HIBPDownloadState | None" = None
_download_lock = threading.Lock()


@dataclass
class HIBPDownloadState:
    """Tracks the state of an active or completed download."""
    status: str = "idle"  # idle, starting, downloading, merging, complete, error, cancelled
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Progress tracking
    total_prefixes: int = TOTAL_PREFIXES
    completed_prefixes: int = 0
    failed_prefixes: int = 0
    total_hashes: int = 0

    # Output info
    output_path: str | None = None
    output_size_bytes: int = 0

    # Error tracking
    error_message: str | None = None
    last_error: str | None = None

    # Control
    cancel_requested: bool = False

    @property
    def progress_percentage(self) -> float:
        if self.total_prefixes == 0:
            return 0.0
        return round((self.completed_prefixes / self.total_prefixes) * 100, 2)

    @property
    def elapsed_seconds(self) -> float:
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.now()
        return (end_time - self.started_at).total_seconds()

    @property
    def estimated_remaining_seconds(self) -> float:
        if self.completed_prefixes == 0 or self.elapsed_seconds == 0:
            return 0.0
        rate = self.completed_prefixes / self.elapsed_seconds
        remaining = self.total_prefixes - self.completed_prefixes
        return remaining / rate if rate > 0 else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_prefixes": self.total_prefixes,
            "completed_prefixes": self.completed_prefixes,
            "failed_prefixes": self.failed_prefixes,
            "progress_percentage": self.progress_percentage,
            "total_hashes": self.total_hashes,
            "output_path": self.output_path,
            "output_size_bytes": self.output_size_bytes,
            "output_size_gb": round(self.output_size_bytes / (1024**3), 2) if self.output_size_bytes else 0,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "estimated_remaining_seconds": round(self.estimated_remaining_seconds, 1),
            "error_message": self.error_message,
            "last_error": self.last_error,
            "cancel_requested": self.cancel_requested
        }


def get_download_status() -> dict:
    """Get the current download status."""
    global _active_download

    with _download_lock:
        if _active_download is None:
            return {"status": "idle"}
        return _active_download.to_dict()


def cancel_download() -> bool:
    """Request cancellation of an active download."""
    global _active_download

    with _download_lock:
        if _active_download is None or _active_download.status not in ["starting", "downloading", "merging"]:
            return False
        _active_download.cancel_requested = True
        return True


def start_download(
    output_dir: str = DEFAULT_OUTPUT_DIR,
    output_filename: str = DEFAULT_OUTPUT_FILENAME,
    parallelism: int = DEFAULT_PARALLELISM,
    progress_callback: Callable[[HIBPDownloadState], None] | None = None
) -> bool:
    """
    Start downloading the HIBP NTLM database.

    This runs in a background thread and updates the global download state.
    Use get_download_status() to monitor progress.

    Args:
        output_dir: Directory to save the database file
        output_filename: Name of the output file
        parallelism: Number of concurrent connections (default 100)
        progress_callback: Optional callback called on progress updates

    Returns:
        True if download started, False if a download is already in progress
    """
    global _active_download

    with _download_lock:
        if _active_download is not None and _active_download.status in ["starting", "downloading", "merging"]:
            return False

        _active_download = HIBPDownloadState(
            status="starting",
            started_at=datetime.now(),
            output_path=os.path.join(output_dir, output_filename)
        )
        # Keep reference to pass to thread
        download_state = _active_download

    # Start download in background thread, passing the state object directly
    thread = threading.Thread(
        target=_run_download_wrapper,
        args=(output_dir, output_filename, parallelism, progress_callback, download_state),
        daemon=True
    )
    thread.start()

    return True


def _run_download_wrapper(
    output_dir: str,
    output_filename: str,
    parallelism: int,
    progress_callback: Callable[[HIBPDownloadState], None] | None,
    download_state: HIBPDownloadState
):
    """Wrapper to run async download in a new event loop."""
    if ASYNC_AVAILABLE:
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                _run_download_async(output_dir, output_filename, parallelism, progress_callback, download_state)
            )
        finally:
            loop.close()
    else:
        # Fallback to synchronous version
        _run_download_sync(output_dir, output_filename, parallelism, progress_callback, download_state)


async def _fetch_prefix_async(
    session: "aiohttp.ClientSession",
    prefix: str,
    temp_dir: str,
    semaphore: asyncio.Semaphore,
    retries: int = 3
) -> tuple[str, int, str | None]:
    """
    Async fetch of hash suffixes for a prefix.
    """
    async with semaphore:
        for attempt in range(retries):
            try:
                async with session.get(
                    f"{HIBP_API_URL}/{prefix}",
                    params={"mode": "ntlm"},
                    headers={
                        "User-Agent": "HashMaster1000-HIBPDownloader",
                        "Add-Padding": "true"
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        text = await response.text()

                        # Write directly to disk
                        prefix_file = os.path.join(temp_dir, f"{prefix}.txt")
                        hash_count = 0

                        with open(prefix_file, "w", encoding="utf-8") as f:
                            for line in text.splitlines():
                                line = line.strip()
                                if line and ":" in line:
                                    parts = line.split(":", 1)
                                    if len(parts) == 2:
                                        full_hash = prefix.upper() + parts[0].upper()
                                        f.write(f"{full_hash}:{parts[1]}\n")
                                        hash_count += 1

                        return prefix, hash_count, None
                    else:
                        error = f"HTTP {response.status}"

            except asyncio.TimeoutError:
                error = "Timeout"
            except Exception as e:
                error = str(e)

            # Wait before retry
            if attempt < retries - 1:
                await asyncio.sleep(1 * (attempt + 1))

        return prefix, 0, error


async def _run_download_async(
    output_dir: str,
    output_filename: str,
    parallelism: int,
    progress_callback: Callable[[HIBPDownloadState], None] | None,
    download_state: HIBPDownloadState
):
    """
    Run the download using async I/O for maximum throughput.
    """
    global _active_download

    temp_dir = os.path.join(output_dir, ".hibp_download_temp")

    try:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(temp_dir, exist_ok=True)

        output_path = os.path.join(output_dir, output_filename)

        with _download_lock:
            download_state.status = "downloading"
            download_state.output_path = output_path

        # Generate all prefixes
        prefixes = [f"{i:05X}" for i in range(TOTAL_PREFIXES)]

        logger.info(f"Starting HIBP download: {TOTAL_PREFIXES:,} prefixes with {parallelism} concurrent connections (async)")
        logger.info(f"Temp directory: {temp_dir}")

        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(parallelism)

        # Create connector with high connection limit
        connector = aiohttp.TCPConnector(
            limit=parallelism,
            limit_per_host=parallelism,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )

        completed = 0
        failed = 0
        total_hashes = 0

        async with aiohttp.ClientSession(connector=connector) as session:
            # Process in batches to avoid overwhelming memory with tasks
            batch_size = parallelism * 10  # Process 10x parallelism at a time

            for batch_start in range(0, TOTAL_PREFIXES, batch_size):
                # Check for cancellation
                with _download_lock:
                    if download_state.cancel_requested:
                        download_state.status = "cancelled"
                        download_state.completed_at = datetime.now()
                        logger.info("HIBP download cancelled by user")
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        return

                batch_end = min(batch_start + batch_size, TOTAL_PREFIXES)
                batch_prefixes = prefixes[batch_start:batch_end]

                # Create tasks for this batch
                tasks = [
                    _fetch_prefix_async(session, prefix, temp_dir, semaphore)
                    for prefix in batch_prefixes
                ]

                # Wait for batch to complete
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        failed += 1
                        with _download_lock:
                            download_state.failed_prefixes = failed
                            download_state.last_error = str(result)
                    else:
                        prefix, hash_count, error = result
                        if error:
                            failed += 1
                            with _download_lock:
                                download_state.failed_prefixes = failed
                                download_state.last_error = f"Prefix {prefix}: {error}"
                        else:
                            total_hashes += hash_count

                    completed += 1

                # Update progress after each batch
                with _download_lock:
                    download_state.completed_prefixes = completed
                    download_state.total_hashes = total_hashes

                # Log progress
                pct = (completed / TOTAL_PREFIXES) * 100
                if completed == batch_size or completed % 10000 < batch_size:
                    logger.info(f"HIBP download progress: {completed:,}/{TOTAL_PREFIXES:,} ({pct:.1f}%) - {total_hashes:,} hashes")

                if progress_callback:
                    progress_callback(download_state)

        # Check for cancellation before merging
        with _download_lock:
            if download_state.cancel_requested:
                download_state.status = "cancelled"
                download_state.completed_at = datetime.now()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

        # Merge files
        await _merge_files_async(output_dir, output_filename, temp_dir, download_state, progress_callback)

    except Exception as e:
        logger.error(f"HIBP download failed: {e}")
        with _download_lock:
            download_state.status = "error"
            download_state.error_message = str(e)
            download_state.completed_at = datetime.now()

        shutil.rmtree(temp_dir, ignore_errors=True)
        temp_output = os.path.join(output_dir, output_filename + ".downloading")
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except Exception:
                pass


async def _merge_files_async(
    output_dir: str,
    output_filename: str,
    temp_dir: str,
    download_state: HIBPDownloadState,
    progress_callback: Callable[[HIBPDownloadState], None] | None
):
    """Merge all prefix files into final output."""
    with _download_lock:
        download_state.status = "merging"

    output_path = os.path.join(output_dir, output_filename)
    temp_output = output_path + ".downloading"

    logger.info(f"Merging {TOTAL_PREFIXES:,} prefix files into {output_path}...")

    merged_hashes = 0

    with open(temp_output, "w", encoding="utf-8") as outfile:
        for i in range(TOTAL_PREFIXES):
            prefix = f"{i:05X}"
            prefix_file = os.path.join(temp_dir, f"{prefix}.txt")

            if os.path.exists(prefix_file):
                with open(prefix_file, "r", encoding="utf-8") as infile:
                    for line in infile:
                        outfile.write(line)
                        merged_hashes += 1

            if (i + 1) % 10000 == 0:
                pct = ((i + 1) / TOTAL_PREFIXES) * 100
                logger.info(f"Merge progress: {i + 1:,}/{TOTAL_PREFIXES:,} ({pct:.1f}%)")

    if os.path.exists(output_path):
        os.remove(output_path)
    os.rename(temp_output, output_path)

    logger.info("Cleaning up temporary files...")
    shutil.rmtree(temp_dir, ignore_errors=True)

    file_size = os.path.getsize(output_path)

    with _download_lock:
        download_state.status = "complete"
        download_state.completed_at = datetime.now()
        download_state.output_size_bytes = file_size
        download_state.total_hashes = merged_hashes

    logger.info(
        f"HIBP download complete: {merged_hashes:,} hashes, "
        f"{file_size / (1024**3):.2f} GB, "
        f"{download_state.elapsed_seconds:.1f}s"
    )

    if progress_callback:
        progress_callback(download_state)


def _run_download_sync(
    output_dir: str,
    output_filename: str,
    parallelism: int,
    progress_callback: Callable[[HIBPDownloadState], None] | None,
    download_state: HIBPDownloadState
):
    """
    Fallback synchronous download using requests + ThreadPoolExecutor.
    Used when aiohttp is not available.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    global _active_download

    temp_dir = os.path.join(output_dir, ".hibp_download_temp")

    try:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(temp_dir, exist_ok=True)

        output_path = os.path.join(output_dir, output_filename)

        with _download_lock:
            download_state.status = "downloading"
            download_state.output_path = output_path

        prefixes = [f"{i:05X}" for i in range(TOTAL_PREFIXES)]

        completed = 0
        failed = 0
        total_hashes = 0

        logger.info(f"Starting HIBP download: {TOTAL_PREFIXES:,} prefixes with {parallelism} threads (sync fallback)")
        logger.info(f"Temp directory: {temp_dir}")

        def fetch_prefix_sync(prefix: str) -> tuple[str, int, str | None]:
            for attempt in range(3):
                try:
                    response = requests.get(
                        f"{HIBP_API_URL}/{prefix}",
                        params={"mode": "ntlm"},
                        headers={
                            "User-Agent": "HashMaster1000-HIBPDownloader",
                            "Add-Padding": "true"
                        },
                        timeout=30
                    )

                    if response.status_code == 200:
                        prefix_file = os.path.join(temp_dir, f"{prefix}.txt")
                        hash_count = 0

                        with open(prefix_file, "w", encoding="utf-8") as f:
                            for line in response.text.splitlines():
                                line = line.strip()
                                if line and ":" in line:
                                    parts = line.split(":", 1)
                                    if len(parts) == 2:
                                        full_hash = prefix.upper() + parts[0].upper()
                                        f.write(f"{full_hash}:{parts[1]}\n")
                                        hash_count += 1

                        return prefix, hash_count, None
                    else:
                        error = f"HTTP {response.status_code}"

                except Exception as e:
                    error = str(e)

                if attempt < 2:
                    time.sleep(1 * (attempt + 1))

            return prefix, 0, error

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            future_to_prefix = {
                executor.submit(fetch_prefix_sync, prefix): prefix
                for prefix in prefixes
            }

            for future in as_completed(future_to_prefix):
                with _download_lock:
                    if download_state.cancel_requested:
                        download_state.status = "cancelled"
                        download_state.completed_at = datetime.now()
                        logger.info("HIBP download cancelled by user")
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        return

                prefix = future_to_prefix[future]
                try:
                    _, hash_count, error = future.result()

                    if error:
                        failed += 1
                        with _download_lock:
                            download_state.failed_prefixes = failed
                            download_state.last_error = f"Prefix {prefix}: {error}"
                    else:
                        total_hashes += hash_count

                    completed += 1

                    with _download_lock:
                        download_state.completed_prefixes = completed
                        download_state.total_hashes = total_hashes

                    if completed == 1 or completed % 1000 == 0:
                        pct = (completed / TOTAL_PREFIXES) * 100
                        logger.info(f"HIBP download progress: {completed:,}/{TOTAL_PREFIXES:,} ({pct:.1f}%) - {total_hashes:,} hashes")

                    if progress_callback:
                        progress_callback(download_state)

                except Exception as e:
                    failed += 1
                    with _download_lock:
                        download_state.failed_prefixes = failed
                        download_state.last_error = f"Prefix {prefix}: {str(e)}"

        with _download_lock:
            if download_state.cancel_requested:
                download_state.status = "cancelled"
                download_state.completed_at = datetime.now()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

        # Merge files
        with _download_lock:
            download_state.status = "merging"

        logger.info(f"Merging {TOTAL_PREFIXES:,} prefix files into {output_path}...")

        temp_output = output_path + ".downloading"
        merged_hashes = 0

        with open(temp_output, "w", encoding="utf-8") as outfile:
            for i in range(TOTAL_PREFIXES):
                prefix = f"{i:05X}"
                prefix_file = os.path.join(temp_dir, f"{prefix}.txt")

                if os.path.exists(prefix_file):
                    with open(prefix_file, "r", encoding="utf-8") as infile:
                        for line in infile:
                            outfile.write(line)
                            merged_hashes += 1

                if (i + 1) % 10000 == 0:
                    pct = ((i + 1) / TOTAL_PREFIXES) * 100
                    logger.info(f"Merge progress: {i + 1:,}/{TOTAL_PREFIXES:,} ({pct:.1f}%)")

        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp_output, output_path)

        logger.info("Cleaning up temporary files...")
        shutil.rmtree(temp_dir, ignore_errors=True)

        file_size = os.path.getsize(output_path)

        with _download_lock:
            download_state.status = "complete"
            download_state.completed_at = datetime.now()
            download_state.output_size_bytes = file_size
            download_state.total_hashes = merged_hashes

        logger.info(
            f"HIBP download complete: {merged_hashes:,} hashes, "
            f"{file_size / (1024**3):.2f} GB, "
            f"{download_state.elapsed_seconds:.1f}s"
        )

        if progress_callback:
            progress_callback(download_state)

    except Exception as e:
        logger.error(f"HIBP download failed: {e}")
        with _download_lock:
            download_state.status = "error"
            download_state.error_message = str(e)
            download_state.completed_at = datetime.now()

        shutil.rmtree(temp_dir, ignore_errors=True)
        temp_output = os.path.join(output_dir, output_filename + ".downloading")
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except Exception:
                pass


def estimate_download() -> dict:
    """
    Estimate download size and time.

    Returns:
        Dict with estimated file size, download time, and requirements
    """
    return {
        "total_prefixes": TOTAL_PREFIXES,
        "estimated_hashes": "~850 million",
        "estimated_size_gb": "~70-80",
        "estimated_time_minutes": "60-120 (depends on connection and parallelism)",
        "api_url": HIBP_API_URL,
        "rate_limit": "None (Pwned Passwords API has no rate limit)",
        "async_available": ASYNC_AVAILABLE,
        "attribution": {
            "name": "Have I Been Pwned - Pwned Passwords",
            "website": "https://haveibeenpwned.com/Passwords",
            "api_docs": "https://haveibeenpwned.com/API/v3#PwnedPasswords",
            "downloader_tool": "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader",
            "creator": "Troy Hunt"
        }
    }


# ============================================================================
# SQLite Conversion Functions
# ============================================================================

# Global state for SQLite conversion
_conversion_state: "SQLiteConversionState | None" = None
_conversion_lock = threading.Lock()


@dataclass
class SQLiteConversionState:
    """Tracks the state of a SQLite conversion operation."""
    status: str = "idle"  # idle, converting, complete, error, cancelled
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Progress tracking
    total_lines: int = 0
    processed_lines: int = 0
    inserted_rows: int = 0

    # Output info
    input_path: str | None = None
    output_path: str | None = None
    output_size_bytes: int = 0

    # Error tracking
    error_message: str | None = None

    # Control
    cancel_requested: bool = False

    @property
    def progress_percentage(self) -> float:
        if self.total_lines == 0:
            return 0.0
        return round((self.processed_lines / self.total_lines) * 100, 2)

    @property
    def elapsed_seconds(self) -> float:
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.now()
        return (end_time - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_lines": self.total_lines,
            "processed_lines": self.processed_lines,
            "inserted_rows": self.inserted_rows,
            "progress_percentage": self.progress_percentage,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "output_size_bytes": self.output_size_bytes,
            "output_size_gb": round(self.output_size_bytes / (1024**3), 2) if self.output_size_bytes else 0,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "error_message": self.error_message,
            "cancel_requested": self.cancel_requested
        }


def get_conversion_status() -> dict:
    """Get the current SQLite conversion status."""
    global _conversion_state

    with _conversion_lock:
        if _conversion_state is None:
            return {"status": "idle"}
        return _conversion_state.to_dict()


def cancel_conversion() -> bool:
    """Request cancellation of an active conversion."""
    global _conversion_state

    with _conversion_lock:
        if _conversion_state is None or _conversion_state.status != "converting":
            return False
        _conversion_state.cancel_requested = True
        return True


def convert_text_to_sqlite(
    text_file_path: str,
    db_output_path: str | None = None,
    batch_size: int = 100000,
    progress_callback: Callable[[SQLiteConversionState], None] | None = None,
    skip_vacuum: bool = True
) -> tuple[bool, str, str | None]:
    """
    Convert a HIBP text file to SQLite database.

    The text file should be in the format: HASH:COUNT (one per line)

    Args:
        text_file_path: Path to the HIBP text file
        db_output_path: Path for the output SQLite database (default: same location with .db extension)
        batch_size: Number of rows to insert per transaction (default 100K for performance)
        progress_callback: Optional callback for progress updates
        skip_vacuum: Skip VACUUM optimization (default True - VACUUM requires 2x database size in free space)

    Returns:
        Tuple of (success, message, db_path)
    """
    global _conversion_state

    # Validate input file
    if not os.path.exists(text_file_path):
        return False, f"Input file not found: {text_file_path}", None

    if not os.path.isfile(text_file_path):
        return False, f"Path is not a file: {text_file_path}", None

    # Determine output path
    if db_output_path is None:
        base_path = os.path.splitext(text_file_path)[0]
        db_output_path = base_path + ".db"

    # Check if conversion already running
    with _conversion_lock:
        if _conversion_state is not None and _conversion_state.status == "converting":
            return False, "A conversion is already in progress", None

        # Estimate total lines from file size
        # HIBP NTLM format is HASH:COUNT, averaging ~35 bytes per line
        # (32-char hash + colon + 1-6 digit count + newline)
        file_size = os.path.getsize(text_file_path)
        estimated_lines = file_size // 35

        _conversion_state = SQLiteConversionState(
            status="converting",
            started_at=datetime.now(),
            total_lines=estimated_lines,
            input_path=text_file_path,
            output_path=db_output_path
        )
        conversion_state = _conversion_state

    temp_db_path = db_output_path + ".converting"

    try:
        logger.info(f"Starting SQLite conversion: {text_file_path} -> {db_output_path}")
        logger.info(f"Estimated {estimated_lines:,} entries")

        # Remove temp file if exists
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)

        # Create SQLite database
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()

        # Create table with WITHOUT ROWID for better performance on hash lookups
        # The hash is the primary key, so lookups are O(log n)
        cursor.execute("""
            CREATE TABLE hashes (
                hash TEXT PRIMARY KEY,
                count INTEGER NOT NULL
            ) WITHOUT ROWID
        """)

        # Create metadata table to store count (avoids slow COUNT(*) at startup)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Process the text file
        batch = []
        processed = 0
        inserted = 0
        last_progress_update = time.time()

        with open(text_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Check for cancellation
                with _conversion_lock:
                    if conversion_state.cancel_requested:
                        conn.close()
                        if os.path.exists(temp_db_path):
                            os.remove(temp_db_path)
                        conversion_state.status = "cancelled"
                        conversion_state.completed_at = datetime.now()
                        logger.info("SQLite conversion cancelled by user")
                        return False, "Conversion cancelled", None

                line = line.strip()
                if not line or ':' not in line:
                    processed += 1
                    continue

                parts = line.split(':', 1)
                if len(parts) != 2:
                    processed += 1
                    continue

                ntlm_hash = parts[0].upper().strip()

                # Validate hash format
                if len(ntlm_hash) != 32:
                    processed += 1
                    continue

                try:
                    count = int(parts[1].strip())
                except ValueError:
                    processed += 1
                    continue

                batch.append((ntlm_hash, count))
                processed += 1

                # Insert batch when full
                if len(batch) >= batch_size:
                    cursor.executemany("INSERT OR REPLACE INTO hashes (hash, count) VALUES (?, ?)", batch)
                    conn.commit()
                    inserted += len(batch)
                    batch = []

                    # Update progress
                    with _conversion_lock:
                        conversion_state.processed_lines = processed
                        conversion_state.inserted_rows = inserted

                    # Progress callback (rate limited to every 2 seconds)
                    now = time.time()
                    if progress_callback and (now - last_progress_update) > 2:
                        progress_callback(conversion_state)
                        last_progress_update = now

                    # Log progress every 10M lines
                    if processed % 10_000_000 == 0:
                        pct = (processed / estimated_lines) * 100 if estimated_lines else 0
                        logger.info(f"SQLite conversion progress: {processed:,} lines ({pct:.1f}%)")

        # Insert remaining batch
        if batch:
            cursor.executemany("INSERT OR REPLACE INTO hashes (hash, count) VALUES (?, ?)", batch)
            conn.commit()
            inserted += len(batch)

        # Update final counts
        with _conversion_lock:
            conversion_state.processed_lines = processed
            conversion_state.inserted_rows = inserted

        # Use inserted count as the row count (avoids slow COUNT(*) on 2B rows)
        actual_count = inserted

        # Store count in metadata table for fast retrieval at startup
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hash_count", str(actual_count))
        )
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("created_at", datetime.now().isoformat())
        )
        conn.commit()

        # Run ANALYZE to populate sqlite_stat1 for fast count lookups
        # This also helps the query planner make better decisions
        logger.info("Running ANALYZE for query optimization...")
        cursor.execute("ANALYZE hashes")
        conn.commit()

        # Optionally optimize the database
        # VACUUM requires temporary space roughly equal to database size
        # For large databases (70GB+), this can fail if disk space is limited
        if not skip_vacuum:
            logger.info("Optimizing SQLite database (VACUUM)...")
            try:
                cursor.execute("VACUUM")
            except sqlite3.OperationalError as e:
                if "disk" in str(e).lower() or "full" in str(e).lower():
                    logger.warning(f"VACUUM skipped due to disk space: {e}")
                    logger.warning("Database is still usable, just not optimally compacted")
                else:
                    raise
        else:
            logger.info("Skipping VACUUM optimization (skip_vacuum=True)")

        conn.close()

        # Move temp file to final location
        if os.path.exists(db_output_path):
            os.remove(db_output_path)
        os.rename(temp_db_path, db_output_path)

        # Get final file size
        output_size = os.path.getsize(db_output_path)

        with _conversion_lock:
            conversion_state.status = "complete"
            conversion_state.completed_at = datetime.now()
            conversion_state.output_size_bytes = output_size
            conversion_state.inserted_rows = actual_count

        message = (
            f"SQLite conversion complete: {actual_count:,} hashes, "
            f"{output_size / (1024**3):.2f} GB, "
            f"{conversion_state.elapsed_seconds:.1f}s"
        )
        logger.info(message)

        if progress_callback:
            progress_callback(conversion_state)

        return True, message, db_output_path

    except Exception as e:
        logger.error(f"SQLite conversion failed: {e}")

        with _conversion_lock:
            conversion_state.status = "error"
            conversion_state.error_message = str(e)
            conversion_state.completed_at = datetime.now()

        # Clean up temp file
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass

        return False, f"Conversion failed: {str(e)}", None


def start_conversion_background(
    text_file_path: str,
    db_output_path: str | None = None,
    progress_callback: Callable[[SQLiteConversionState], None] | None = None,
    skip_vacuum: bool = True
) -> bool:
    """
    Start SQLite conversion in a background thread.

    Args:
        text_file_path: Path to the HIBP text file
        db_output_path: Path for the output SQLite database
        progress_callback: Optional callback for progress updates
        skip_vacuum: Skip VACUUM optimization (default True - saves disk space)

    Returns:
        True if conversion started, False if already running
    """
    global _conversion_state

    with _conversion_lock:
        if _conversion_state is not None and _conversion_state.status == "converting":
            return False

    thread = threading.Thread(
        target=convert_text_to_sqlite,
        args=(text_file_path, db_output_path, 100000, progress_callback, skip_vacuum),
        daemon=True
    )
    thread.start()

    return True


def get_sqlite_db_info(db_path: str) -> dict | None:
    """
    Get information about an existing HIBP SQLite database.

    Args:
        db_path: Path to the SQLite database

    Returns:
        Dict with database info, or None if not valid
    """
    if not os.path.exists(db_path):
        return None

    if not os.path.isfile(db_path):
        return None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verify it has the expected table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hashes'")
        if not cursor.fetchone():
            conn.close()
            return None

        # Get row count
        cursor.execute("SELECT COUNT(*) FROM hashes")
        count = cursor.fetchone()[0]

        # Get sample hash to verify format
        cursor.execute("SELECT hash, count FROM hashes LIMIT 1")
        sample = cursor.fetchone()

        conn.close()

        file_size = os.path.getsize(db_path)

        # Get file modification time
        stat_info = os.stat(db_path)
        if hasattr(stat_info, 'st_birthtime'):
            timestamp = stat_info.st_birthtime
        else:
            timestamp = stat_info.st_mtime
        file_date = datetime.fromtimestamp(timestamp).strftime("%B %d, %Y")

        return {
            "path": db_path,
            "hash_count": count,
            "file_size_bytes": file_size,
            "file_size_gb": round(file_size / (1024**3), 2),
            "sample_hash": sample[0][:8] + "..." if sample else None,
            "sample_count": sample[1] if sample else None,
            "file_date": file_date,
            "valid": True
        }

    except Exception as e:
        logger.error(f"Error reading SQLite database: {e}")
        return None
