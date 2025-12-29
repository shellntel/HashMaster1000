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
"""

import logging
import os
import shutil
import time
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

logger = logging.getLogger(__name__)

# HIBP API Configuration
HIBP_API_URL = "https://api.pwnedpasswords.com/range"
TOTAL_PREFIXES = 1048576  # 16^5 = 00000 to FFFFF

# Default download settings
DEFAULT_PARALLELISM = 100  # Concurrent download threads (HIBP has no rate limit)
DEFAULT_OUTPUT_DIR = "data"
DEFAULT_OUTPUT_FILENAME = "pwnedpasswords-ntlm.txt"

# Global download state (for tracking active downloads)
_active_download: Optional["HIBPDownloadState"] = None
_download_lock = threading.Lock()


@dataclass
class HIBPDownloadState:
    """Tracks the state of an active or completed download."""
    status: str = "idle"  # idle, starting, downloading, merging, complete, error, cancelled
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Progress tracking
    total_prefixes: int = TOTAL_PREFIXES
    completed_prefixes: int = 0
    failed_prefixes: int = 0
    total_hashes: int = 0

    # Output info
    output_path: Optional[str] = None
    output_size_bytes: int = 0

    # Error tracking
    error_message: Optional[str] = None
    last_error: Optional[str] = None

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


def get_download_status() -> Dict:
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
    progress_callback: Optional[Callable[[HIBPDownloadState], None]] = None
) -> bool:
    """
    Start downloading the HIBP NTLM database.

    This runs in a background thread and updates the global download state.
    Use get_download_status() to monitor progress.

    Args:
        output_dir: Directory to save the database file
        output_filename: Name of the output file
        parallelism: Number of concurrent download threads (default 20)
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
        target=_run_download,
        args=(output_dir, output_filename, parallelism, progress_callback, download_state),
        daemon=True
    )
    thread.start()

    return True


def _fetch_and_save_prefix(prefix: str, temp_dir: str, retries: int = 3) -> tuple[str, int, Optional[str]]:
    """
    Fetch all hash suffixes for a given prefix and save directly to disk.

    Args:
        prefix: 5-character hex prefix (e.g., "00000")
        temp_dir: Directory to save the prefix file
        retries: Number of retry attempts

    Returns:
        Tuple of (prefix, hash_count, error_message or None)
    """
    for attempt in range(retries):
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
                # Write directly to disk - one file per prefix
                prefix_file = os.path.join(temp_dir, f"{prefix}.txt")
                hash_count = 0

                with open(prefix_file, "w", encoding="utf-8") as f:
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and ":" in line:
                            # Reconstruct full hash: PREFIX + SUFFIX
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                full_hash = prefix.upper() + parts[0].upper()
                                f.write(f"{full_hash}:{parts[1]}\n")
                                hash_count += 1

                return prefix, hash_count, None
            else:
                error = f"HTTP {response.status_code}"

        except requests.RequestException as e:
            error = str(e)

        # Wait before retry
        if attempt < retries - 1:
            time.sleep(1 * (attempt + 1))

    return prefix, 0, error


def _run_download(
    output_dir: str,
    output_filename: str,
    parallelism: int,
    progress_callback: Optional[Callable[[HIBPDownloadState], None]],
    download_state: HIBPDownloadState
):
    """
    Run the actual download process using disk-based storage.

    This downloads all 1,048,576 hash prefixes to individual files, then
    concatenates them in order (which produces a sorted file since prefixes
    are sequential hex values 00000-FFFFF).

    Memory usage is minimal - only one prefix's data is in memory at a time.
    """
    global _active_download

    # Create temp directory for prefix files
    temp_dir = os.path.join(output_dir, ".hibp_download_temp")

    try:
        # Ensure directories exist
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(temp_dir, exist_ok=True)

        output_path = os.path.join(output_dir, output_filename)

        with _download_lock:
            download_state.status = "downloading"
            download_state.output_path = output_path

        # Generate all prefixes (00000 to FFFFF)
        prefixes = [f"{i:05X}" for i in range(TOTAL_PREFIXES)]

        # Track progress
        completed = 0
        failed = 0
        total_hashes = 0

        logger.info(f"Starting HIBP download: {TOTAL_PREFIXES:,} prefixes with {parallelism} threads")
        logger.info(f"Temp directory: {temp_dir}")

        # Download in parallel, writing each prefix to its own file
        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            # Submit all tasks
            future_to_prefix = {
                executor.submit(_fetch_and_save_prefix, prefix, temp_dir): prefix
                for prefix in prefixes
            }

            # Process completed tasks
            for future in as_completed(future_to_prefix):
                # Check for cancellation
                with _download_lock:
                    if download_state.cancel_requested:
                        download_state.status = "cancelled"
                        download_state.completed_at = datetime.now()
                        logger.info("HIBP download cancelled by user")
                        # Clean up temp directory
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

                    # Update progress
                    with _download_lock:
                        download_state.completed_prefixes = completed
                        download_state.total_hashes = total_hashes

                    # Log progress periodically
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

        # Check for cancellation before merging
        with _download_lock:
            if download_state.cancel_requested:
                download_state.status = "cancelled"
                download_state.completed_at = datetime.now()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

        # Merge all prefix files into final output
        # Since prefixes are 00000-FFFFF in hex order, concatenating in order gives sorted output
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

                # Log merge progress periodically
                if (i + 1) % 10000 == 0:
                    pct = ((i + 1) / TOTAL_PREFIXES) * 100
                    logger.info(f"Merge progress: {i + 1:,}/{TOTAL_PREFIXES:,} ({pct:.1f}%)")

        # Rename temp file to final
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp_output, output_path)

        # Clean up temp directory
        logger.info("Cleaning up temporary files...")
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Get final file size
        file_size = os.path.getsize(output_path)

        # Update final state
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

        # Clean up temp files
        shutil.rmtree(temp_dir, ignore_errors=True)
        temp_output = os.path.join(output_dir, output_filename + ".downloading")
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except Exception:
                pass


def estimate_download() -> Dict:
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
        "attribution": {
            "name": "Have I Been Pwned - Pwned Passwords",
            "website": "https://haveibeenpwned.com/Passwords",
            "api_docs": "https://haveibeenpwned.com/API/v3#PwnedPasswords",
            "downloader_tool": "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader",
            "creator": "Troy Hunt"
        }
    }
