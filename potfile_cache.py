"""
potfile_cache.py - High-performance caching for master potfile operations

Provides in-memory caching of the master potfile to avoid repeated file I/O
when processing large hash dumps. The cache is invalidated when the file
modification time changes.

Performance characteristics:
- Initial load: O(n) where n = number of entries in potfile
- Subsequent lookups: O(1) hash table lookup
- Merge operations: O(m) where m = new entries only
- File change detection: O(1) using mtime
"""

import os
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from file_parser import PotfileValidationResult, PotfileEntry

logger = logging.getLogger(__name__)


@dataclass
class CachedPotfile:
    """Cached representation of a potfile for fast lookups."""
    filepath: str
    mtime: float  # File modification time when cache was built
    hash_to_password: Dict[str, str] = field(default_factory=dict)  # hash (uppercase) -> password
    total_entries: int = 0
    ntlm_count: int = 0


class PotfileCache:
    """
    Thread-safe cache for master potfile operations.

    Maintains an in-memory hash→password dictionary that's loaded once
    and updated incrementally when new hashes are merged.
    """

    def __init__(self):
        self._cache: Optional[CachedPotfile] = None
        self._lock = threading.RLock()

    def _is_cache_valid(self, filepath: str) -> bool:
        """Check if cache is valid for the given file."""
        if self._cache is None:
            return False
        if self._cache.filepath != filepath:
            return False
        if not os.path.exists(filepath):
            return False

        # Check if file was modified since we cached it
        current_mtime = os.path.getmtime(filepath)
        return current_mtime == self._cache.mtime

    def load(self, filepath: str, force_reload: bool = False) -> CachedPotfile:
        """
        Load potfile into cache. Returns cached version if still valid.

        Args:
            filepath: Path to the potfile
            force_reload: If True, reload even if cache is valid

        Returns:
            CachedPotfile with hash→password mappings
        """
        with self._lock:
            if not force_reload and self._is_cache_valid(filepath):
                logger.debug(f"Using cached potfile ({self._cache.ntlm_count} hashes)")
                return self._cache

            logger.info(f"Loading potfile into cache: {filepath}")

            hash_to_password: Dict[str, str] = {}
            ntlm_count = 0
            total_entries = 0

            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue

                            total_entries += 1

                            if ':' in line:
                                parts = line.split(':', 1)
                                hash_part = parts[0].lower()  # Store lowercase to match pwdump format
                                password = parts[1] if len(parts) > 1 else ""

                                # Check if it's a valid NTLM hash (32 hex chars)
                                hash_upper = hash_part.upper()
                                if len(hash_part) == 32 and all(c in '0123456789ABCDEF' for c in hash_upper):
                                    hash_to_password[hash_part] = password
                                    ntlm_count += 1

                except Exception as e:
                    logger.error(f"Error loading potfile into cache: {e}")
                    raise

            mtime = os.path.getmtime(filepath) if os.path.exists(filepath) else 0

            self._cache = CachedPotfile(
                filepath=filepath,
                mtime=mtime,
                hash_to_password=hash_to_password,
                total_entries=total_entries,
                ntlm_count=ntlm_count
            )

            logger.info(f"Potfile cache loaded: {ntlm_count} NTLM hashes")
            return self._cache

    def get_cracked_hashes(self, filepath: str) -> Dict[str, str]:
        """
        Get the hash→password dictionary for fast lookups.

        Args:
            filepath: Path to the potfile

        Returns:
            Dict mapping uppercase hash to password
        """
        cache = self.load(filepath)
        return cache.hash_to_password

    def get_hash_set(self, filepath: str) -> Set[str]:
        """
        Get set of all hashes (for deduplication checks).

        Args:
            filepath: Path to the potfile

        Returns:
            Set of uppercase hashes
        """
        cache = self.load(filepath)
        return set(cache.hash_to_password.keys())

    def merge_entries(
        self,
        filepath: str,
        new_entries: list,  # List of objects with ntlm_hash and password attributes
    ) -> Tuple[int, int, int]:
        """
        Merge new entries into the potfile and update cache incrementally.

        This is more efficient than merge_potfile_entries() because it:
        1. Uses cached hashes for deduplication (no file read)
        2. Only appends new entries to file
        3. Updates cache in-memory without re-reading

        Args:
            filepath: Path to the master potfile
            new_entries: List of potfile entry objects with is_valid, included,
                        is_ntlm, ntlm_hash, and password attributes

        Returns:
            Tuple of (entries_added, entries_skipped, total_in_master)
        """
        import fcntl

        with self._lock:
            # Ensure cache is loaded
            cache = self.load(filepath)
            existing_hashes = cache.hash_to_password

            # Filter to valid NTLM entries
            ntlm_entries = [
                e for e in new_entries
                if getattr(e, 'is_valid', False) and
                   getattr(e, 'included', True) and
                   getattr(e, 'is_ntlm', False) and
                   getattr(e, 'ntlm_hash', None)
            ]

            if not ntlm_entries:
                return (0, 0, len(existing_hashes))

            # Ensure directory exists
            master_dir = os.path.dirname(filepath)
            if master_dir and not os.path.exists(master_dir):
                os.makedirs(master_dir, exist_ok=True)

            entries_added = 0
            entries_skipped = 0
            new_hashes: Dict[str, str] = {}

            # Check which entries are new (use lowercase for consistency)
            for entry in ntlm_entries:
                hash_lower = entry.ntlm_hash.lower()
                if hash_lower not in existing_hashes:
                    password = getattr(entry, 'password', '') or ""
                    new_hashes[hash_lower] = password
                    entries_added += 1
                else:
                    entries_skipped += 1

            # Append new entries to file
            if new_hashes:
                try:
                    with open(filepath, 'a', encoding='utf-8') as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        try:
                            for hash_val, password in new_hashes.items():
                                f.write(f"{hash_val}:{password}\n")
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                    # Update cache in-memory (avoid file re-read)
                    existing_hashes.update(new_hashes)
                    cache.ntlm_count += entries_added
                    cache.total_entries += entries_added
                    cache.mtime = os.path.getmtime(filepath)

                except Exception as e:
                    logger.error(f"Error writing to potfile: {e}")
                    raise

            total = len(existing_hashes)
            logger.info(f"Potfile merge: {entries_added} added, {entries_skipped} skipped, {total} total")

            return (entries_added, entries_skipped, total)

    def invalidate(self):
        """Invalidate the cache, forcing a reload on next access."""
        with self._lock:
            self._cache = None
            logger.debug("Potfile cache invalidated")

    def get_stats(self) -> Optional[Dict]:
        """Get cache statistics."""
        with self._lock:
            if self._cache is None:
                return None
            return {
                "filepath": self._cache.filepath,
                "ntlm_count": self._cache.ntlm_count,
                "total_entries": self._cache.total_entries,
                "mtime": self._cache.mtime
            }

    def to_validation_result(self, filepath: str) -> "PotfileValidationResult":
        """
        Create a PotfileValidationResult from cached data.

        This is MUCH faster than validate_potfile() because:
        1. Uses cached hash→password dict (no file I/O)
        2. Creates minimal PotfileEntry objects (no hash type detection)
        3. Skips error tracking (master potfile is pre-validated)

        Args:
            filepath: Path to the potfile

        Returns:
            PotfileValidationResult compatible with rest of the application
        """
        from file_parser import PotfileValidationResult, PotfileEntry

        cache = self.load(filepath)

        # Create lightweight PotfileEntry objects from cache
        entries: List["PotfileEntry"] = []
        for idx, (hash_val, password) in enumerate(cache.hash_to_password.items(), start=1):
            entry = PotfileEntry(
                line_number=idx,
                raw_line=f"{hash_val}:{password}",
                ntlm_hash=hash_val,
                password=password,
                is_valid=True,
                is_ntlm=True,
                detected_type="NTLM",
                detected_mode=1000,
                errors=[],
                included=True
            )
            entries.append(entry)

        return PotfileValidationResult(
            filepath=filepath,
            total_lines=cache.total_entries,
            valid_lines=cache.ntlm_count,
            error_lines=0,
            ntlm_count=cache.ntlm_count,
            non_ntlm_count=0,  # Master potfile is NTLM only
            entries=entries,
            error_summary={},
            hash_type_summary={
                "ntlm": {
                    "name": "NTLM",
                    "mode": 1000,
                    "count": cache.ntlm_count,
                    "is_ntlm": True
                }
            }
        )


# Global cache instance
_master_potfile_cache = PotfileCache()


def get_master_cache() -> PotfileCache:
    """Get the global master potfile cache instance."""
    return _master_potfile_cache


def build_cracked_hashes_fast(
    potfile_result: "PotfileValidationResult",
    master_potfile_path: Optional[str] = None
) -> Dict[str, str]:
    """
    Build a hash→password lookup dict efficiently.

    Automatically detects if potfile_result is from the master potfile
    by checking its filepath. If so, returns the cached dict directly
    (O(1) vs O(n) iteration).

    Args:
        potfile_result: The potfile validation result
        master_potfile_path: Optional path to master potfile for explicit check.
                            If not provided, uses potfile_result.filepath.

    Returns:
        Dict mapping uppercase NTLM hash to password
    """
    from file_parser import BLANK_NTLM_HASH

    # Determine which path to check against cache
    check_path = master_potfile_path or getattr(potfile_result, 'filepath', None)

    if check_path:
        cache = get_master_cache()
        stats = cache.get_stats()
        if stats and stats["filepath"] == check_path:
            # This is the master potfile - use cached dict directly
            logger.debug(f"Using cached cracked_hashes ({stats['ntlm_count']} entries)")
            cached_data = cache.load(check_path)
            cracked = cached_data.hash_to_password.copy()
            cracked[BLANK_NTLM_HASH] = ""  # Add blank hash
            return cracked

    # Fall back to iteration for non-master potfiles
    # Note: preserve original hash case to match how lookups work in file_parser
    cracked_hashes: Dict[str, str] = {BLANK_NTLM_HASH: ""}
    for entry in potfile_result.entries:
        if entry.included and entry.is_valid and entry.ntlm_hash:
            cracked_hashes[entry.ntlm_hash] = entry.password or ""
    return cracked_hashes
