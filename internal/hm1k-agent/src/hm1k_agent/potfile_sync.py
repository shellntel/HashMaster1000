"""
Potfile synchronization for HM1K agent.

Manages bidirectional sync of cracked hashes between agent and HM1K server.
- Uploads newly cracked hashes to master potfile
- Downloads hashes cracked by other agents
- Integrates with hashcat's --potfile-path

The goal is to ensure all agents share cracked passwords, avoiding
redundant cracking of already-known hashes across distributed systems.
"""

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from hm1k_agent.config import Config
from hm1k_agent.api_client import APIClient

logger = logging.getLogger(__name__)

# Maximum retries for sync operations
MAX_SYNC_RETRIES = 3


@dataclass
class SyncState:
    """Track sync state with server."""

    last_server_position: int = 0  # Last known position in master potfile
    last_upload_position: int = 0  # Lines in local potfile already uploaded
    last_sync_error: Optional[str] = None
    consecutive_failures: int = 0


class PotfileSync:
    """
    Manages potfile synchronization between agent and HM1K server.

    Usage:
        sync = PotfileSync(config, api_client)

        # Before starting a job
        sync.sync_before_job()

        # After job completes
        sync.sync_after_job()

    The local potfile is kept at config.resources.potfile_path and is
    used by hashcat via --potfile-path. After sync, it contains both
    locally cracked hashes and hashes from other agents.
    """

    def __init__(self, config: Config, api_client: APIClient):
        """
        Initialize potfile sync manager.

        Args:
            config: Agent configuration
            api_client: REST API client for server communication
        """
        self.config = config
        self.api = api_client
        self.potfile_path = Path(config.resources.potfile_path)
        self._state = SyncState()
        self._lock = threading.Lock()

        # Ensure potfile exists
        self._ensure_potfile()

    def _ensure_potfile(self) -> None:
        """Ensure potfile directory and file exist."""
        self.potfile_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.potfile_path.exists():
            self.potfile_path.touch()

    def _read_local_potfile(self) -> list[str]:
        """Read all entries from local potfile."""
        if not self.potfile_path.exists():
            return []
        try:
            with open(self.potfile_path, "r", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to read local potfile: {e}")
            return []

    def _get_new_local_entries(self) -> list[str]:
        """Get entries from local potfile that haven't been uploaded yet."""
        all_entries = self._read_local_potfile()
        return all_entries[self._state.last_upload_position:]

    def _append_to_local_potfile(self, entries: list[str]) -> int:
        """
        Append entries to local potfile, deduplicating.

        Returns:
            Number of new unique entries added
        """
        if not entries:
            return 0

        existing = set(self._read_local_potfile())
        new_entries = [e for e in entries if e not in existing]

        if new_entries:
            with open(self.potfile_path, "a") as f:
                for entry in new_entries:
                    f.write(entry + "\n")

            logger.info(f"Added {len(new_entries)} entries to local potfile")

        return len(new_entries)

    def _do_sync(self) -> bool:
        """
        Perform bidirectional sync with server.

        Returns:
            True if sync succeeded
        """
        with self._lock:
            # Get new local entries to upload
            new_entries = self._get_new_local_entries()

            try:
                result = self.api.sync_potfile(
                    entries=new_entries,
                    last_position=self._state.last_server_position,
                )

                if result is None:
                    self._state.consecutive_failures += 1
                    self._state.last_sync_error = "API request failed"
                    return False

                # Update local potfile with entries from other agents
                server_entries = result.get("new_entries", [])
                if server_entries:
                    added = self._append_to_local_potfile(server_entries)
                    logger.info(f"Received {len(server_entries)} entries from server, {added} new")

                # Update sync state
                self._state.last_server_position = result.get("current_position", 0)
                self._state.last_upload_position = len(self._read_local_potfile())
                self._state.consecutive_failures = 0
                self._state.last_sync_error = None

                merged = result.get("merged_count", 0)
                if merged > 0 or server_entries:
                    logger.info(
                        f"Potfile sync complete: uploaded {merged}, "
                        f"received {len(server_entries)} entries"
                    )

                return True

            except Exception as e:
                self._state.consecutive_failures += 1
                self._state.last_sync_error = str(e)
                logger.error(f"Potfile sync error: {e}")
                return False

    def sync_with_retry(self, context: str = "sync") -> bool:
        """
        Perform sync with retry logic.

        Args:
            context: Description for logging (e.g., "before_job", "after_job")

        Returns:
            True if sync eventually succeeded
        """
        for attempt in range(1, MAX_SYNC_RETRIES + 1):
            logger.debug(f"Potfile sync attempt {attempt}/{MAX_SYNC_RETRIES} ({context})")

            if self._do_sync():
                return True

            if attempt < MAX_SYNC_RETRIES:
                import time
                wait_time = 2 ** attempt  # Exponential backoff: 2, 4, 8 seconds
                logger.warning(
                    f"Potfile sync failed, retrying in {wait_time}s "
                    f"(attempt {attempt}/{MAX_SYNC_RETRIES})"
                )
                time.sleep(wait_time)

        logger.error(
            f"Potfile sync failed after {MAX_SYNC_RETRIES} attempts: "
            f"{self._state.last_sync_error}"
        )
        return False

    def sync_before_job(self) -> bool:
        """
        Sync potfile before starting a job.

        Downloads latest entries from other agents so hashcat can
        skip already-cracked hashes.

        Returns:
            True if sync succeeded
        """
        logger.info("Syncing potfile before job start")
        return self.sync_with_retry("before_job")

    def sync_after_job(self) -> bool:
        """
        Sync potfile after job completion.

        Uploads newly cracked hashes to server and downloads any
        new entries from other agents.

        Returns:
            True if sync succeeded
        """
        logger.info("Syncing potfile after job completion")
        return self.sync_with_retry("after_job")

    def do_full_sync(self) -> bool:
        """
        Perform full potfile download from server.

        Used for initial setup or recovery from inconsistent state.
        Replaces local potfile with server's master potfile.

        Returns:
            True if sync succeeded
        """
        logger.info("Performing full potfile sync from server")

        result = self.api.get_full_potfile()
        if result is None:
            logger.error("Failed to download full potfile")
            return False

        content, position = result

        try:
            # Write full potfile content
            with open(self.potfile_path, "w") as f:
                f.write(content)

            # Update sync state
            with self._lock:
                self._state.last_server_position = position
                self._state.last_upload_position = position
                self._state.consecutive_failures = 0
                self._state.last_sync_error = None

            logger.info(f"Full potfile sync complete: {position} entries")
            return True

        except Exception as e:
            logger.error(f"Failed to write potfile: {e}")
            return False

    @property
    def sync_healthy(self) -> bool:
        """Check if sync is in healthy state (no recent failures)."""
        return self._state.consecutive_failures == 0

    @property
    def last_error(self) -> Optional[str]:
        """Get the last sync error message."""
        return self._state.last_sync_error

    def get_stats(self) -> dict:
        """Get sync statistics."""
        local_count = len(self._read_local_potfile())
        return {
            "local_entries": local_count,
            "last_server_position": self._state.last_server_position,
            "sync_healthy": self.sync_healthy,
            "last_error": self._state.last_sync_error,
        }
