"""
Potfile Manager - Centralized potfile synchronization for distributed hashcat agents.

Manages the master potfile and handles bidirectional sync with agents.
"""

import hashlib
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional


class PotfileManager:
    """Manages the master potfile and agent synchronization state."""

    def __init__(self, data_dir: str, potfile_path: Optional[str] = None):
        """
        Initialize the potfile manager.

        Args:
            data_dir: Directory for sync state and other data
            potfile_path: Optional explicit path to master potfile.
                         If not provided, uses {data_dir}/potfile/master.potfile
        """
        self.data_dir = Path(data_dir)
        self.potfile_dir = self.data_dir / "potfile"
        self.potfile_dir.mkdir(parents=True, exist_ok=True)

        # Use explicit potfile path if provided, otherwise use default location
        if potfile_path:
            self.master_potfile = Path(potfile_path)
            # Ensure parent directory exists
            self.master_potfile.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.master_potfile = self.potfile_dir / "master.potfile"

        self.sync_state_file = self.potfile_dir / "sync_state.json"

        self._lock = threading.Lock()
        self._sync_state = self._load_sync_state()

        # Ensure master potfile exists
        if not self.master_potfile.exists():
            self.master_potfile.touch()

    def _load_sync_state(self) -> dict:
        """Load sync state from disk."""
        if self.sync_state_file.exists():
            try:
                with open(self.sync_state_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"agents": {}, "total_entries": 0, "last_modified": None}

    def _save_sync_state(self) -> None:
        """Save sync state to disk."""
        with open(self.sync_state_file, "w") as f:
            json.dump(self._sync_state, f, indent=2)

    def _count_lines(self) -> int:
        """Count lines in master potfile."""
        if not self.master_potfile.exists():
            return 0
        with open(self.master_potfile, "r", errors="ignore") as f:
            return sum(1 for _ in f)

    def _get_entries_set(self) -> set[str]:
        """Get all entries in master potfile as a set for deduplication."""
        if not self.master_potfile.exists():
            return set()
        with open(self.master_potfile, "r", errors="ignore") as f:
            return set(line.strip() for line in f if line.strip())

    def get_stats(self) -> dict:
        """Get potfile statistics."""
        with self._lock:
            total_entries = self._count_lines()
            size_bytes = (
                self.master_potfile.stat().st_size
                if self.master_potfile.exists()
                else 0
            )
            return {
                "total_entries": total_entries,
                "size_bytes": size_bytes,
                "last_modified": self._sync_state.get("last_modified"),
                "agents_synced": len(self._sync_state.get("agents", {})),
            }

    def get_agent_sync_position(self, agent_id: str) -> int:
        """Get the last synced line number for an agent."""
        with self._lock:
            return self._sync_state.get("agents", {}).get(agent_id, {}).get("position", 0)

    def set_agent_sync_position(self, agent_id: str, position: int) -> None:
        """Update the sync position for an agent."""
        with self._lock:
            if "agents" not in self._sync_state:
                self._sync_state["agents"] = {}
            if agent_id not in self._sync_state["agents"]:
                self._sync_state["agents"][agent_id] = {}
            self._sync_state["agents"][agent_id]["position"] = position
            self._sync_state["agents"][agent_id]["last_sync"] = datetime.utcnow().isoformat()
            self._save_sync_state()

    def merge_entries(self, new_entries: list[str], agent_id: str) -> dict:
        """
        Merge new entries from an agent into the master potfile.

        Returns dict with:
        - added: number of new unique entries added
        - duplicates: number of entries that already existed
        - total: total entries in master after merge
        """
        if not new_entries:
            return {"added": 0, "duplicates": 0, "total": self._count_lines()}

        with self._lock:
            # Get existing entries for deduplication
            existing = self._get_entries_set()
            initial_count = len(existing)

            # Filter to only new entries
            new_unique = []
            duplicates = 0
            for entry in new_entries:
                entry = entry.strip()
                if entry and entry not in existing:
                    new_unique.append(entry)
                    existing.add(entry)
                elif entry:
                    duplicates += 1

            # Append new entries to master potfile
            if new_unique:
                with open(self.master_potfile, "a") as f:
                    for entry in new_unique:
                        f.write(entry + "\n")

                # Update sync state
                self._sync_state["total_entries"] = len(existing)
                self._sync_state["last_modified"] = datetime.utcnow().isoformat()
                self._save_sync_state()

            return {
                "added": len(new_unique),
                "duplicates": duplicates,
                "total": len(existing),
            }

    def get_entries_since(self, position: int) -> tuple[list[str], int]:
        """
        Get all entries after the given line position.

        Returns (entries, new_position) tuple.
        """
        with self._lock:
            if not self.master_potfile.exists():
                return [], 0

            entries = []
            current_pos = 0
            with open(self.master_potfile, "r", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    if i > position:
                        line = line.strip()
                        if line:
                            entries.append(line)
                    current_pos = i

            return entries, current_pos

    def get_full_potfile(self) -> tuple[str, int]:
        """Get the complete master potfile content and current line count."""
        with self._lock:
            if not self.master_potfile.exists():
                return "", 0
            with open(self.master_potfile, "r", errors="ignore") as f:
                content = f.read()
            position = len([line for line in content.split("\n") if line.strip()])
            return content, position

    def get_potfile_hash(self) -> str:
        """Get MD5 hash of master potfile for quick comparison."""
        with self._lock:
            if not self.master_potfile.exists():
                return ""
            hasher = hashlib.md5()
            with open(self.master_potfile, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()

    def sync_from_job_potfile(self, job_id: str, potfile_content: str, agent_id: str) -> dict:
        """
        Sync potfile content from a completed job.

        Called when a job completes to merge its cracked hashes into master.
        """
        if not potfile_content or not potfile_content.strip():
            return {"added": 0, "duplicates": 0, "total": self._count_lines()}

        entries = [line.strip() for line in potfile_content.strip().split("\n") if line.strip()]
        return self.merge_entries(entries, agent_id)


# Global instance (initialized by Flask app)
_potfile_manager: Optional[PotfileManager] = None


def init_potfile_manager(data_dir: str, potfile_path: Optional[str] = None) -> PotfileManager:
    """
    Initialize the global potfile manager.

    Args:
        data_dir: Directory for sync state and other data
        potfile_path: Optional explicit path to master potfile
    """
    global _potfile_manager
    _potfile_manager = PotfileManager(data_dir, potfile_path)
    return _potfile_manager


def get_potfile_manager() -> Optional[PotfileManager]:
    """Get the global potfile manager instance."""
    return _potfile_manager
