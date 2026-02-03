"""
SQLite-based mask and mask group storage.

Uses WAL (Write-Ahead Logging) mode for concurrent access from multiple
gunicorn workers without blocking.
"""

import json
import logging
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, Generator

logger = logging.getLogger(__name__)


class MaskDB:
    """
    SQLite-based storage for masks and mask groups.

    Thread-safe and multi-process safe using WAL mode.
    """

    def __init__(self, db_path: str):
        """
        Initialize the database.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size=-64000")
        return self._local.conn

    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database transactions."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._transaction() as conn:
            # Masks table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS masks (
                    mask_id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    length INTEGER NOT NULL,
                    keyspace INTEGER NOT NULL,
                    description TEXT DEFAULT '',
                    tags_json TEXT DEFAULT '[]',
                    custom_charsets_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    created_by TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_masks_length
                ON masks(length)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_masks_pattern
                ON masks(pattern)
            """)

            # Groups table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT DEFAULT '',
                    custom_charsets_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
            """)

            # Group-mask association table (many-to-many)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS group_masks (
                    group_id TEXT NOT NULL,
                    mask_id TEXT NOT NULL,
                    position INTEGER DEFAULT 0,
                    PRIMARY KEY (group_id, mask_id),
                    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE,
                    FOREIGN KEY (mask_id) REFERENCES masks(mask_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_group_masks_group
                ON group_masks(group_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_group_masks_mask
                ON group_masks(mask_id)
            """)

            # Mask performance tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mask_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT,
                    group_name TEXT,
                    agent_id TEXT NOT NULL,
                    agent_name TEXT,
                    hash_count INTEGER NOT NULL,
                    hash_mode INTEGER NOT NULL,
                    avg_speed_hps REAL NOT NULL,
                    peak_speed_hps REAL,
                    duration_seconds REAL NOT NULL,
                    keyspace_total INTEGER,
                    masks_in_file INTEGER,
                    timestamp TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE SET NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mask_performance_group
                ON mask_performance(group_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mask_performance_agent
                ON mask_performance(agent_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mask_performance_hash_mode
                ON mask_performance(hash_mode)
            """)

            logger.info(f"Mask database initialized: {self.db_path}")

    # ==================== Mask Operations ====================

    def add_mask(
        self,
        pattern: str,
        length: int,
        keyspace: int,
        description: str = "",
        tags: Optional[list[str]] = None,
        custom_charsets: Optional[dict[str, str]] = None,
        created_by: str = "",
    ) -> tuple[Optional[str], str]:
        """
        Add a new mask.

        Returns:
            Tuple of (mask_id or None, error message)
        """
        if tags is None:
            tags = []
        if custom_charsets is None:
            custom_charsets = {}

        mask_id = f"mask_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._transaction() as conn:
                # Check for duplicate pattern with same charsets
                existing = conn.execute(
                    "SELECT mask_id, custom_charsets_json FROM masks WHERE pattern = ?",
                    (pattern,)
                ).fetchone()

                if existing:
                    existing_charsets = json.loads(existing['custom_charsets_json'])
                    if existing_charsets == custom_charsets:
                        return None, f"Mask '{pattern}' already exists"

                conn.execute("""
                    INSERT INTO masks (
                        mask_id, pattern, length, keyspace, description,
                        tags_json, custom_charsets_json, created_at, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    mask_id, pattern, length, keyspace, description,
                    json.dumps(tags), json.dumps(custom_charsets),
                    created_at, created_by
                ))

            logger.info(f"Added mask {mask_id}: {pattern} (keyspace: {keyspace})")
            return mask_id, ""

        except sqlite3.IntegrityError as e:
            return None, f"Database error: {e}"
        except Exception as e:
            logger.error(f"Failed to add mask: {e}")
            return None, str(e)

    def get_mask(self, mask_id: str) -> Optional[dict]:
        """Get a mask by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM masks WHERE mask_id = ?", (mask_id,)
        ).fetchone()

        if row is None:
            return None

        return self._row_to_mask(row)

    def get_mask_by_pattern(self, pattern: str) -> Optional[dict]:
        """Get a mask by pattern."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM masks WHERE pattern = ?", (pattern,)
        ).fetchone()

        if row is None:
            return None

        return self._row_to_mask(row)

    def get_all_masks(self) -> list[dict]:
        """Get all masks."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM masks ORDER BY length, pattern"
        ).fetchall()

        return [self._row_to_mask(row) for row in rows]

    def get_masks_by_length(self) -> dict[int, list[dict]]:
        """Get all masks grouped by length."""
        masks = self.get_all_masks()
        by_length: dict[int, list[dict]] = {}
        for mask in masks:
            length = mask['length']
            if length not in by_length:
                by_length[length] = []
            by_length[length].append(mask)
        return by_length

    def get_ungrouped_masks(self) -> list[dict]:
        """Get masks that are not in any group."""
        conn = self._get_connection()
        rows = conn.execute("""
            SELECT m.* FROM masks m
            LEFT JOIN group_masks gm ON m.mask_id = gm.mask_id
            WHERE gm.group_id IS NULL
            ORDER BY m.length, m.pattern
        """).fetchall()

        return [self._row_to_mask(row) for row in rows]

    def update_mask(
        self,
        mask_id: str,
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[bool, str]:
        """Update a mask's metadata."""
        try:
            with self._transaction() as conn:
                updates = []
                params = []

                if description is not None:
                    updates.append("description = ?")
                    params.append(description)

                if tags is not None:
                    updates.append("tags_json = ?")
                    params.append(json.dumps(tags))

                if not updates:
                    return False, "No updates provided"

                params.append(mask_id)
                conn.execute(
                    f"UPDATE masks SET {', '.join(updates)} WHERE mask_id = ?",
                    params
                )

                if conn.total_changes == 0:
                    return False, f"Mask not found: {mask_id}"

            return True, ""
        except Exception as e:
            logger.error(f"Failed to update mask: {e}")
            return False, str(e)

    def delete_mask(self, mask_id: str) -> tuple[bool, str]:
        """Delete a mask."""
        try:
            with self._transaction() as conn:
                # This will also delete from group_masks due to CASCADE
                result = conn.execute(
                    "DELETE FROM masks WHERE mask_id = ?", (mask_id,)
                )

                if result.rowcount == 0:
                    return False, f"Mask not found: {mask_id}"

            logger.info(f"Deleted mask {mask_id}")
            return True, ""
        except Exception as e:
            logger.error(f"Failed to delete mask: {e}")
            return False, str(e)

    def _row_to_mask(self, row: sqlite3.Row) -> dict:
        """Convert a database row to a mask dict."""
        return {
            'mask_id': row['mask_id'],
            'pattern': row['pattern'],
            'length': row['length'],
            'keyspace': row['keyspace'],
            'description': row['description'],
            'tags': json.loads(row['tags_json']),
            'custom_charsets': json.loads(row['custom_charsets_json']),
            'created_at': row['created_at'],
            'created_by': row['created_by'],
        }

    # ==================== Group Operations ====================

    def create_group(
        self,
        name: str,
        description: str = "",
        mask_ids: Optional[list[str]] = None,
        custom_charsets: Optional[dict[str, str]] = None,
    ) -> tuple[Optional[str], str]:
        """
        Create a new mask group.

        Returns:
            Tuple of (group_id or None, error message)
        """
        if mask_ids is None:
            mask_ids = []
        if custom_charsets is None:
            custom_charsets = {}

        group_id = f"grp_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._transaction() as conn:
                conn.execute("""
                    INSERT INTO groups (
                        group_id, name, description, custom_charsets_json, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                """, (group_id, name, description, json.dumps(custom_charsets), created_at))

                # Add masks to group
                for i, mask_id in enumerate(mask_ids):
                    conn.execute("""
                        INSERT OR IGNORE INTO group_masks (group_id, mask_id, position)
                        VALUES (?, ?, ?)
                    """, (group_id, mask_id, i))

            logger.info(f"Created group {group_id}: {name} with {len(mask_ids)} masks")
            return group_id, ""

        except sqlite3.IntegrityError:
            return None, f"Group '{name}' already exists"
        except Exception as e:
            logger.error(f"Failed to create group: {e}")
            return None, str(e)

    def get_group(self, group_id: str) -> Optional[dict]:
        """Get a group by ID (without masks)."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM groups WHERE group_id = ?", (group_id,)
        ).fetchone()

        if row is None:
            return None

        return self._row_to_group(row)

    def get_group_with_masks(self, group_id: str) -> Optional[dict]:
        """Get a group by ID with its masks."""
        group = self.get_group(group_id)
        if group is None:
            return None

        conn = self._get_connection()
        rows = conn.execute("""
            SELECT m.* FROM masks m
            JOIN group_masks gm ON m.mask_id = gm.mask_id
            WHERE gm.group_id = ?
            ORDER BY gm.position, m.pattern
        """, (group_id,)).fetchall()

        group['masks'] = [self._row_to_mask(row) for row in rows]
        group['mask_ids'] = [m['mask_id'] for m in group['masks']]

        return group

    def get_all_groups(self) -> list[dict]:
        """Get all groups (with mask IDs but not full mask data)."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM groups ORDER BY name"
        ).fetchall()

        groups = []
        for row in rows:
            group = self._row_to_group(row)

            # Get mask IDs for this group
            mask_rows = conn.execute("""
                SELECT mask_id FROM group_masks
                WHERE group_id = ?
                ORDER BY position
            """, (group['group_id'],)).fetchall()

            group['mask_ids'] = [r['mask_id'] for r in mask_rows]
            group['mask_count'] = len(group['mask_ids'])
            groups.append(group)

        return groups

    def update_group(
        self,
        group_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        mask_ids: Optional[list[str]] = None,
        custom_charsets: Optional[dict[str, str]] = None,
    ) -> tuple[bool, str]:
        """Update a group."""
        try:
            with self._transaction() as conn:
                # Check group exists
                existing = conn.execute(
                    "SELECT group_id FROM groups WHERE group_id = ?", (group_id,)
                ).fetchone()

                if existing is None:
                    return False, f"Group not found: {group_id}"

                # Update group fields
                updates = []
                params = []

                if name is not None:
                    # Check for duplicate name
                    dup = conn.execute(
                        "SELECT group_id FROM groups WHERE name = ? AND group_id != ?",
                        (name, group_id)
                    ).fetchone()
                    if dup:
                        return False, f"Group '{name}' already exists"
                    updates.append("name = ?")
                    params.append(name)

                if description is not None:
                    updates.append("description = ?")
                    params.append(description)

                if custom_charsets is not None:
                    updates.append("custom_charsets_json = ?")
                    params.append(json.dumps(custom_charsets))

                if updates:
                    params.append(group_id)
                    conn.execute(
                        f"UPDATE groups SET {', '.join(updates)} WHERE group_id = ?",
                        params
                    )

                # Update mask associations if provided
                if mask_ids is not None:
                    conn.execute(
                        "DELETE FROM group_masks WHERE group_id = ?", (group_id,)
                    )
                    for i, mask_id in enumerate(mask_ids):
                        conn.execute("""
                            INSERT OR IGNORE INTO group_masks (group_id, mask_id, position)
                            VALUES (?, ?, ?)
                        """, (group_id, mask_id, i))

            logger.info(f"Updated group {group_id}")
            return True, ""
        except Exception as e:
            logger.error(f"Failed to update group: {e}")
            return False, str(e)

    def delete_group(self, group_id: str) -> tuple[bool, str]:
        """Delete a group (masks remain)."""
        try:
            with self._transaction() as conn:
                result = conn.execute(
                    "DELETE FROM groups WHERE group_id = ?", (group_id,)
                )

                if result.rowcount == 0:
                    return False, f"Group not found: {group_id}"

            logger.info(f"Deleted group {group_id}")
            return True, ""
        except Exception as e:
            logger.error(f"Failed to delete group: {e}")
            return False, str(e)

    def _row_to_group(self, row: sqlite3.Row) -> dict:
        """Convert a database row to a group dict."""
        return {
            'group_id': row['group_id'],
            'name': row['name'],
            'description': row['description'],
            'custom_charsets': json.loads(row['custom_charsets_json']),
            'created_at': row['created_at'],
        }

    # ==================== Stats ====================

    def get_stats(self) -> dict:
        """Get statistics about masks and groups."""
        conn = self._get_connection()

        mask_count = conn.execute("SELECT COUNT(*) FROM masks").fetchone()[0]
        group_count = conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0]

        return {
            'mask_count': mask_count,
            'group_count': group_count,
        }

    # ==================== Mask Performance Tracking ====================

    def record_mask_performance(
        self,
        job_id: str,
        agent_id: str,
        hash_count: int,
        hash_mode: int,
        avg_speed_hps: float,
        duration_seconds: float,
        group_id: Optional[str] = None,
        group_name: Optional[str] = None,
        agent_name: Optional[str] = None,
        peak_speed_hps: Optional[float] = None,
        keyspace_total: Optional[int] = None,
        masks_in_file: Optional[int] = None,
    ) -> tuple[bool, str]:
        """
        Record performance data from a completed mask attack job.

        Args:
            job_id: Unique job identifier
            agent_id: Agent that ran the job
            hash_count: Number of hashes being cracked
            hash_mode: Hashcat hash mode (e.g., 1000 for NTLM)
            avg_speed_hps: Average speed in H/s
            duration_seconds: Total job duration
            group_id: Mask group ID (if applicable)
            group_name: Mask group name (for reference if group is deleted)
            agent_name: Agent name (for reference)
            peak_speed_hps: Peak speed observed
            keyspace_total: Total keyspace processed
            masks_in_file: Number of masks in the mask file

        Returns:
            Tuple of (success, error message)
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            with self._transaction() as conn:
                conn.execute("""
                    INSERT INTO mask_performance (
                        group_id, group_name, agent_id, agent_name,
                        hash_count, hash_mode, avg_speed_hps, peak_speed_hps,
                        duration_seconds, keyspace_total, masks_in_file,
                        timestamp, job_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    group_id, group_name, agent_id, agent_name,
                    hash_count, hash_mode, avg_speed_hps, peak_speed_hps,
                    duration_seconds, keyspace_total, masks_in_file,
                    timestamp, job_id
                ))

            logger.info(
                f"Recorded mask performance: group={group_name or group_id}, "
                f"agent={agent_name or agent_id}, speed={avg_speed_hps/1e9:.2f} GH/s"
            )
            return True, ""

        except Exception as e:
            logger.error(f"Failed to record mask performance: {e}")
            return False, str(e)

    def get_group_performance(
        self,
        group_id: str,
        agent_id: Optional[str] = None,
        hash_mode: int = 1000,
        limit: int = 10,
    ) -> list[dict]:
        """
        Get historical performance data for a mask group.

        Args:
            group_id: Mask group ID
            agent_id: Optional filter by agent
            hash_mode: Hash mode (default NTLM)
            limit: Maximum records to return

        Returns:
            List of performance records, newest first
        """
        conn = self._get_connection()

        if agent_id:
            rows = conn.execute("""
                SELECT * FROM mask_performance
                WHERE group_id = ? AND agent_id = ? AND hash_mode = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (group_id, agent_id, hash_mode, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM mask_performance
                WHERE group_id = ? AND hash_mode = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (group_id, hash_mode, limit)).fetchall()

        return [self._row_to_performance(row) for row in rows]

    def get_group_avg_speed(
        self,
        group_id: str,
        agent_id: Optional[str] = None,
        hash_mode: int = 1000,
        hash_count_min: Optional[int] = None,
        hash_count_max: Optional[int] = None,
    ) -> Optional[float]:
        """
        Get average speed for a mask group based on historical data.

        Can optionally filter by agent and hash count range to get
        more accurate estimates for similar workloads.

        Args:
            group_id: Mask group ID
            agent_id: Optional filter by specific agent
            hash_mode: Hash mode (default NTLM)
            hash_count_min: Minimum hash count for filtering
            hash_count_max: Maximum hash count for filtering

        Returns:
            Average speed in H/s or None if no data
        """
        conn = self._get_connection()

        query = """
            SELECT AVG(avg_speed_hps) as avg_speed
            FROM mask_performance
            WHERE group_id = ? AND hash_mode = ?
        """
        params: list = [group_id, hash_mode]

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if hash_count_min is not None:
            query += " AND hash_count >= ?"
            params.append(hash_count_min)

        if hash_count_max is not None:
            query += " AND hash_count <= ?"
            params.append(hash_count_max)

        row = conn.execute(query, params).fetchone()
        return row['avg_speed'] if row and row['avg_speed'] else None

    def get_agent_performance_summary(
        self,
        agent_id: str,
        hash_mode: int = 1000,
    ) -> dict:
        """
        Get performance summary for an agent across all mask groups.

        Returns:
            Dict with avg_speed, job_count, groups_run
        """
        conn = self._get_connection()

        row = conn.execute("""
            SELECT
                AVG(avg_speed_hps) as avg_speed,
                COUNT(*) as job_count,
                COUNT(DISTINCT group_id) as groups_run
            FROM mask_performance
            WHERE agent_id = ? AND hash_mode = ?
        """, (agent_id, hash_mode)).fetchone()

        return {
            'avg_speed': row['avg_speed'] or 0,
            'job_count': row['job_count'] or 0,
            'groups_run': row['groups_run'] or 0,
        }

    def get_all_performance_data(
        self,
        hash_mode: int = 1000,
        limit: int = 100,
    ) -> list[dict]:
        """
        Get all performance records for analysis.

        Returns:
            List of performance records, newest first
        """
        conn = self._get_connection()

        rows = conn.execute("""
            SELECT * FROM mask_performance
            WHERE hash_mode = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (hash_mode, limit)).fetchall()

        return [self._row_to_performance(row) for row in rows]

    def _row_to_performance(self, row: sqlite3.Row) -> dict:
        """Convert a database row to a performance dict."""
        return {
            'id': row['id'],
            'group_id': row['group_id'],
            'group_name': row['group_name'],
            'agent_id': row['agent_id'],
            'agent_name': row['agent_name'],
            'hash_count': row['hash_count'],
            'hash_mode': row['hash_mode'],
            'avg_speed_hps': row['avg_speed_hps'],
            'peak_speed_hps': row['peak_speed_hps'],
            'duration_seconds': row['duration_seconds'],
            'keyspace_total': row['keyspace_total'],
            'masks_in_file': row['masks_in_file'],
            'timestamp': row['timestamp'],
            'job_id': row['job_id'],
        }


# Singleton instance management
_mask_db_instance: Optional[MaskDB] = None
_mask_db_lock = threading.Lock()


def get_mask_db(data_dir: str) -> MaskDB:
    """Get or create the MaskDB singleton."""
    global _mask_db_instance

    if _mask_db_instance is None:
        with _mask_db_lock:
            if _mask_db_instance is None:
                import os
                db_path = os.path.join(data_dir, "mask_state.db")
                _mask_db_instance = MaskDB(db_path)

    return _mask_db_instance
