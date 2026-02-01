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
