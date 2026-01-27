"""
Offline buffer for queuing messages when server is unreachable.

Provides resilience for:
- Status updates that couldn't be sent
- Job completion reports
- Cracked password uploads
- Heartbeat data

Messages are persisted to SQLite and retried when connection is restored.
"""

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
import logging

from hm1k_agent.config import Config

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of buffered messages."""

    HEARTBEAT = "heartbeat"
    JOB_STATUS = "job_status"
    JOB_COMPLETE = "job_complete"
    JOB_ERROR = "job_error"
    CRACKED_PASSWORDS = "cracked_passwords"
    BENCHMARK = "benchmark"


@dataclass
class BufferedMessage:
    """A message waiting to be sent."""

    id: int
    message_type: MessageType
    payload: dict
    created_at: float
    attempts: int
    last_attempt: Optional[float]
    job_id: Optional[str]


# Type alias for message sender callback
MessageSender = Callable[[MessageType, dict], bool]


class OfflineBuffer:
    """
    SQLite-backed queue for offline message buffering.

    Features:
    - Persists messages to survive agent restarts
    - Automatic retry with exponential backoff
    - Priority ordering (newer job status > old heartbeats)
    - Configurable retention period
    - Thread-safe operations
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        job_id TEXT,
        created_at REAL NOT NULL,
        attempts INTEGER DEFAULT 0,
        last_attempt REAL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type);
    CREATE INDEX IF NOT EXISTS idx_messages_job ON messages(job_id);
    CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
    """

    def __init__(self, config: Config):
        """
        Initialize the offline buffer.

        Args:
            config: Agent configuration
        """
        self.config = config
        self.db_path = Path(config.resources.data_dir) / "offline_buffer.db"
        self.max_age_hours = 72  # Discard messages older than 3 days
        self.max_attempts = 10
        self.retry_delay = 30  # Seconds between retry attempts

        self._lock = threading.Lock()
        self._sender: Optional[MessageSender] = None
        self._running = False
        self._retry_thread: Optional[threading.Thread] = None

        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._get_conn() as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()

        # Clean old messages on startup
        self._cleanup_old_messages()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def set_sender(self, sender: MessageSender) -> None:
        """
        Set the callback used to send messages.

        Args:
            sender: Function that takes (MessageType, payload) and returns success bool
        """
        self._sender = sender

    def start(self) -> None:
        """Start the background retry thread."""
        if self._running:
            return

        self._running = True
        self._retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
        self._retry_thread.start()
        logger.info("Offline buffer started")

    def stop(self) -> None:
        """Stop the background retry thread."""
        self._running = False
        if self._retry_thread:
            self._retry_thread.join(timeout=5)
            self._retry_thread = None
        logger.info("Offline buffer stopped")

    def queue(
        self,
        message_type: MessageType,
        payload: dict,
        job_id: Optional[str] = None,
    ) -> int:
        """
        Add a message to the buffer.

        Args:
            message_type: Type of message
            payload: Message data
            job_id: Associated job ID if any

        Returns:
            Message ID
        """
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO messages (message_type, payload, job_id, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        message_type.value,
                        json.dumps(payload),
                        job_id,
                        time.time(),
                    ),
                )
                conn.commit()
                msg_id = cursor.lastrowid

        logger.debug(f"Queued {message_type.value} message (id={msg_id})")
        return msg_id

    def remove(self, message_id: int) -> None:
        """
        Remove a message from the buffer (after successful send).

        Args:
            message_id: Message to remove
        """
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
                conn.commit()

    def get_pending(self, limit: int = 100) -> list[BufferedMessage]:
        """
        Get pending messages to retry.

        Args:
            limit: Maximum number of messages to return

        Returns:
            List of pending messages, oldest first
        """
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, message_type, payload, job_id, created_at, attempts, last_attempt
                    FROM messages
                    WHERE attempts < ?
                    ORDER BY
                        CASE message_type
                            WHEN 'job_complete' THEN 1
                            WHEN 'job_error' THEN 2
                            WHEN 'job_status' THEN 3
                            WHEN 'cracked_passwords' THEN 4
                            WHEN 'benchmark' THEN 5
                            WHEN 'heartbeat' THEN 6
                        END,
                        created_at ASC
                    LIMIT ?
                    """,
                    (self.max_attempts, limit),
                ).fetchall()

        return [
            BufferedMessage(
                id=row["id"],
                message_type=MessageType(row["message_type"]),
                payload=json.loads(row["payload"]),
                created_at=row["created_at"],
                attempts=row["attempts"],
                last_attempt=row["last_attempt"],
                job_id=row["job_id"],
            )
            for row in rows
        ]

    def mark_attempt(self, message_id: int) -> None:
        """
        Increment attempt count for a message.

        Args:
            message_id: Message that was attempted
        """
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    UPDATE messages
                    SET attempts = attempts + 1, last_attempt = ?
                    WHERE id = ?
                    """,
                    (time.time(), message_id),
                )
                conn.commit()

    def _retry_loop(self) -> None:
        """Background thread to retry sending buffered messages."""
        while self._running:
            try:
                if self._sender:
                    self._process_pending()
                time.sleep(self.retry_delay)
            except Exception as e:
                logger.error(f"Retry loop error: {e}")
                time.sleep(5)

    def _process_pending(self) -> None:
        """Try to send pending messages."""
        pending = self.get_pending(limit=50)

        if not pending:
            return

        logger.debug(f"Processing {len(pending)} buffered messages")

        success_count = 0
        for msg in pending:
            # Check if enough time has passed since last attempt
            if msg.last_attempt:
                backoff = min(self.retry_delay * (2 ** msg.attempts), 3600)
                if time.time() - msg.last_attempt < backoff:
                    continue

            try:
                if self._sender(msg.message_type, msg.payload):
                    self.remove(msg.id)
                    success_count += 1
                else:
                    self.mark_attempt(msg.id)
            except Exception as e:
                logger.warning(f"Failed to send buffered message: {e}")
                self.mark_attempt(msg.id)

        if success_count > 0:
            logger.info(f"Sent {success_count} buffered messages")

    def _cleanup_old_messages(self) -> None:
        """Remove messages older than max_age_hours."""
        cutoff = time.time() - (self.max_age_hours * 3600)

        with self._lock:
            with self._get_conn() as conn:
                result = conn.execute(
                    "DELETE FROM messages WHERE created_at < ?",
                    (cutoff,),
                )
                conn.commit()
                deleted = result.rowcount

        if deleted > 0:
            logger.info(f"Cleaned up {deleted} old buffered messages")

    def clear_job(self, job_id: str) -> int:
        """
        Remove all buffered messages for a job.

        Args:
            job_id: Job to clear messages for

        Returns:
            Number of messages removed
        """
        with self._lock:
            with self._get_conn() as conn:
                result = conn.execute(
                    "DELETE FROM messages WHERE job_id = ?",
                    (job_id,),
                )
                conn.commit()
                return result.rowcount

    def clear_all(self) -> int:
        """
        Remove all buffered messages.

        Returns:
            Number of messages removed
        """
        with self._lock:
            with self._get_conn() as conn:
                result = conn.execute("DELETE FROM messages")
                conn.commit()
                return result.rowcount

    def get_stats(self) -> dict:
        """Get buffer statistics."""
        with self._lock:
            with self._get_conn() as conn:
                total = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
                by_type = conn.execute(
                    """
                    SELECT message_type, COUNT(*) as count
                    FROM messages
                    GROUP BY message_type
                    """
                ).fetchall()
                oldest = conn.execute(
                    "SELECT MIN(created_at) FROM messages"
                ).fetchone()[0]

        return {
            "total_pending": total,
            "by_type": {row["message_type"]: row["count"] for row in by_type},
            "oldest_message_age_hours": (time.time() - oldest) / 3600 if oldest else 0,
        }

    @property
    def pending_count(self) -> int:
        """Get count of pending messages."""
        with self._lock:
            with self._get_conn() as conn:
                return conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    @property
    def is_empty(self) -> bool:
        """Check if buffer is empty."""
        return self.pending_count == 0
