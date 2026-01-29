"""
SQLite-based agent state management for multi-worker concurrency.

Uses WAL (Write-Ahead Logging) mode to allow concurrent reads and writes
without blocking, solving the file I/O contention issues with JSON files.
"""

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AgentStateDB:
    """
    SQLite-based state management for agents.

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
                timeout=30.0,  # Wait up to 30s for locks
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrency
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            # Improve performance
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return self._local.conn

    @contextmanager
    def _transaction(self):
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
            # Agents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    first_seen TEXT,
                    last_heartbeat TEXT,
                    status TEXT DEFAULT 'offline',
                    ip_address TEXT,
                    state_json TEXT,
                    current_job_json TEXT
                )
            """)

            # Agent commands queue
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    command_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_commands_agent
                ON agent_commands(agent_id)
            """)

            # Pending registrations
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_registrations (
                    id TEXT PRIMARY KEY,
                    hostname TEXT,
                    ip_address TEXT,
                    requested_at TEXT,
                    agent_info_json TEXT
                )
            """)

            # Stopped jobs (for ignoring stale updates)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stopped_jobs (
                    job_id TEXT PRIMARY KEY,
                    stopped_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Job history
            conn.execute("""
                CREATE TABLE IF NOT EXISTS job_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    agent_id TEXT,
                    agent_name TEXT,
                    hash_type TEXT,
                    attack_mode TEXT,
                    status TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    total_hashes INTEGER,
                    cracked_hashes INTEGER,
                    job_data_json TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_completed
                ON job_history(completed_at DESC)
            """)

            logger.info(f"Agent state database initialized: {self.db_path}")

    # ==================== Agent Operations ====================

    def get_agent(self, agent_id: str) -> Optional[dict]:
        """Get an agent by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()

        if row is None:
            return None

        return self._row_to_agent(row)

    def get_all_agents(self) -> dict[str, dict]:
        """Get all agents as a dictionary keyed by agent ID."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM agents").fetchall()
        return {row['id']: self._row_to_agent(row) for row in rows}

    def upsert_agent(self, agent_id: str, agent_data: dict) -> None:
        """Insert or update an agent."""
        with self._transaction() as conn:
            state_json = json.dumps(agent_data.get('state', {}))
            current_job_json = json.dumps(agent_data.get('current_job')) if agent_data.get('current_job') else None

            conn.execute("""
                INSERT INTO agents (id, name, first_seen, last_heartbeat, status, ip_address, state_json, current_job_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    last_heartbeat = excluded.last_heartbeat,
                    status = excluded.status,
                    ip_address = excluded.ip_address,
                    state_json = excluded.state_json,
                    current_job_json = COALESCE(excluded.current_job_json, current_job_json)
            """, (
                agent_id,
                agent_data.get('name', f'Agent-{agent_id[:8]}'),
                agent_data.get('first_seen', datetime.now().isoformat()),
                agent_data.get('last_heartbeat', datetime.now().isoformat()),
                agent_data.get('status', 'online'),
                agent_data.get('ip_address', 'unknown'),
                state_json,
                current_job_json,
            ))

    def update_agent_heartbeat(self, agent_id: str, state: dict, ip_address: str) -> bool:
        """
        Update agent heartbeat efficiently.

        Returns True if agent exists, False if it's a new agent.
        """
        with self._transaction() as conn:
            state_json = json.dumps(state)
            now = datetime.now().isoformat()

            # Try to update existing
            cursor = conn.execute("""
                UPDATE agents
                SET last_heartbeat = ?, state_json = ?, ip_address = ?,
                    status = CASE WHEN current_job_json IS NOT NULL THEN 'working' ELSE 'online' END
                WHERE id = ?
            """, (now, state_json, ip_address, agent_id))

            return cursor.rowcount > 0

    def register_new_agent(self, agent_id: str, name: str, state: dict, ip_address: str) -> None:
        """Register a new agent."""
        with self._transaction() as conn:
            now = datetime.now().isoformat()
            state_json = json.dumps(state)

            conn.execute("""
                INSERT INTO agents (id, name, first_seen, last_heartbeat, status, ip_address, state_json)
                VALUES (?, ?, ?, ?, 'online', ?, ?)
            """, (agent_id, name, now, now, ip_address, state_json))

    def pre_register_agent(self, agent_id: str, name: str, ip_address: str, hostname: str = None) -> None:
        """Pre-register an agent (approved but not yet connected)."""
        with self._transaction() as conn:
            now = datetime.now().isoformat()
            state = {"hostname": hostname} if hostname else {}
            state_json = json.dumps(state)

            conn.execute("""
                INSERT INTO agents (id, name, first_seen, last_heartbeat, status, ip_address, state_json)
                VALUES (?, ?, ?, NULL, 'registered', ?, ?)
            """, (agent_id, name, now, ip_address, state_json))

    def set_agent_job(self, agent_id: str, job_data: Optional[dict]) -> None:
        """Set or clear an agent's current job."""
        with self._transaction() as conn:
            job_json = json.dumps(job_data) if job_data else None
            status = 'working' if job_data else 'online'

            conn.execute("""
                UPDATE agents SET current_job_json = ?, status = ?
                WHERE id = ?
            """, (job_json, status, agent_id))

    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent."""
        with self._transaction() as conn:
            # Delete commands first
            conn.execute("DELETE FROM agent_commands WHERE agent_id = ?", (agent_id,))
            cursor = conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
            return cursor.rowcount > 0

    def mark_agents_offline(self, timeout_seconds: int = 120) -> int:
        """Mark agents as offline if they haven't sent a heartbeat recently."""
        with self._transaction() as conn:
            # SQLite datetime comparison
            cursor = conn.execute("""
                UPDATE agents
                SET status = 'offline'
                WHERE status != 'offline'
                AND datetime(last_heartbeat) < datetime('now', ? || ' seconds')
            """, (f'-{timeout_seconds}',))
            return cursor.rowcount

    def get_agent_stats(self) -> dict:
        """Get agent statistics for dashboard."""
        conn = self._get_connection()
        row = conn.execute("""
            SELECT
                COUNT(*) as total_agents,
                SUM(CASE WHEN current_job_json IS NOT NULL THEN 1 ELSE 0 END) as active_jobs,
                SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online_agents
            FROM agents
        """).fetchone()
        return {
            'total_agents': row['total_agents'] or 0,
            'active_jobs': row['active_jobs'] or 0,
            'online_agents': row['online_agents'] or 0,
        }

    def _row_to_agent(self, row: sqlite3.Row) -> dict:
        """Convert a database row to an agent dictionary."""
        agent = {
            'id': row['id'],
            'name': row['name'],
            'first_seen': row['first_seen'],
            'last_heartbeat': row['last_heartbeat'],
            'status': row['status'],
            'ip_address': row['ip_address'],
            'state': json.loads(row['state_json']) if row['state_json'] else {},
        }
        if row['current_job_json']:
            agent['current_job'] = json.loads(row['current_job_json'])
        return agent

    # ==================== Command Queue Operations ====================

    def queue_command(self, agent_id: str, command: dict) -> None:
        """Queue a command for an agent."""
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO agent_commands (agent_id, command_json)
                VALUES (?, ?)
            """, (agent_id, json.dumps(command)))
            logger.info(f"Queued command for agent {agent_id}: {command.get('type')}")

    def pop_commands(self, agent_id: str) -> list[dict]:
        """Pop all pending commands for an agent."""
        with self._transaction() as conn:
            rows = conn.execute("""
                SELECT id, command_json FROM agent_commands
                WHERE agent_id = ?
                ORDER BY id ASC
            """, (agent_id,)).fetchall()

            if not rows:
                return []

            # Delete the commands we're returning
            ids = [row['id'] for row in rows]
            conn.execute(f"""
                DELETE FROM agent_commands
                WHERE id IN ({','.join('?' * len(ids))})
            """, ids)

            commands = [json.loads(row['command_json']) for row in rows]
            logger.info(f"Delivering {len(commands)} command(s) to agent {agent_id}")
            return commands

    # ==================== Pending Registration Operations ====================

    def add_pending_registration(self, registration_id: str, hostname: str,
                                  ip_address: str, agent_info: dict) -> None:
        """Add a pending registration request."""
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO pending_registrations
                (id, hostname, ip_address, requested_at, agent_info_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                registration_id,
                hostname,
                ip_address,
                datetime.now().isoformat(),
                json.dumps(agent_info),
            ))

    def get_pending_registrations(self) -> dict[str, dict]:
        """Get all pending registrations."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM pending_registrations").fetchall()
        return {
            row['id']: {
                'id': row['id'],
                'hostname': row['hostname'],
                'ip_address': row['ip_address'],
                'requested_at': row['requested_at'],
                **json.loads(row['agent_info_json']),
            }
            for row in rows
        }

    def get_pending_registration(self, registration_id: str) -> Optional[dict]:
        """Get a specific pending registration."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM pending_registrations WHERE id = ?",
            (registration_id,)
        ).fetchone()

        if row is None:
            return None

        return {
            'id': row['id'],
            'hostname': row['hostname'],
            'ip_address': row['ip_address'],
            'requested_at': row['requested_at'],
            **json.loads(row['agent_info_json']),
        }

    def remove_pending_registration(self, registration_id: str) -> bool:
        """Remove a pending registration."""
        with self._transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM pending_registrations WHERE id = ?",
                (registration_id,)
            )
            return cursor.rowcount > 0

    # ==================== Stopped Jobs Operations ====================

    def mark_job_stopped(self, job_id: str) -> None:
        """Mark a job as stopped."""
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO stopped_jobs (job_id, stopped_at)
                VALUES (?, ?)
            """, (job_id, datetime.now().isoformat()))

            # Cleanup old entries (keep last 100)
            conn.execute("""
                DELETE FROM stopped_jobs
                WHERE job_id NOT IN (
                    SELECT job_id FROM stopped_jobs
                    ORDER BY stopped_at DESC LIMIT 100
                )
            """)

    def is_job_stopped(self, job_id: str) -> bool:
        """Check if a job was stopped."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT 1 FROM stopped_jobs WHERE job_id = ?",
            (job_id,)
        ).fetchone()
        return row is not None

    # ==================== Job History Operations ====================

    def add_job_history(self, job_data: dict) -> None:
        """Add a completed job to history."""
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO job_history
                (job_id, agent_id, agent_name, hash_type, attack_mode, status,
                 started_at, completed_at, total_hashes, cracked_hashes, job_data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job_data.get('job_id'),
                job_data.get('agent_id'),
                job_data.get('agent_name'),
                job_data.get('hash_type'),
                job_data.get('attack_mode'),
                job_data.get('status'),
                job_data.get('started_at'),
                job_data.get('completed_at'),
                job_data.get('total_hashes'),
                job_data.get('cracked_hashes'),
                json.dumps(job_data),
            ))

    def get_job_history(self, limit: int = 50) -> list[dict]:
        """Get recent job history."""
        conn = self._get_connection()
        rows = conn.execute("""
            SELECT job_data_json FROM job_history
            ORDER BY completed_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [json.loads(row['job_data_json']) for row in rows]

    # ==================== Migration ====================

    def migrate_from_json(self, data_dir: str) -> dict:
        """
        Migrate data from JSON files to SQLite.

        Returns a dict with counts of migrated items.
        """
        migrated = {'agents': 0, 'pending': 0, 'commands': 0, 'stopped': 0, 'history': 0}

        # Migrate agents
        agents_file = os.path.join(data_dir, 'agents.json')
        if os.path.exists(agents_file):
            try:
                with open(agents_file, 'r') as f:
                    agents = json.load(f)
                for agent_id, agent_data in agents.items():
                    agent_data['id'] = agent_id
                    self.upsert_agent(agent_id, agent_data)
                    migrated['agents'] += 1
                logger.info(f"Migrated {migrated['agents']} agents from JSON")
            except Exception as e:
                logger.error(f"Failed to migrate agents: {e}")

        # Migrate pending registrations
        pending_file = os.path.join(data_dir, 'pending_registrations.json')
        if os.path.exists(pending_file):
            try:
                with open(pending_file, 'r') as f:
                    pending = json.load(f)
                for reg_id, reg_data in pending.items():
                    self.add_pending_registration(
                        reg_id,
                        reg_data.get('hostname', ''),
                        reg_data.get('ip_address', ''),
                        reg_data,
                    )
                    migrated['pending'] += 1
                logger.info(f"Migrated {migrated['pending']} pending registrations from JSON")
            except Exception as e:
                logger.error(f"Failed to migrate pending registrations: {e}")

        # Migrate job queue (commands)
        queue_file = os.path.join(data_dir, 'job_queue.json')
        if os.path.exists(queue_file):
            try:
                with open(queue_file, 'r') as f:
                    queue = json.load(f)
                for agent_id, commands in queue.items():
                    for cmd in commands:
                        self.queue_command(agent_id, cmd)
                        migrated['commands'] += 1
                logger.info(f"Migrated {migrated['commands']} commands from JSON")
            except Exception as e:
                logger.error(f"Failed to migrate commands: {e}")

        # Migrate stopped jobs
        stopped_file = os.path.join(data_dir, 'stopped_jobs.json')
        if os.path.exists(stopped_file):
            try:
                with open(stopped_file, 'r') as f:
                    stopped = json.load(f)
                for job_id in stopped.get('job_ids', []):
                    self.mark_job_stopped(job_id)
                    migrated['stopped'] += 1
                logger.info(f"Migrated {migrated['stopped']} stopped jobs from JSON")
            except Exception as e:
                logger.error(f"Failed to migrate stopped jobs: {e}")

        # Migrate job history
        history_file = os.path.join(data_dir, 'job_history.json')
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    history = json.load(f)
                for job in history:
                    self.add_job_history(job)
                    migrated['history'] += 1
                logger.info(f"Migrated {migrated['history']} job history entries from JSON")
            except Exception as e:
                logger.error(f"Failed to migrate job history: {e}")

        return migrated

    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Global instance with thread-safe initialization
_db: Optional[AgentStateDB] = None
_db_lock = threading.Lock()


def get_agent_db(data_dir: str = None) -> AgentStateDB:
    """Get or create the global AgentStateDB instance (thread-safe)."""
    global _db
    if _db is not None:
        return _db

    with _db_lock:
        # Double-check after acquiring lock
        if _db is not None:
            return _db

        if data_dir is None:
            raise ValueError("data_dir must be provided on first call")
        db_path = os.path.join(data_dir, 'agent_state.db')
        _db = AgentStateDB(db_path)

        # Check if we need to migrate from JSON
        migration_marker = os.path.join(data_dir, '.db_migrated')
        if not os.path.exists(migration_marker):
            logger.info("Migrating from JSON files to SQLite...")
            migrated = _db.migrate_from_json(data_dir)
            # Create marker file
            with open(migration_marker, 'w') as f:
                f.write(f"Migrated at {datetime.now().isoformat()}\n")
                f.write(f"Counts: {migrated}\n")
            logger.info(f"Migration complete: {migrated}")

    return _db
